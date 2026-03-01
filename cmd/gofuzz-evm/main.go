// Command gofuzz-evm is a coverage-guided smart contract fuzzer for EVM-based contracts.
package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	abiparser "github.com/kyyblin/gofuzz-evm/internal/abi"
	"github.com/kyyblin/gofuzz-evm/internal/evm"
	"github.com/kyyblin/gofuzz-evm/internal/mutator"
	"github.com/kyyblin/gofuzz-evm/pkg/config"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "gofuzz-evm",
		Short: "Coverage-guided smart contract fuzzer for EVM-based contracts",
		Long: `GoFuzz-EVM ingests a compiled smart contract (ABI + bytecode), generates
mutated transaction inputs, and executes them against a local EVM to detect
security vulnerabilities such as reentrancy, integer overflow, and access control issues.`,
	}

	root.AddCommand(
		buildFuzzCmd(),
		buildAnalyzeCmd(),
		buildVersionCmd(),
	)
	return root
}

// --- fuzz command ---

func buildFuzzCmd() *cobra.Command {
	cfg := config.DefaultConfig()

	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Run a fuzzing campaign against a target contract",
		Example: `  gofuzz-evm fuzz --abi contract.abi.json --bin contract.bin
  gofuzz-evm fuzz --abi contract.abi.json --bin contract.bin --workers 4 --duration 5m`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFuzz(cfg)
		},
	}

	f := cmd.Flags()
	f.StringVar(&cfg.ABIPath, "abi", "", "Path to ABI JSON file (required)")
	f.StringVar(&cfg.BytecodePath, "bin", "", "Path to bytecode hex file (required)")
	f.IntVar(&cfg.Workers, "workers", cfg.Workers, "Number of parallel fuzzing workers")
	f.Uint64Var(&cfg.MaxRuns, "max-runs", cfg.MaxRuns, "Maximum number of executions (0 = unlimited)")
	f.DurationVar(&cfg.Duration, "duration", cfg.Duration, "Maximum campaign duration (0 = unlimited)")
	f.Uint64Var(&cfg.GasLimit, "gas-limit", cfg.GasLimit, "Per-transaction gas limit")
	f.IntVar(&cfg.MaxSequenceLen, "max-seq", cfg.MaxSequenceLen, "Maximum transaction sequence length")
	f.Int64Var(&cfg.Seed, "seed", cfg.Seed, "Random seed (0 = use current time)")
	f.StringVar(&cfg.CorpusDir, "corpus", cfg.CorpusDir, "Corpus directory")
	f.StringVar(&cfg.OutputDir, "output", cfg.OutputDir, "Output directory for reports")
	f.StringVar(&cfg.EVMFork, "fork", cfg.EVMFork, "EVM fork: cancun, shanghai, london")
	f.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	f.BoolVar(&cfg.Quiet, "quiet", false, "Suppress progress output")
	_ = cmd.MarkFlagRequired("abi")
	_ = cmd.MarkFlagRequired("bin")

	return cmd
}

func runFuzz(cfg *config.FuzzConfig) error {
	setupLogger(cfg.Verbose)

	// Load ABI
	parsed, err := abiparser.ParseFile(cfg.ABIPath)
	if err != nil {
		return fmt.Errorf("loading ABI: %w", err)
	}
	slog.Info("ABI loaded", "functions", len(parsed.Functions))

	// Load bytecode
	bytecode, err := loadBytecode(cfg.BytecodePath)
	if err != nil {
		return fmt.Errorf("loading bytecode: %w", err)
	}
	slog.Info("Bytecode loaded", "bytes", len(bytecode))

	// Create EVM executor
	exec, err := evm.New(cfg)
	if err != nil {
		return fmt.Errorf("creating EVM: %w", err)
	}

	// Deploy contract
	deployer := exec.Accounts()[0]
	contractAddr, err := exec.Deploy(bytecode, deployer)
	if err != nil {
		return fmt.Errorf("deploying contract: %w", err)
	}
	slog.Info("Contract deployed", "address", contractAddr.Hex())

	// Create mutator
	rng := rand.New(rand.NewSource(cfg.Seed))
	mut := mutator.New(rng, parsed, cfg, exec.Accounts())

	// Campaign loop
	ctx, cancel := campaignContext(cfg)
	defer cancel()

	if !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "GoFuzz-EVM %s — starting campaign\n", Version)
		fmt.Fprintf(os.Stderr, "  Contract : %s\n", contractAddr.Hex())
		fmt.Fprintf(os.Stderr, "  Functions: %d\n", len(parsed.Functions))
		fmt.Fprintf(os.Stderr, "  Workers  : %d\n", cfg.Workers)
		fmt.Fprintf(os.Stderr, "  Gas limit: %d\n", cfg.GasLimit)
		fmt.Fprintf(os.Stderr, "  Seed     : %d\n\n", cfg.Seed)
	}

	var (
		runs     uint64
		findings uint64
		start    = time.Now()
		ticker   = time.NewTicker(5 * time.Second)
	)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			printSummary(runs, findings, start, cfg.Quiet)
			return nil
		case <-ticker.C:
			if !cfg.Quiet {
				elapsed := time.Since(start).Round(time.Second)
				tps := float64(runs) / time.Since(start).Seconds()
				fmt.Fprintf(os.Stderr, "[%s] runs=%-8d tps=%-6.0f findings=%d\n",
					elapsed, runs, tps, findings)
			}
		default:
		}

		if cfg.MaxRuns > 0 && runs >= cfg.MaxRuns {
			printSummary(runs, findings, start, cfg.Quiet)
			return nil
		}

		// Generate calldata
		calldata, fn, err := mut.Generate()
		if err != nil {
			slog.Warn("mutator error", "err", err)
			continue
		}

		// Execute
		caller := exec.Accounts()[rng.Intn(len(exec.Accounts()))]
		result, err := exec.Execute(caller, calldata, nil)
		if err != nil {
			slog.Warn("execution error", "err", err)
			continue
		}
		runs++

		if cfg.Verbose {
			slog.Debug("exec", "fn", fn.Name, "gas_used", result.GasUsed, "reverted", result.Reverted)
		}

		// Basic finding: unexpected revert on valid input
		if result.Reverted && !fn.IsPayable {
			findings++
			slog.Warn("UNEXPECTED_REVERT",
				"function", fn.Name,
				"calldata", hex.EncodeToString(calldata),
				"gas_used", result.GasUsed,
			)
		}
	}
}

// --- analyze command ---

func buildAnalyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "analyze <abi-file>",
		Short: "Parse and display ABI information",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			parsed, err := abiparser.ParseFile(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("ABI: %s\n", args[0])
			fmt.Printf("Functions (%d):\n", len(parsed.Functions))
			for _, fn := range parsed.Functions {
				fmt.Printf("  %-30s selector=0x%x  mutability=%s  inputs=%d\n",
					fn.Name, fn.Selector, fn.Mutability, len(fn.Inputs))
			}
			if parsed.Constructor != nil {
				fmt.Printf("  <constructor>                  inputs=%d  payable=%v\n",
					len(parsed.Constructor.Inputs), parsed.Constructor.IsPayable)
			}
			return nil
		},
	}
}

// --- version command ---

func buildVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("gofuzz-evm %s\n", Version)
		},
	}
}

// --- helpers ---

func setupLogger(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func loadBytecode(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Strip whitespace and 0x prefix
	s := string(raw)
	for _, ch := range []string{"\n", "\r", " ", "\t", "0x", "0X"} {
		s = stripPrefix(s, ch)
	}
	return hex.DecodeString(s)
}

func stripPrefix(s, prefix string) string {
	for len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		s = s[len(prefix):]
	}
	return s
}

// campaignContext returns a context that cancels on SIGINT/SIGTERM or duration expiry.
func campaignContext(cfg *config.FuzzConfig) (interface{ Done() <-chan struct{} }, func()) {
	done := make(chan struct{})
	stop := func() { close(done) }

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigs:
			slog.Info("signal received, stopping campaign")
		case <-timer(cfg.Duration):
		}
		stop()
	}()

	return &chanCtx{done}, stop
}

type chanCtx struct{ ch chan struct{} }

func (c *chanCtx) Done() <-chan struct{} { return c.ch }

func timer(d time.Duration) <-chan time.Time {
	if d <= 0 {
		return make(chan time.Time) // never fires
	}
	return time.After(d)
}

func printSummary(runs, findings uint64, start time.Time, quiet bool) {
	if quiet {
		return
	}
	elapsed := time.Since(start).Round(time.Millisecond)
	tps := 0.0
	if elapsed > 0 {
		tps = float64(runs) / elapsed.Seconds()
	}
	fmt.Fprintf(os.Stderr, "\n--- Campaign complete ---\n")
	fmt.Fprintf(os.Stderr, "  Runs    : %d\n", runs)
	fmt.Fprintf(os.Stderr, "  Findings: %d\n", findings)
	fmt.Fprintf(os.Stderr, "  Elapsed : %s\n", elapsed)
	fmt.Fprintf(os.Stderr, "  Avg TPS : %.0f\n", tps)
}
