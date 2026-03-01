// Package config defines FuzzConfig and its defaults.
package config

import (
	"math/big"
	"runtime"
	"time"
)

// FuzzConfig holds all parameters controlling a fuzzing campaign.
type FuzzConfig struct {
	// Input
	ABIPath      string `mapstructure:"abi"`
	BytecodePath string `mapstructure:"bin"`

	// Campaign control
	Workers        int           `mapstructure:"workers"`
	MaxSequenceLen int           `mapstructure:"max_sequence_len"`
	GasLimit       uint64        `mapstructure:"gas_limit"`
	MaxRuns        uint64        `mapstructure:"max_runs"`
	Duration       time.Duration `mapstructure:"duration"`
	Seed           int64         `mapstructure:"seed"`

	// Storage
	CorpusDir string `mapstructure:"corpus_dir"`
	OutputDir string `mapstructure:"output_dir"`

	// Oracle selection
	Oracles []string `mapstructure:"oracles"`

	// EVM environment
	Accounts       int      `mapstructure:"accounts"`
	InitialBalance *big.Int `mapstructure:"-"`
	EVMFork        string   `mapstructure:"evm_fork"`

	// Output control
	Verbose bool `mapstructure:"verbose"`
	Quiet   bool `mapstructure:"quiet"`
}

// DefaultConfig returns a FuzzConfig populated with sensible defaults.
func DefaultConfig() *FuzzConfig {
	return &FuzzConfig{
		Workers:        runtime.NumCPU(),
		MaxSequenceLen: 10,
		GasLimit:       10_000_000,
		MaxRuns:        1_000_000,
		Seed:           time.Now().UnixNano(),
		CorpusDir:      "corpus",
		OutputDir:      "output",
		Oracles: []string{
			"reentrancy",
			"integer_overflow",
			"access_control",
			"unexpected_revert",
			"gas_griefing",
			"selfdestruct",
			"delegatecall_injection",
		},
		Accounts:       5,
		InitialBalance: new(big.Int).Mul(big.NewInt(1_000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)),
		EVMFork:        "cancun",
	}
}
