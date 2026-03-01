// Package mutator generates and mutates EVM calldata using ABI type information.
package mutator

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	abiparser "github.com/kyyblin/gofuzz-evm/internal/abi"
	"github.com/kyyblin/gofuzz-evm/pkg/config"
)

// Strategy identifies a mutation approach.
type Strategy int

const (
	StrategyRandom      Strategy = iota // pure random within type bounds
	StrategyBoundary                    // boundary/edge values
	StrategyBitFlip                     // flip a random bit in a corpus entry
	StrategyArithmetic                  // ±1, ±small delta
	StrategyDictionary                  // known interesting values
	StrategyTransplant                  // copy argument from another corpus entry
)

// Mutator produces calldata for fuzz inputs.
type Mutator struct {
	rng      *rand.Rand
	parsed   *abiparser.ParsedABI
	cfg      *config.FuzzConfig
	corpus   [][]byte            // raw calldata entries for transplant mutations
	accounts []common.Address    // simulated EOAs for address mutations
	weights  [6]float64          // strategy selection weights (adaptive)
}

// New creates a Mutator with the given random source, parsed ABI, and config.
func New(rng *rand.Rand, parsed *abiparser.ParsedABI, cfg *config.FuzzConfig, accounts []common.Address) *Mutator {
	m := &Mutator{
		rng:      rng,
		parsed:   parsed,
		cfg:      cfg,
		accounts: accounts,
	}
	// Equal initial weights for all strategies
	for i := range m.weights {
		m.weights[i] = 1.0
	}
	return m
}

// AddCorpusEntry adds a calldata entry for use in transplant mutations.
func (m *Mutator) AddCorpusEntry(calldata []byte) {
	m.corpus = append(m.corpus, calldata)
}

// Generate creates fresh calldata for a randomly selected function.
func (m *Mutator) Generate() ([]byte, *abiparser.Function, error) {
	fn := m.pickFunction()
	calldata, err := m.generateForFunction(fn)
	return calldata, fn, err
}

// GenerateFor creates fresh calldata for a specific function.
func (m *Mutator) GenerateFor(fn *abiparser.Function) ([]byte, error) {
	return m.generateForFunction(fn)
}

// Mutate applies a mutation strategy to existing calldata.
// Returns mutated calldata and the function it targets.
func (m *Mutator) Mutate(calldata []byte) ([]byte, *abiparser.Function, error) {
	if len(calldata) < 4 {
		return m.Generate()
	}

	var sel [4]byte
	copy(sel[:], calldata[:4])
	fn := m.parsed.FunctionBySelector(sel)
	if fn == nil {
		return m.Generate()
	}

	strategy := m.pickStrategy()
	var mutated []byte
	var err error

	switch strategy {
	case StrategyBoundary:
		mutated, err = m.mutBoundary(fn)
	case StrategyBitFlip:
		mutated, err = m.mutBitFlip(calldata)
	case StrategyArithmetic:
		mutated, err = m.mutArithmetic(calldata, fn)
	case StrategyDictionary:
		mutated, err = m.mutDictionary(fn)
	case StrategyTransplant:
		mutated, err = m.mutTransplant(calldata, fn)
	default:
		mutated, err = m.generateForFunction(fn)
	}

	if err != nil || len(mutated) < 4 {
		// Fallback to random generation
		mutated, err = m.generateForFunction(fn)
	}
	return mutated, fn, err
}

// RewardStrategy increases the weight of a strategy that produced a coverage gain.
func (m *Mutator) RewardStrategy(s Strategy) {
	m.weights[int(s)] *= 1.1
	m.normalizeWeights()
}

// --- internal helpers ---

func (m *Mutator) pickFunction() *abiparser.Function {
	idx := m.rng.Intn(len(m.parsed.Functions))
	return m.parsed.Functions[idx]
}

func (m *Mutator) pickStrategy() Strategy {
	total := 0.0
	for _, w := range m.weights {
		total += w
	}
	r := m.rng.Float64() * total
	cumul := 0.0
	for i, w := range m.weights {
		cumul += w
		if r <= cumul {
			return Strategy(i)
		}
	}
	return StrategyRandom
}

func (m *Mutator) normalizeWeights() {
	total := 0.0
	for _, w := range m.weights {
		total += w
	}
	for i := range m.weights {
		m.weights[i] /= total
		m.weights[i] *= float64(len(m.weights)) // keep sum == len
	}
}

func (m *Mutator) generateForFunction(fn *abiparser.Function) ([]byte, error) {
	args := make([]interface{}, len(fn.Inputs))
	for i, input := range fn.Inputs {
		v, err := m.randomValue(input.Type)
		if err != nil {
			return nil, fmt.Errorf("mutator: generating arg %d (%s): %w", i, input.Name, err)
		}
		args[i] = v
	}
	return m.parsed.Raw.Pack(fn.Name, args...)
}

func (m *Mutator) mutBoundary(fn *abiparser.Function) ([]byte, error) {
	args := make([]interface{}, len(fn.Inputs))
	for i, input := range fn.Inputs {
		v, err := m.boundaryValue(input.Type)
		if err != nil {
			return nil, err
		}
		args[i] = v
	}
	return m.parsed.Raw.Pack(fn.Name, args...)
}

func (m *Mutator) mutBitFlip(calldata []byte) ([]byte, error) {
	if len(calldata) <= 4 {
		return nil, fmt.Errorf("calldata too short for bit flip")
	}
	out := make([]byte, len(calldata))
	copy(out, calldata)
	// Flip one random bit in the parameter region (after 4-byte selector)
	byteIdx := 4 + m.rng.Intn(len(calldata)-4)
	bitIdx := m.rng.Intn(8)
	out[byteIdx] ^= 1 << bitIdx
	return out, nil
}

func (m *Mutator) mutArithmetic(calldata []byte, fn *abiparser.Function) ([]byte, error) {
	args, err := m.decoded(calldata, fn)
	if err != nil {
		return m.generateForFunction(fn)
	}
	// Pick a random argument to perturb
	for i, arg := range args {
		if n, ok := arg.(*big.Int); ok {
			delta := big.NewInt(int64(m.rng.Intn(3) - 1)) // -1, 0, +1
			if m.rng.Intn(4) == 0 {
				delta = big.NewInt(int64(m.rng.Intn(256) - 128)) // larger delta
			}
			args[i] = new(big.Int).Add(n, delta)
			break
		}
	}
	return m.parsed.Raw.Pack(fn.Name, args...)
}

func (m *Mutator) mutDictionary(fn *abiparser.Function) ([]byte, error) {
	args := make([]interface{}, len(fn.Inputs))
	for i, input := range fn.Inputs {
		v, err := m.dictionaryValue(input.Type)
		if err != nil {
			v2, err2 := m.randomValue(input.Type)
			if err2 != nil {
				return nil, err2
			}
			v = v2
		}
		args[i] = v
	}
	return m.parsed.Raw.Pack(fn.Name, args...)
}

func (m *Mutator) mutTransplant(calldata []byte, fn *abiparser.Function) ([]byte, error) {
	if len(m.corpus) == 0 {
		return m.generateForFunction(fn)
	}
	donor := m.corpus[m.rng.Intn(len(m.corpus))]
	if len(donor) <= 4 {
		return m.generateForFunction(fn)
	}

	// Try to decode donor calldata to extract an argument
	var donorSel [4]byte
	copy(donorSel[:], donor[:4])
	donorFn := m.parsed.FunctionBySelector(donorSel)
	if donorFn == nil || len(donorFn.Inputs) == 0 {
		return m.generateForFunction(fn)
	}

	donorArgs, err := m.decoded(donor, donorFn)
	if err != nil || len(donorArgs) == 0 {
		return m.generateForFunction(fn)
	}

	// Build args for target function, transplanting compatible values
	args := make([]interface{}, len(fn.Inputs))
	for i, input := range fn.Inputs {
		transplanted := false
		for j, donorInput := range donorFn.Inputs {
			if input.Type.T == donorInput.Type.T && j < len(donorArgs) {
				args[i] = donorArgs[j]
				transplanted = true
				break
			}
		}
		if !transplanted {
			v, err := m.randomValue(input.Type)
			if err != nil {
				return nil, err
			}
			args[i] = v
		}
	}
	return m.parsed.Raw.Pack(fn.Name, args...)
}

func (m *Mutator) decoded(calldata []byte, fn *abiparser.Function) ([]interface{}, error) {
	if len(calldata) < 4 {
		return nil, fmt.Errorf("calldata too short")
	}
	vals, err := fn.Inputs.Unpack(calldata[4:])
	if err != nil {
		return nil, err
	}
	return vals, nil
}

// randomValue produces a random value for the given ABI type.
func (m *Mutator) randomValue(t abi.Type) (interface{}, error) {
	return generateValue(m.rng, t, m.accounts, false)
}

// boundaryValue produces a boundary/edge value for the given ABI type.
func (m *Mutator) boundaryValue(t abi.Type) (interface{}, error) {
	return generateValue(m.rng, t, m.accounts, true)
}

// dictionaryValue returns a known-interesting value for the type.
func (m *Mutator) dictionaryValue(t abi.Type) (interface{}, error) {
	return generateValue(m.rng, t, m.accounts, true) // reuse boundary for Phase 1
}
