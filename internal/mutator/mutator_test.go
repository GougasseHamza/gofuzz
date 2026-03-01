package mutator

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	abiparser "github.com/kyyblin/gofuzz-evm/internal/abi"
	"github.com/kyyblin/gofuzz-evm/pkg/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const erc20ABI = `[
	{
		"inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
		"name": "transfer",
		"outputs": [{"name": "", "type": "bool"}],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "recipients", "type": "address[]"},
			{"name": "amounts", "type": "uint256[]"}
		],
		"name": "batchTransfer",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [{"name": "x", "type": "uint256"}],
		"name": "set",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "get",
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	}
]`

func makeTestMutator(t *testing.T) (*Mutator, *abiparser.ParsedABI) {
	t.Helper()
	parsed, err := abiparser.Parse([]byte(erc20ABI))
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	rng := rand.New(rand.NewSource(42))
	accounts := []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
	}
	return New(rng, parsed, cfg, accounts), parsed
}

func TestGenerate(t *testing.T) {
	mut, _ := makeTestMutator(t)

	for i := 0; i < 100; i++ {
		calldata, fn, err := mut.Generate()
		require.NoError(t, err)
		require.NotNil(t, fn)
		assert.GreaterOrEqual(t, len(calldata), 4, "calldata must have at least 4-byte selector")

		// Verify first 4 bytes match the function selector
		var sel [4]byte
		copy(sel[:], calldata[:4])
		assert.Equal(t, fn.Selector, sel, "selector mismatch for %s", fn.Name)
	}
}

func TestGenerateFor(t *testing.T) {
	mut, parsed := makeTestMutator(t)

	for _, fn := range parsed.Functions {
		calldata, err := mut.GenerateFor(fn)
		require.NoError(t, err, "function: %s", fn.Name)
		assert.GreaterOrEqual(t, len(calldata), 4)

		var sel [4]byte
		copy(sel[:], calldata[:4])
		assert.Equal(t, fn.Selector, sel, "selector mismatch for %s", fn.Name)
	}
}

func TestMutate(t *testing.T) {
	mut, parsed := makeTestMutator(t)

	// Generate base calldata
	base, err := mut.GenerateFor(parsed.FunctionByName("set"))
	require.NoError(t, err)

	// Mutate 50 times — should not panic and always return valid calldata
	for i := 0; i < 50; i++ {
		mutated, fn, err := mut.Mutate(base)
		require.NoError(t, err)
		require.NotNil(t, fn)
		assert.GreaterOrEqual(t, len(mutated), 4)
	}
}

func TestBoundaryValues(t *testing.T) {
	mut, parsed := makeTestMutator(t)
	setFn := parsed.FunctionByName("set")
	require.NotNil(t, setFn)

	boundaryHit := false
	for i := 0; i < 200; i++ {
		calldata, err := mut.mutBoundary(setFn)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(calldata), 4+32) // selector + uint256

		// Check if we got 0 or max uint256 (all 0xff bytes)
		param := calldata[4:]
		if isZero(param) || isMaxUint256(param) {
			boundaryHit = true
		}
	}
	assert.True(t, boundaryHit, "expected boundary values to appear in 200 iterations")
}

func TestBitFlip(t *testing.T) {
	mut, parsed := makeTestMutator(t)
	base, err := mut.GenerateFor(parsed.FunctionByName("set"))
	require.NoError(t, err)

	flipped, err := mut.mutBitFlip(base)
	require.NoError(t, err)
	assert.Equal(t, len(base), len(flipped), "bit-flip should preserve length")

	// At least one byte should differ
	diff := 0
	for i := range base {
		if base[i] != flipped[i] {
			diff++
		}
	}
	assert.Equal(t, 1, diff, "exactly one byte should differ after bit-flip")
}

func TestAddCorpusEntry(t *testing.T) {
	mut, parsed := makeTestMutator(t)

	base, err := mut.GenerateFor(parsed.FunctionByName("set"))
	require.NoError(t, err)
	mut.AddCorpusEntry(base)

	assert.Len(t, mut.corpus, 1)
}

func TestRewardStrategy(t *testing.T) {
	mut, _ := makeTestMutator(t)
	initialWeight := mut.weights[int(StrategyBoundary)]
	mut.RewardStrategy(StrategyBoundary)
	assert.Greater(t, mut.weights[int(StrategyBoundary)], initialWeight)
}

func TestGenerateValuesBoundary(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	accounts := []common.Address{common.HexToAddress("0x01")}

	types := []struct {
		abiType string
	}{
		{"uint256"}, {"uint8"}, {"uint128"},
		{"int256"}, {"int8"},
		{"address"}, {"bool"},
		{"bytes"}, {"string"},
		{"bytes32"}, {"bytes1"},
	}

	for _, tc := range types {
		t.Run(tc.abiType, func(t *testing.T) {
			typ, err := abi.NewType(tc.abiType, "", nil)
			require.NoError(t, err)

			for i := 0; i < 20; i++ {
				v, err := generateValue(rng, typ, accounts, i%2 == 0)
				require.NoError(t, err, "type: %s", tc.abiType)
				assert.NotNil(t, v)
			}
		})
	}
}

// --- helpers ---

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isMaxUint256(b []byte) bool {
	if len(b) < 32 {
		return false
	}
	for _, v := range b[:32] {
		if v != 0xff {
			return false
		}
	}
	return true
}

// TestSliceAndArrayTypes tests dynamic and fixed array generation.
func TestSliceAndArrayTypes(t *testing.T) {
	abiJSON := `[
		{
			"inputs": [{"name": "vals", "type": "uint256[]"}],
			"name": "processSlice",
			"outputs": [],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [{"name": "data", "type": "bytes"}],
			"name": "processBytes",
			"outputs": [],
			"stateMutability": "nonpayable",
			"type": "function"
		}
	]`

	parsed, err := abiparser.Parse([]byte(abiJSON))
	require.NoError(t, err)

	cfg := config.DefaultConfig()
	rng := rand.New(rand.NewSource(99))
	accounts := []common.Address{common.HexToAddress("0x01")}
	mut := New(rng, parsed, cfg, accounts)

	for _, fn := range parsed.Functions {
		for i := 0; i < 20; i++ {
			calldata, err := mut.GenerateFor(fn)
			require.NoError(t, err, "function: %s iteration: %d", fn.Name, i)
			assert.GreaterOrEqual(t, len(calldata), 4, strings.Repeat(" fn="+fn.Name, 1))
		}
	}
}
