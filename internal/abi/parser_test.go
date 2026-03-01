package abi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const simpleStorageABI = `[
	{
		"inputs": [{"internalType": "uint256", "name": "x", "type": "uint256"}],
		"name": "set",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "get",
		"outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	}
]`

const transferABI = `[
	{
		"inputs": [
			{"name": "to", "type": "address"},
			{"name": "amount", "type": "uint256"}
		],
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
	}
]`

func TestParseSimpleStorage(t *testing.T) {
	p, err := Parse([]byte(simpleStorageABI))
	require.NoError(t, err)
	assert.Len(t, p.Functions, 2)

	set := p.FunctionByName("set")
	require.NotNil(t, set)
	assert.Equal(t, "set", set.Name)
	assert.Len(t, set.Inputs, 1)
	assert.Equal(t, "x", set.Inputs[0].Name)
	assert.Equal(t, "nonpayable", set.Mutability)
	assert.False(t, set.IsPayable)

	// Verify 4-byte selector for "set(uint256)"
	// keccak256("set(uint256)") = 0x60fe47b1...
	assert.Equal(t, byte(0x60), set.Selector[0])

	get := p.FunctionByName("get")
	require.NotNil(t, get)
	assert.Equal(t, "view", get.Mutability)
}

func TestParseTransferABI(t *testing.T) {
	p, err := Parse([]byte(transferABI))
	require.NoError(t, err)
	assert.Len(t, p.Functions, 2)

	transfer := p.FunctionByName("transfer")
	require.NotNil(t, transfer)
	assert.True(t, false == transfer.IsPayable)

	batch := p.FunctionByName("batchTransfer")
	require.NotNil(t, batch)
	assert.True(t, batch.IsPayable)
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := Parse([]byte("not json"))
	assert.Error(t, err)
}

func TestParseEmptyABI(t *testing.T) {
	_, err := Parse([]byte("[]"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no callable functions")
}

func TestFunctionBySelector(t *testing.T) {
	p, err := Parse([]byte(simpleStorageABI))
	require.NoError(t, err)

	set := p.FunctionByName("set")
	require.NotNil(t, set)

	found := p.FunctionBySelector(set.Selector)
	require.NotNil(t, found)
	assert.Equal(t, "set", found.Name)
}

func TestParseWithBytecodeArtifact(t *testing.T) {
	artifact := `{
		"abi": [
			{
				"inputs": [{"name": "x", "type": "uint256"}],
				"name": "set",
				"outputs": [],
				"stateMutability": "nonpayable",
				"type": "function"
			}
		],
		"bytecode": "0x6080604052"
	}`
	p, bytecode, err := ParseWithBytecode([]byte(artifact))
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.NotEmpty(t, bytecode)
	assert.Equal(t, []byte{0x60, 0x80, 0x60, 0x40, 0x52}, bytecode)
}

func FuzzParseABI(f *testing.F) {
	f.Add([]byte(simpleStorageABI))
	f.Add([]byte("[]"))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic regardless of input
		_, _ = Parse(data)
	})
}
