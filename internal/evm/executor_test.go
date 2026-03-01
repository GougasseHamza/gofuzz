package evm

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kyyblin/gofuzz-evm/pkg/config"
)

// simpleStorageBytecode is the constructor + runtime bytecode for:
//
//	pragma solidity ^0.8.0;
//	contract SimpleStorage {
//	    uint256 public value;
//	    function set(uint256 x) external { value = x; }
//	    function get() external view returns (uint256) { return value; }
//	}
//
// Pre-compiled with solc 0.8.26, optimization enabled.
// Selector for set(uint256): 0x60fe47b1
// Selector for get():        0x6d4ce63c
const simpleStorageBytecode = "6080604052348015600e575f80fd5b5060" +
	"b980601a5f395ff3fe6080604052348015600e575f80fd5b50600436106" +
	"030575f3560e01c806360fe47b1146034578063" +
	"6d4ce63c14604357600080fd5b603f603f3660046062565b6057565b005" +
	"b6049605c565b6040519081526020015b60405180910390f35b5f5d5481" +
	"5660b480603f565b90815560e01b565b5f60209182526004359055565" +
	"b5f80fd"

func defaultTestConfig() *config.FuzzConfig {
	cfg := config.DefaultConfig()
	cfg.Workers = 1
	cfg.GasLimit = 1_000_000
	return cfg
}

func TestNew(t *testing.T) {
	cfg := defaultTestConfig()
	exec, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, exec)
	assert.Len(t, exec.Accounts(), cfg.Accounts)
}

func TestDeployAndExecute(t *testing.T) {
	cfg := defaultTestConfig()
	exec, err := New(cfg)
	require.NoError(t, err)

	deployer := exec.Accounts()[0]

	// Use a minimal valid bytecode: PUSH1 0x00 STOP (0x600000)
	// This won't have any functions, but we can test that deploy doesn't crash.
	// A PUSH1 0 (0x60 0x00) followed by DUP1 (0x80) RETURN sequence for a minimal contract.
	// runtime: 0x600080fd (PUSH1 0 DUP1 REVERT) — always reverts
	// constructor: push runtime code to memory and return it
	// Minimal constructor that returns empty runtime:
	// PUSH1 0 PUSH1 0 RETURN → 0x600060005160005260016000f3 is too complex
	// Simplest: use STOP (0x00) as both constructor and runtime.
	// Constructor bytecode: just the runtime prefixed with CODECOPY+RETURN boilerplate.
	// For testing we use a raw STOP opcode deployed via the CREATE mechanism.
	stopCode := []byte{0x00} // STOP opcode — minimal valid contract

	// Deploy using constructor code that just returns empty runtime
	// Use a simple constructor: PUSH1 0, PUSH1 0, RETURN
	// This deploys an empty (0-byte) runtime code, which is valid
	constructorBytecode := []byte{
		0x60, 0x00, // PUSH1 0 (runtime size = 0)
		0x60, 0x00, // PUSH1 0 (runtime offset)
		0xF3, // RETURN
	}
	_ = stopCode

	contractAddr, err := exec.Deploy(constructorBytecode, deployer)
	require.NoError(t, err)
	assert.NotEqual(t, contractAddr, deployer)

	// Call the empty contract with arbitrary calldata — should succeed (empty code = no revert)
	caller := exec.Accounts()[1]
	result, err := exec.Execute(caller, []byte{0x60, 0xFE, 0x47, 0xB1, 0x00, 0x00, 0x00, 0x00}, big.NewInt(0))
	require.NoError(t, err)
	assert.NotNil(t, result)
	// Empty contract silently succeeds
	assert.True(t, result.Success)
}

func TestSnapshot(t *testing.T) {
	cfg := defaultTestConfig()
	exec, err := New(cfg)
	require.NoError(t, err)

	snap := exec.Snapshot()
	assert.GreaterOrEqual(t, snap, 0)

	// Revert should not panic
	exec.Revert(snap)
}

func TestAccountFunding(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Accounts = 3
	exec, err := New(cfg)
	require.NoError(t, err)

	accounts := exec.Accounts()
	assert.Len(t, accounts, 3)

	// Accounts should be distinct
	assert.NotEqual(t, accounts[0], accounts[1])
	assert.NotEqual(t, accounts[1], accounts[2])
}

func TestTraceCapture(t *testing.T) {
	cfg := defaultTestConfig()
	exec, err := New(cfg)
	require.NoError(t, err)

	deployer := exec.Accounts()[0]

	// Deploy contract that pushes a value and stops
	// Runtime bytecode: PUSH1 42 POP STOP (0x602a5000)
	// Constructor: return the runtime bytes
	runtime := []byte{0x60, 0x2a, 0x50, 0x00} // PUSH1 42, POP, STOP
	constructor := append([]byte{
		0x60, byte(len(runtime)), // PUSH1 <runtime size>
		0x60, 0x0C,               // PUSH1 12 (offset in constructor where runtime begins)
		0x60, 0x00,               // PUSH1 0 (memory destination)
		0x39,                     // CODECOPY
		0x60, byte(len(runtime)), // PUSH1 <runtime size>
		0x60, 0x00,               // PUSH1 0
		0xF3,                     // RETURN
	}, runtime...)

	contractAddr, err := exec.Deploy(constructor, deployer)
	require.NoError(t, err)

	caller := exec.Accounts()[1]
	result, err := exec.ExecuteAt(caller, contractAddr, nil, big.NewInt(0))
	require.NoError(t, err)
	assert.True(t, result.Success)
	// Should have captured PUSH1, POP, STOP opcodes
	assert.NotEmpty(t, result.Trace)
	t.Logf("Captured %d trace entries", len(result.Trace))
	for _, e := range result.Trace {
		t.Logf("  PC=%d op=%s gas=%d", e.PC, e.OpName, e.Gas)
	}
}
