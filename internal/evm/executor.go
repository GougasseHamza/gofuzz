// Package evm manages go-ethereum EVM instances for contract deployment and execution.
package evm

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	coretypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"

	itypes "github.com/kyyblin/gofuzz-evm/internal/types"
	"github.com/kyyblin/gofuzz-evm/pkg/config"
)

// Executor wraps a go-ethereum EVM instance with state management.
type Executor struct {
	chainConfig  *params.ChainConfig
	stateDB      *state.StateDB
	accounts     []common.Address
	contractAddr common.Address
	gasLimit     uint64
	tracer       *Tracer
	blockNum     *big.Int
	blockTime    uint64
}

// New creates an Executor configured for the given fork and accounts.
func New(cfg *config.FuzzConfig) (*Executor, error) {
	chainConfig := chainConfigForFork(cfg.EVMFork)

	// state.NewDatabaseForTesting creates an ephemeral in-memory state database.
	sdb := state.NewDatabaseForTesting()
	stateDB, err := state.New(coretypes.EmptyRootHash, sdb)
	if err != nil {
		return nil, fmt.Errorf("evm: creating state: %w", err)
	}

	// Fund simulated accounts.
	accounts := make([]common.Address, cfg.Accounts)
	balance, overflow := uint256.FromBig(cfg.InitialBalance)
	if overflow {
		return nil, fmt.Errorf("evm: initial balance overflows uint256")
	}
	for i := range accounts {
		addr := accountAddress(i)
		accounts[i] = addr
		stateDB.CreateAccount(addr)
		stateDB.AddBalance(addr, balance, tracing.BalanceChangeUnspecified)
	}
	stateDB.Finalise(true)

	return &Executor{
		chainConfig: chainConfig,
		stateDB:     stateDB,
		accounts:    accounts,
		gasLimit:    cfg.GasLimit,
		tracer:      NewTracer(8),
		blockNum:    big.NewInt(20_000_000),
		blockTime:   1_700_000_000,
	}, nil
}

// Accounts returns the list of simulated EOA addresses.
func (e *Executor) Accounts() []common.Address { return e.accounts }

// ContractAddress returns the deployed contract address.
func (e *Executor) ContractAddress() common.Address { return e.contractAddr }

// Deploy deploys initCode (constructor bytecode) from `from` and records the contract address.
func (e *Executor) Deploy(initCode []byte, from common.Address) (common.Address, error) {
	evm := e.newEVM(from)
	defer evm.Cancel()

	_, contractAddr, _, err := evm.Create(from, initCode, e.gasLimit, uint256.NewInt(0))
	if err != nil {
		return common.Address{}, fmt.Errorf("evm: deploy failed: %w", err)
	}

	e.contractAddr = contractAddr
	e.stateDB.Finalise(true)
	return contractAddr, nil
}

// Execute calls a function on the deployed contract and returns the result.
func (e *Executor) Execute(from common.Address, calldata []byte, value *big.Int) (*itypes.ExecutionResult, error) {
	if e.contractAddr == (common.Address{}) {
		return nil, errors.New("evm: no contract deployed")
	}
	return e.ExecuteAt(from, e.contractAddr, calldata, value)
}

// ExecuteAt calls `to` from `from` with the given calldata and value.
func (e *Executor) ExecuteAt(from, to common.Address, calldata []byte, value *big.Int) (*itypes.ExecutionResult, error) {
	if value == nil {
		value = big.NewInt(0)
	}
	u256val, overflow := uint256.FromBig(value)
	if overflow {
		return nil, fmt.Errorf("evm: value overflows uint256")
	}

	e.tracer.Reset()
	evm := e.newEVM(from)
	defer evm.Cancel()

	snapshot := e.stateDB.Snapshot()

	ret, gasLeft, err := evm.Call(from, to, calldata, e.gasLimit, u256val)

	gasUsed := e.gasLimit - gasLeft
	reverted := false
	var callErr error

	if err != nil {
		reverted = isRevert(err)
		callErr = err
		e.stateDB.RevertToSnapshot(snapshot)
	} else {
		e.stateDB.Finalise(true)
	}

	trace := make([]itypes.TraceEntry, len(e.tracer.Entries()))
	copy(trace, e.tracer.Entries())

	return &itypes.ExecutionResult{
		Success:      err == nil,
		ReturnData:   ret,
		GasUsed:      gasUsed,
		GasRemaining: gasLeft,
		Trace:        trace,
		Err:          callErr,
		Reverted:     reverted,
	}, nil
}

// Snapshot takes a state snapshot and returns an opaque ID.
func (e *Executor) Snapshot() int { return e.stateDB.Snapshot() }

// Revert rolls the state back to the given snapshot ID.
func (e *Executor) Revert(id int) { e.stateDB.RevertToSnapshot(id) }

// --- internal ---

func (e *Executor) newEVM(from common.Address) *vm.EVM {
	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash:     zeroGetHash,
		Coinbase:    common.Address{},
		GasLimit:    e.gasLimit,
		BlockNumber: new(big.Int).Set(e.blockNum),
		Time:        e.blockTime,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(0),
		Random:      &common.Hash{},
	}
	vmCfg := vm.Config{
		Tracer:    e.tracer.Hooks(),
		NoBaseFee: true,
	}
	evm := vm.NewEVM(blockCtx, e.stateDB, e.chainConfig, vmCfg)
	evm.SetTxContext(vm.TxContext{
		Origin:   from,
		GasPrice: big.NewInt(0),
	})
	return evm
}

// chainConfigForFork returns a ChainConfig with all forks through the named one active at genesis.
func chainConfigForFork(fork string) *params.ChainConfig {
	zero := uint64(0)
	enabled := &zero

	cfg := &params.ChainConfig{
		ChainID:             big.NewInt(1337),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArrowGlacierBlock:   big.NewInt(0),
		GrayGlacierBlock:    big.NewInt(0),
		MergeNetsplitBlock:  big.NewInt(0),
		ShanghaiTime:        enabled,
		TerminalTotalDifficulty: big.NewInt(0),
	}

	switch fork {
	case "cancun", "":
		cfg.CancunTime = enabled
	case "shanghai":
		// ShanghaiTime already set
	case "london":
		cfg.ShanghaiTime = nil
	}

	return cfg
}

// accountAddress derives a deterministic address for simulated account index i.
func accountAddress(i int) common.Address {
	var addr common.Address
	addr[19] = byte(i + 1) // 0x01, 0x02, …
	return addr
}

// zeroGetHash is a stub that returns zero for all block numbers.
func zeroGetHash(_ uint64) common.Hash { return common.Hash{} }

// isRevert returns true if err represents an EVM execution revert.
func isRevert(err error) bool { return errors.Is(err, vm.ErrExecutionReverted) }
