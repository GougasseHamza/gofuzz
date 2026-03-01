package evm

import (
	"math/big"

	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"

	itypes "github.com/kyyblin/gofuzz-evm/internal/types"
)

// Tracer collects a full opcode-level execution trace using go-ethereum's tracing.Hooks API.
type Tracer struct {
	entries  []itypes.TraceEntry
	maxStack int
	hooks    *tracing.Hooks
}

// NewTracer creates a Tracer. maxStack controls how many top stack entries are recorded per step.
func NewTracer(maxStack int) *Tracer {
	if maxStack <= 0 {
		maxStack = 8
	}
	t := &Tracer{maxStack: maxStack}
	t.hooks = &tracing.Hooks{
		OnOpcode: t.onOpcode,
		OnFault:  t.onFault,
	}
	return t
}

// Hooks returns the *tracing.Hooks to pass into vm.Config.Tracer.
func (t *Tracer) Hooks() *tracing.Hooks { return t.hooks }

// Entries returns the collected trace after execution.
func (t *Tracer) Entries() []itypes.TraceEntry { return t.entries }

// Reset clears the trace for reuse between calls.
func (t *Tracer) Reset() { t.entries = t.entries[:0] }

// onOpcode is called by the EVM before each opcode execution.
func (t *Tracer) onOpcode(
	pc uint64,
	op byte,
	gas, cost uint64,
	scope tracing.OpContext,
	rData []byte,
	depth int,
	err error,
) {
	entry := itypes.TraceEntry{
		PC:      pc,
		Op:      op,
		OpName:  vm.OpCode(op).String(),
		Gas:     gas,
		GasCost: cost,
		Depth:   depth,
	}
	if err != nil {
		entry.Err = err.Error()
	}

	// Capture top-N stack entries (index 0 = top of stack)
	stackData := scope.StackData()
	n := len(stackData)
	if n > t.maxStack {
		n = t.maxStack
	}
	if n > 0 {
		entry.Stack = make([]*big.Int, n)
		for i := 0; i < n; i++ {
			entry.Stack[i] = stackData[len(stackData)-1-i].ToBig()
		}
	}

	t.entries = append(t.entries, entry)
}

// onFault is called when an opcode execution fault occurs.
func (t *Tracer) onFault(
	pc uint64,
	op byte,
	gas, cost uint64,
	scope tracing.OpContext,
	depth int,
	err error,
) {
	entry := itypes.TraceEntry{
		PC:      pc,
		Op:      op,
		OpName:  vm.OpCode(op).String(),
		Gas:     gas,
		GasCost: cost,
		Depth:   depth,
	}
	if err != nil {
		entry.Err = err.Error()
	}
	t.entries = append(t.entries, entry)
}
