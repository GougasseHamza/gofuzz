// Package types defines shared data structures used across GoFuzz-EVM subsystems.
package types

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Severity classifies finding impact.
type Severity string

const (
	SeverityCritical      Severity = "CRITICAL"
	SeverityHigh          Severity = "HIGH"
	SeverityMedium        Severity = "MEDIUM"
	SeverityLow           Severity = "LOW"
	SeverityInformational Severity = "INFORMATIONAL"
)

// Transaction represents a single EVM transaction in a sequence.
type Transaction struct {
	From     common.Address `json:"from"`
	To       common.Address `json:"to"`
	Calldata []byte         `json:"calldata"`
	Value    *big.Int       `json:"value"`
	GasLimit uint64         `json:"gas_limit"`
}

// TraceEntry records a single opcode execution step.
type TraceEntry struct {
	PC      uint64     `json:"pc"`
	Op      byte       `json:"op"`      // vm.OpCode as byte
	OpName  string     `json:"op_name"` // human-readable name
	Gas     uint64     `json:"gas"`
	GasCost uint64     `json:"gas_cost"`
	Depth   int        `json:"depth"`
	Stack   []*big.Int `json:"stack,omitempty"` // top-N entries
	Err     string     `json:"err,omitempty"`
}

// ExecutionResult holds the outcome of a single EVM call.
type ExecutionResult struct {
	Success      bool         `json:"success"`
	ReturnData   []byte       `json:"return_data,omitempty"`
	GasUsed      uint64       `json:"gas_used"`
	GasRemaining uint64       `json:"gas_remaining"`
	Trace        []TraceEntry `json:"trace,omitempty"`
	Err          error        `json:"-"`
	Reverted     bool         `json:"reverted"`
}

// Finding represents a detected vulnerability.
type Finding struct {
	ID             string        `json:"id"`
	Timestamp      time.Time     `json:"timestamp"`
	VulnClass      string        `json:"vuln_class"`
	Severity       Severity      `json:"severity"`
	Function       string        `json:"function"`
	TriggerInput   []byte        `json:"trigger_input"`
	TxSequence     []Transaction `json:"tx_sequence"`
	TraceExcerpt   []TraceEntry  `json:"trace_excerpt,omitempty"`
	Description    string        `json:"description"`
	Remediation    string        `json:"remediation"`
	CoverageAtFind float64       `json:"coverage_at_find"`
}
