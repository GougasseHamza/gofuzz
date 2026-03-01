// Package abi wraps go-ethereum's ABI library with validation and metadata extraction.
package abi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

// Function holds parsed metadata for a single contract function.
type Function struct {
	Name       string
	Selector   [4]byte
	Inputs     abi.Arguments
	Outputs    abi.Arguments
	Mutability string // "pure" | "view" | "nonpayable" | "payable"
	IsPayable  bool
}

// ParsedABI is the result of parsing and validating an ABI JSON document.
type ParsedABI struct {
	Raw         abi.ABI
	Functions   []*Function
	Constructor *Function // nil if absent
}

// ParseFile reads an ABI JSON file from disk and parses it.
func ParseFile(path string) (*ParsedABI, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("abi: reading %q: %w", path, err)
	}
	return Parse(data)
}

// Parse parses raw ABI JSON bytes.
func Parse(data []byte) (*ParsedABI, error) {
	if !json.Valid(data) {
		return nil, fmt.Errorf("abi: invalid JSON")
	}

	raw, err := abi.JSON(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("abi: parse error: %w", err)
	}

	p := &ParsedABI{Raw: raw}

	for name, method := range raw.Methods {
		fn := methodToFunction(name, method)
		p.Functions = append(p.Functions, fn)
	}

	if raw.Constructor.Type == abi.Constructor {
		p.Constructor = &Function{
			Name:       "<constructor>",
			Inputs:     raw.Constructor.Inputs,
			Mutability: string(raw.Constructor.StateMutability),
			IsPayable:  raw.Constructor.IsPayable(),
		}
	}

	if len(p.Functions) == 0 {
		return nil, fmt.Errorf("abi: no callable functions found")
	}

	return p, nil
}

// ParseWithBytecode accepts a combined JSON containing both "abi" and "bytecode" keys,
// or falls back to treating the entire input as a bare ABI array.
func ParseWithBytecode(abiData []byte) (*ParsedABI, []byte, error) {
	// Try combined artifact format: {"abi": [...], "bytecode": "0x..."}
	var artifact struct {
		ABI      json.RawMessage `json:"abi"`
		Bytecode string          `json:"bytecode"`
	}
	if err := json.Unmarshal(abiData, &artifact); err == nil && len(artifact.ABI) > 0 {
		parsed, err := Parse(artifact.ABI)
		if err != nil {
			return nil, nil, err
		}
		bytecode, err := hexToBytes(artifact.Bytecode)
		if err != nil {
			return nil, nil, fmt.Errorf("abi: invalid bytecode in artifact: %w", err)
		}
		return parsed, bytecode, nil
	}

	// Bare ABI array
	parsed, err := Parse(abiData)
	return parsed, nil, err
}

// FunctionBySelector returns the Function matching a 4-byte selector, or nil.
func (p *ParsedABI) FunctionBySelector(sel [4]byte) *Function {
	for _, fn := range p.Functions {
		if fn.Selector == sel {
			return fn
		}
	}
	return nil
}

// FunctionByName returns the Function with the given name, or nil.
func (p *ParsedABI) FunctionByName(name string) *Function {
	for _, fn := range p.Functions {
		if fn.Name == name {
			return fn
		}
	}
	return nil
}

// methodToFunction converts a go-ethereum abi.Method to our Function type.
func methodToFunction(name string, m abi.Method) *Function {
	sig := m.Sig
	hash := crypto.Keccak256([]byte(sig))
	var sel [4]byte
	copy(sel[:], hash[:4])

	return &Function{
		Name:       name,
		Selector:   sel,
		Inputs:     m.Inputs,
		Outputs:    m.Outputs,
		Mutability: string(m.StateMutability),
		IsPayable:  m.IsPayable(),
	}
}

// hexToBytes decodes a 0x-prefixed or bare hex string.
func hexToBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return nil, fmt.Errorf("empty bytecode")
	}
	return hex.DecodeString(s)
}
