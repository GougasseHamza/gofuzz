# GoFuzz-EVM

`gofuzz-evm` is a Go-based smart contract fuzzer for EVM bytecode.  
It parses a contract ABI, generates mutated calldata, executes calls in an in-memory EVM (`go-ethereum`), and reports basic runtime anomalies.

## Current Status

This repository is an MVP/prototype with working core pieces:

- ABI parsing and selector extraction
- In-memory EVM deployment and execution
- Calldata generation + mutation strategies (random, boundary, bitflip, arithmetic, dictionary, transplant)
- Opcode-level tracing
- Basic finding signal: unexpected revert on nonpayable functions

Some config fields/flags are present but not fully wired into behavior yet (`workers`, `max-seq`, `corpus`, `output`, and multi-oracle list).

## Requirements

- Go `1.23+`
- A compiled contract ABI file (`.json`)
- Contract deployment bytecode hex file (`.bin` or text hex)

## Build

```bash
make build
./gofuzz-evm version
```

Or:

```bash
go build -o gofuzz-evm ./cmd/gofuzz-evm
```

## Quick Start

1. Compile your Solidity contract to ABI + bytecode (example with `solc`):

```bash
solc --abi --bin MyContract.sol -o build
```

2. Inspect ABI:

```bash
./gofuzz-evm analyze build/MyContract.abi
```

3. Run fuzzing:

```bash
./gofuzz-evm fuzz \
  --abi build/MyContract.abi \
  --bin build/MyContract.bin \
  --duration 2m \
  --max-runs 200000 \
  --verbose
```

## CLI

```bash
gofuzz-evm [command]
```

Available commands:

- `fuzz` - Run a fuzzing campaign
- `analyze` - Parse and print ABI function metadata
- `version` - Print binary version

Useful `fuzz` flags:

- `--abi` (required): ABI JSON path
- `--bin` (required): deployment bytecode hex path
- `--duration`: stop after a time window (`0` = unlimited)
- `--max-runs`: stop after N executions (`0` = unlimited)
- `--gas-limit`: per-call gas limit
- `--fork`: `cancun` | `shanghai` | `london`
- `--seed`: deterministic fuzz seed
- `--verbose`: debug logs
- `--quiet`: suppress progress output

## Development

```bash
make test
make test-verbose
make bench
make fuzz-abi
```

## Project Layout

```text
cmd/gofuzz-evm/        CLI entrypoint
internal/abi/          ABI parsing and metadata extraction
internal/evm/          EVM executor + tracer
internal/mutator/      Calldata generation/mutation strategies
internal/types/        Shared result/finding/trace types
pkg/config/            Runtime config defaults
```

## Notes / Limitations

- Fuzz loop currently executes single-call inputs (not transaction sequences).
- `workers` is currently a config/CLI field but execution loop is single-threaded in `cmd/gofuzz-evm/main.go`.
- Findings are currently logged; structured report writing to `output/` is not implemented yet.
- Corpus persistence/loading from `corpus/` is not implemented yet.

