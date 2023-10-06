# Analysis Modules

Author: Soubhagya

This document describes the extended analysis modules in `svm_bytecode_analyzer` beyond core disassembly and CFG construction.

## opcode_stats

The `opcode_stats` module aggregates instruction level metrics from a `DisassemblyResult`:

* Mnemonic and class histograms
* Syscall call counts resolved through `syscall_registry`
* Branch, call, exit, and unknown opcode totals
* Shannon entropy of the mnemonic distribution
* Syscall streak detection for repeated CPI patterns

Use `compute_stats` after disassembly and `compare_distributions` when diffing two builds of the same program.

## cfg_export

The `cfg_export` module serializes a `ControlFlowGraph` for visualization or pipeline ingestion:

* **DOT**: Graphviz compatible output with entry, exit, and invoke heavy block highlighting
* **JSON**: Portable node and edge document via `CfgGraphDocument`
* **Metrics**: Block count, edge count, merge points, invoke blocks

Example:

```bash
svm_bytecode_analyzer disasm program.so --cfg --dot
svm_bytecode_analyzer report program.so --json --dot
```

## sbf_validator

The `sbf_validator` module applies structural checks before deeper analysis:

* Unknown opcode detection
* Register index bounds (r0 through r10)
* Branch target alignment and range
* Instruction overlap and trailing byte detection
* Wide `lddw` alignment

A program can disassemble with warnings yet fail validation when branch targets leave the text section.

## binary_report

The `binary_report` module combines ELF metadata, disassembly summary, opcode stats, CFG metrics, validation, and anomaly findings into one `BinaryReport` with a computed risk score from 0 to 100.

The `report` subcommand emits either human readable text or JSON suitable for CI gates:

```bash
svm_bytecode_analyzer report program.so
svm_bytecode_analyzer report program.so --json
```

## Integration workflow

```
ELF load -> disassemble -> validate_bytecode
                |                |
                v                v
           compute_stats    build_cfg -> export_cfg / compute_metrics
                \                /
                 v              v
              analyze_binary -> BinaryReport
```

## Testing

Module tests live in `tests/analysis_modules_test.rs` alongside existing disassembly integration tests in `tests/disasm_test.rs`.

Run the full suite with:

```bash
cargo test
```
