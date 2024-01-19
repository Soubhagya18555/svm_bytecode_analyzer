# svm_bytecode_analyzer

Static analysis toolkit for Solana Virtual Machine (SVM) programs. The analyzer ingests compiled SBF (Solana BPF) ELF binaries, decodes eBPF style instructions, reconstructs a control flow graph, resolves syscall targets, and flags structural anomalies such as unreachable basic blocks and invoke heavy execution paths.

Author: **Soubhagya**

## Features

* **ELF ingestion**: Parses 64 bit little endian ELF objects and extracts the executable `.text` section used by Solana loaders.
* **SBF disassembly**: Decodes 50+ opcode variants covering ALU32, ALU64, memory, branch, wide `lddw`, `call`, and `exit` instructions.
* **Syscall resolution**: Maps immediate syscall identifiers to human readable Solana runtime functions (`sol_log_`, `sol_invoke_signed_c`, sysvar accessors, and more).
* **Control flow graph**: Partitions instructions into basic blocks, tracks fallthrough and branch edges, and summarizes call density per block.
* **Anomaly detection**: Flags unreachable blocks, invoke heavy regions, high call density, missing terminators, and unknown opcodes.
* **CLI and JSON**: Human readable listing or structured JSON for automation pipelines.

## Architecture

```
+-------------------+       +------------------+       +-------------------+
|  ELF binary file  | ----> |   elf_parser     | ----> |  .text bytecode   |
+-------------------+       +------------------+       +-------------------+
                                                                |
                                                                v
                       +------------------+       +-------------------+
                       | syscall_registry | <---- |   sbf_disasm      |
                       +------------------+       +-------------------+
                                                                |
                                                                v
                       +------------------+       +-------------------+
                       | anomaly_rules    | <---- |   cfg_builder     |
                       +------------------+       +-------------------+
                                |
                                v
                       +------------------+
                       |  CLI / JSON out  |
                       +------------------+
```

### Module responsibilities

| Module | Role |
|--------|------|
| `elf_parser` | Validates ELF magic, walks section headers, extracts `.text` and `.rodata` |
| `sbf_disasm` | Opcode table lookup, operand formatting, wide instruction handling |
| `syscall_registry` | Static table of Solana syscall IDs with descriptions |
| `cfg_builder` | Leader identification, edge construction, reachability helpers |
| `anomaly_rules` | Policy engine for invoke heavy paths and unreachable code |

## Instruction format

Each SBF instruction is eight bytes unless it is a wide `lddw`, which consumes sixteen bytes:

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    opcode     |     dst       |     src       |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
|                          imm32                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Branches encode a signed instruction offset in the `off` field. The disassembler converts this to an absolute byte offset using `target = pc + 8 + off * 8`.

## Build

Requires Rust 1.70 or newer.

```bash
cargo build --release
```

## Usage

```bash
# Plain disassembly
svm_bytecode_analyzer disasm program.so

# Include CFG summary and anomaly report
svm_bytecode_analyzer disasm program.so --cfg

# Machine readable output
svm_bytecode_analyzer disasm program.so --cfg --json
```

### Example output

```
; svm_bytecode_analyzer disassembly
; file: program.so
; entry_point: 0x0
; text_size: 16 bytes

0x0000: mov64    r0, 42
0x0008: exit     return
```

## Testing

```bash
cargo test
```

Integration tests cover opcode coverage, wide instruction decoding, CFG construction, syscall naming, ELF section extraction, and anomaly triggers.

## Security research applications

* Audit CPI heavy program regions before mainnet deployment
* Compare compiler output across toolchain versions
* Detect dead code left by optimization or obfuscation attempts
* Build teaching material for SVM internals and syscall surfaces

## Documentation

See [docs/VM_INTERNALS.md](docs/VM_INTERNALS.md) for a deeper treatment of register conventions, syscall calling patterns, and CFG construction rules.

## License

MIT License. Copyright (c) 2026 Soubhagya. See [LICENSE](LICENSE).
