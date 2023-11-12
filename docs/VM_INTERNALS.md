# SVM VM Internals

This document describes how `svm_bytecode_analyzer` models the Solana Virtual Machine at the bytecode layer. It is intended for security reviewers, program auditors, and contributors extending the analyzer.

## Execution model

Solana programs are shipped as ELF shared objects compiled for the SBF target. The on chain loader maps the executable segment into the RBPF virtual machine, sets register `r10` to the stack pointer, places the input parameter buffer in `r1`, and transfers control to the ELF entry point.

The analyzer focuses on static views of that bytecode:

1. Extract `.text` from the ELF container.
2. Linearly decode instructions using the SBF opcode map.
3. Split decoded instructions into basic blocks at leaders.
4. Connect blocks with edges for branches, calls, and fallthrough.
5. Apply anomaly policies on top of the resulting graph.

## Register file

RBPF exposes eleven general purpose registers:

| Register | Typical use |
|----------|-------------|
| r0 | Return value |
| r1 | First argument / input buffer pointer at entry |
| r2 .. r5 | Additional syscall arguments |
| r6 .. r9 | Callee saved scratch |
| r10 | Frame pointer / stack anchor |

The disassembler prints register operands using `rN` syntax regardless of whether the underlying compiler used a symbolic name in debug metadata.

## Opcode classes

### ALU64 and ALU32

Arithmetic and logic operations support immediate and register forms. Immediate variants encode a signed 32 bit constant in the `imm` field. Register variants read the second operand from `src`.

### Memory

* `lddw` loads a 64 bit immediate spread across two consecutive eight byte slots.
* `ldxb`, `ldxh`, `ldxw`, `ldxdw` read from `[src + off]`.
* `stb`, `sth`, `stw`, `stdw` write immediates to `[dst + off]`.
* `stxb`, `stxh`, `stxw`, `stxdw` write from `src` to `[dst + off]`.

All offsets are signed 16 bit displacements.

### Control transfer

Unconditional `ja` uses only the offset field. Conditional branches compare `dst` and `src` and fall through to the next instruction when the predicate is false.

`call` uses the `imm` field as a syscall identifier for external functions implemented by the runtime. Regular function calls inside the same ELF object are also encoded with `call`, but those use PC relative targets in newer toolchains; this analyzer treats any `call` with a small immediate as a syscall candidate and consults `syscall_registry`.

`exit` terminates execution and returns the value held in `r0`.

## Syscall calling convention

Syscall invocation is a specialized `call` instruction. Arguments are passed in `r1` through `r5` depending on the syscall prototype. The registry in `syscall_registry.rs` lists the stable identifiers for logging, hashing, sysvar access, memory helpers, and cross program invocation.

Invoke syscalls of particular interest to security review:

* `sol_invoke_signed_c` (19)
* `sol_invoke_signed_rust` (20)

The anomaly engine treats blocks with repeated invoke syscalls as higher risk because each invoke expands the attack surface for account metas validation bugs and reentrancy style issues at the protocol layer.

## CFG construction

Basic block leaders are discovered using standard rules:

* The entry offset is always a leader.
* Branch targets are leaders.
* Instructions following conditional branches are leaders.
* Instructions following `call` or `exit` begin a new leader when fallthrough is possible.

Edges are added as follows:

* Conditional branch: edge to target, optional fallthrough edge.
* Unconditional branch: edge to target only.
* Call: fallthrough edge to the next block unless the call is marked as noreturn by ending the block.
* Straight line code: fallthrough edge.

Reachability analysis performs a breadth first traversal from the entry block. Blocks outside the reachable set are reported as unreachable. Unreachable code can indicate dead compiler output, feature gated paths, or manual insertion of unreachable sleds.

## Anomaly policies

| Policy | Trigger | Severity |
|--------|---------|----------|
| Unreachable block | Block not reachable from entry | 2 |
| Invoke heavy path | Block with `invoke` syscall count above threshold | 3 |
| High call density | Block where calls exceed 40 percent of instructions and at least three calls | 2 |
| Missing exit | Block without `exit` and without successors | 1 |
| Unknown opcode | Byte sequence not present in opcode table | 2 |

Thresholds are configurable through `analyze_anomalies` for library users. The CLI uses a default invoke threshold of one and call density threshold of forty percent.

## JSON schema

When `--json` is passed, the tool emits a single document containing:

* `entry_point` from the ELF header
* `text_size` in bytes
* `disassembly` with per instruction metadata
* optional `control_flow_graph`
* optional `anomalies`

This format is suitable for diffing builds in CI or feeding graph visualizers.

## Limitations

* The analyzer does not emulate the VM and does not validate account metadata.
* PC relative internal calls are reported as syscalls when the immediate matches the registry.
* Only little endian 64 bit ELF objects are fully supported.
* Stack and heap usage require dynamic tracing and are out of scope for this release.

## References

* Solana RBPF repository instruction definitions
* ELF 64 specification for section header parsing
* Solana syscall list published with agave releases
