pub mod anomaly_rules;
pub mod cfg_builder;
pub mod elf_parser;
pub mod sbf_disasm;
pub mod syscall_registry;

pub use anomaly_rules::{AnomalyReport, analyze_anomalies};
pub use cfg_builder::{ControlFlowGraph, build_cfg};
pub use elf_parser::{ElfBinary, ElfParseError, load_elf, parse_elf_bytes};
pub use sbf_disasm::{
    DisassemblyResult, Instruction, disassemble, format_instruction_line, lookup_opcode,
    opcode_table,
};
pub use syscall_registry::{SyscallInfo, resolve_syscall};
