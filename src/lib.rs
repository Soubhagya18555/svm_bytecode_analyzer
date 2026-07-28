pub mod anomaly_rules;
pub mod binary_report;
pub mod cfg_builder;
pub mod cfg_export;
pub mod elf_parser;
pub mod opcode_stats;
pub mod sbf_disasm;
pub mod sbf_validator;
pub mod syscall_registry;

pub use anomaly_rules::{AnomalyReport, analyze_anomalies};
pub use binary_report::{analyze_binary, BinaryReport, ReportOptions};
pub use cfg_builder::{ControlFlowGraph, build_cfg};
pub use cfg_export::{export_cfg, export_json, CfgExportFormat};
pub use elf_parser::{ElfBinary, ElfParseError, load_elf, parse_elf_bytes};
pub use opcode_stats::{
    compare_distributions, compute_stats, detect_syscall_streaks, OpcodeStats,
};
pub use sbf_disasm::{
    disassemble, format_instruction_line, lookup_opcode, opcode_table, DisassemblyResult,
    Instruction,
};
pub use sbf_validator::{validate_bytecode, ValidationKind, ValidationReport};
pub use syscall_registry::{resolve_syscall, SyscallInfo};
