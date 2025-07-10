//! Structural validation rules for SBF bytecode before execution or deeper analysis.

use crate::sbf_disasm::{DisassemblyResult, Instruction, lookup_opcode};
use serde::Serialize;
use std::collections::HashSet;

const MAX_REGISTER: u8 = 10;

/// Category of validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ValidationKind {
    UnknownOpcode,
    RegisterOutOfRange,
    BranchOutOfBounds,
    OverlappingInstruction,
    TrailingBytes,
    UnalignedWideLoad,
    ExitNotTerminator,
    DuplicateOffset,
}

/// Single validation issue with severity and location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationIssue {
    pub kind: ValidationKind,
    pub offset: usize,
    pub message: String,
    pub severity: u8,
}

/// Result of bytecode structural validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub is_valid: bool,
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|i| i.severity >= 3)
    }
}

/// Validate disassembled instructions against bytecode bounds and SBF conventions.
pub fn validate_bytecode(disasm: &DisassemblyResult, code: &[u8]) -> ValidationReport {
    let mut issues = Vec::new();
    let mut seen_offsets: HashSet<usize> = HashSet::new();

    for insn in &disasm.instructions {
        if !seen_offsets.insert(insn.offset) {
            issues.push(ValidationIssue {
                kind: ValidationKind::DuplicateOffset,
                offset: insn.offset,
                message: format!("duplicate instruction at offset 0x{:x}", insn.offset),
                severity: 3,
            });
        }

        if insn.mnemonic == ".byte" {
            issues.push(ValidationIssue {
                kind: ValidationKind::UnknownOpcode,
                offset: insn.offset,
                message: format!("unknown opcode 0x{:02x}", insn.raw.opcode),
                severity: 3,
            });
            continue;
        }

        validate_registers(insn, &mut issues);
        validate_branch_target(insn, code.len(), &mut issues);
        validate_wide_alignment(insn, &mut issues);
    }

    validate_coverage(disasm, code.len(), &mut issues);
    validate_exit_terminators(disasm, &mut issues);

    for warning in &disasm.errors {
        if warning.contains("trailing") {
            issues.push(ValidationIssue {
                kind: ValidationKind::TrailingBytes,
                offset: code.len(),
                message: warning.clone(),
                severity: 2,
            });
        }
    }

    issues.sort_by_key(|i| (i.severity, i.offset));
    let is_valid = !issues.iter().any(|i| i.severity >= 3);

    ValidationReport { is_valid, issues }
}

/// Quick validity check without building full report.
pub fn is_valid_bytecode(disasm: &DisassemblyResult, code: &[u8]) -> bool {
    validate_bytecode(disasm, code).is_valid
}

fn validate_registers(insn: &Instruction, issues: &mut Vec<ValidationIssue>) {
    if let Some(info) = lookup_opcode(insn.raw.opcode) {
        if info.has_dst && insn.raw.dst > MAX_REGISTER {
            issues.push(ValidationIssue {
                kind: ValidationKind::RegisterOutOfRange,
                offset: insn.offset,
                message: format!("dst register r{} exceeds r{MAX_REGISTER}", insn.raw.dst),
                severity: 3,
            });
        }
        if info.has_src && insn.raw.src > MAX_REGISTER {
            issues.push(ValidationIssue {
                kind: ValidationKind::RegisterOutOfRange,
                offset: insn.offset,
                message: format!("src register r{} exceeds r{MAX_REGISTER}", insn.raw.src),
                severity: 3,
            });
        }
    }
}

fn validate_branch_target(insn: &Instruction, code_len: usize, issues: &mut Vec<ValidationIssue>) {
    if !insn.is_branch {
        return;
    }
    let Some(target) = insn.branch_target else {
        issues.push(ValidationIssue {
            kind: ValidationKind::BranchOutOfBounds,
            offset: insn.offset,
            message: "branch missing computed target".into(),
            severity: 3,
        });
        return;
    };

    if target >= code_len || target % 8 != 0 {
        issues.push(ValidationIssue {
            kind: ValidationKind::BranchOutOfBounds,
            offset: insn.offset,
            message: format!(
                "branch target 0x{target:x} outside aligned code range 0..0x{code_len:x}"
            ),
            severity: 3,
        });
    }
}

fn validate_wide_alignment(insn: &Instruction, issues: &mut Vec<ValidationIssue>) {
    if insn.size == 16 && insn.offset % 8 != 0 {
        issues.push(ValidationIssue {
            kind: ValidationKind::UnalignedWideLoad,
            offset: insn.offset,
            message: "lddw must start at 8 byte aligned offset".into(),
            severity: 2,
        });
    }
}

fn validate_coverage(disasm: &DisassemblyResult, code_len: usize, issues: &mut Vec<ValidationIssue>) {
    let mut covered = vec![false; code_len];
    for insn in &disasm.instructions {
        let end = insn.offset.saturating_add(insn.size).min(code_len);
        for byte_idx in insn.offset..end {
            if covered[byte_idx] {
                issues.push(ValidationIssue {
                    kind: ValidationKind::OverlappingInstruction,
                    offset: insn.offset,
                    message: format!("instruction overlaps prior decode at byte {byte_idx}"),
                    severity: 3,
                });
                break;
            }
            covered[byte_idx] = true;
        }
    }
}

fn validate_exit_terminators(disasm: &DisassemblyResult, issues: &mut Vec<ValidationIssue>) {
    for window in disasm.instructions.windows(2) {
        if window[0].is_exit {
            issues.push(ValidationIssue {
                kind: ValidationKind::ExitNotTerminator,
                offset: window[1].offset,
                message: "instruction follows exit without new basic block leader".into(),
                severity: 1,
            });
        }
    }
}

/// Format validation report for CLI display.
pub fn format_validation_report(report: &ValidationReport) -> String {
    if report.issues.is_empty() {
        return "validation passed".into();
    }
    report
        .issues
        .iter()
        .map(|i| format!("[sev {}] {:?} @0x{:x}: {}", i.severity, i.kind, i.offset, i.message))
        .collect::<Vec<_>>()
        .join("\n")
}
