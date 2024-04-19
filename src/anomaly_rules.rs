use crate::cfg_builder::{ControlFlowGraph, invoke_heavy_blocks, unreachable_block_offsets};
use crate::sbf_disasm::{DisassemblyResult, Instruction};
use crate::syscall_registry::is_invoke_syscall;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AnomalyKind {
    InvokeHeavyPath,
    UnreachableBlock,
    HighCallDensity,
    MissingExit,
    UnknownOpcode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub offset: usize,
    pub message: String,
    pub severity: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnomalyReport {
    pub anomalies: Vec<Anomaly>,
    pub invoke_heavy_threshold: usize,
    pub call_density_threshold: usize,
}

impl AnomalyReport {
    pub fn is_clean(&self) -> bool {
        self.anomalies.is_empty()
    }
}

pub fn analyze_anomalies(
    disasm: &DisassemblyResult,
    cfg: &ControlFlowGraph,
    invoke_heavy_threshold: usize,
    call_density_threshold: usize,
) -> AnomalyReport {
    let mut anomalies = Vec::new();

    for offset in unreachable_block_offsets(cfg) {
        anomalies.push(Anomaly {
            kind: AnomalyKind::UnreachableBlock,
            offset,
            message: format!("basic block at 0x{offset:x} is not reachable from entry"),
            severity: 2,
        });
    }

    for offset in invoke_heavy_blocks(cfg, invoke_heavy_threshold) {
        anomalies.push(Anomaly {
            kind: AnomalyKind::InvokeHeavyPath,
            offset,
            message: format!(
                "block at 0x{offset:x} contains {invoke_heavy_threshold}+ invoke syscalls"
            ),
            severity: 3,
        });
    }

    for block in &cfg.blocks {
        if block.instruction_offsets.is_empty() {
            continue;
        }
        let density = block.call_count * 100 / block.instruction_offsets.len().max(1);
        if density >= call_density_threshold && block.call_count >= 3 {
            anomalies.push(Anomaly {
                kind: AnomalyKind::HighCallDensity,
                offset: block.start_offset,
                message: format!(
                    "block at 0x{:x} has call density {density}% ({} calls / {} insns)",
                    block.start_offset,
                    block.call_count,
                    block.instruction_offsets.len()
                ),
                severity: 2,
            });
        }
        if !block.has_exit && block.successors.is_empty() && !block.instruction_offsets.is_empty() {
            anomalies.push(Anomaly {
                kind: AnomalyKind::MissingExit,
                offset: block.start_offset,
                message: format!(
                    "block at 0x{:x} has no exit instruction and no successors",
                    block.start_offset
                ),
                severity: 1,
            });
        }
    }

    for insn in &disasm.instructions {
        if insn.mnemonic == ".byte" {
            anomalies.push(Anomaly {
                kind: AnomalyKind::UnknownOpcode,
                offset: insn.offset,
                message: format!("unknown opcode at 0x{:x}", insn.offset),
                severity: 2,
            });
        }
        if insn.is_call {
            if let Some(name) = &insn.syscall_name {
                if name.contains("invoke") {
                    continue;
                }
            }
            if is_invoke_syscall(insn.raw.imm as u32) {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::InvokeHeavyPath,
                    offset: insn.offset,
                    message: format!("invoke syscall at 0x{:x}", insn.offset),
                    severity: 2,
                });
            }
        }
    }

    anomalies.sort_by_key(|a| (a.severity, a.offset));
    anomalies.dedup_by(|a, b| a.kind == b.kind && a.offset == b.offset);

    AnomalyReport {
        anomalies,
        invoke_heavy_threshold,
        call_density_threshold,
    }
}

pub fn format_report(report: &AnomalyReport) -> String {
    if report.anomalies.is_empty() {
        return "no anomalies detected".into();
    }

    report
        .anomalies
        .iter()
        .map(|a| format!("[sev {}] {:?} @0x{:x}: {}", a.severity, a.kind, a.offset, a.message))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn count_invoke_calls(instructions: &[Instruction]) -> usize {
    instructions
        .iter()
        .filter(|insn| {
            insn.is_call
                && (insn
                    .syscall_name
                    .as_deref()
                    .is_some_and(|n| n.contains("invoke"))
                    || is_invoke_syscall(insn.raw.imm as u32))
        })
        .count()
}
