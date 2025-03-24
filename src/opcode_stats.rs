//! Opcode frequency and distribution statistics for SBF disassembly output.

use crate::sbf_disasm::{DisassemblyResult, Instruction, InstructionClass};
use serde::Serialize;
use std::collections::BTreeMap;

/// Aggregated opcode usage metrics for a single disassembly pass.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OpcodeStats {
    pub total_instructions: usize,
    pub total_bytes: usize,
    pub unique_mnemonics: usize,
    pub by_mnemonic: BTreeMap<String, usize>,
    pub by_class: BTreeMap<String, usize>,
    pub syscall_counts: BTreeMap<String, usize>,
    pub branch_count: usize,
    pub call_count: usize,
    pub exit_count: usize,
    pub unknown_count: usize,
    pub wide_instruction_count: usize,
    pub entropy_bits: f64,
}

impl OpcodeStats {
    pub fn top_mnemonics(&self, limit: usize) -> Vec<(&str, usize)> {
        let mut entries: Vec<_> = self
            .by_mnemonic
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        entries.truncate(limit);
        entries
    }

    pub fn class_ratio(&self, class: InstructionClass) -> f64 {
        if self.total_instructions == 0 {
            return 0.0;
        }
        let key = class_label(class);
        let count = self.by_class.get(key).copied().unwrap_or(0);
        count as f64 / self.total_instructions as f64
    }
}

/// Compute opcode statistics from a disassembly result.
pub fn compute_stats(disasm: &DisassemblyResult) -> OpcodeStats {
    let mut by_mnemonic: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    let mut syscall_counts: BTreeMap<String, usize> = BTreeMap::new();

    let mut branch_count = 0usize;
    let mut call_count = 0usize;
    let mut exit_count = 0usize;
    let mut unknown_count = 0usize;
    let mut wide_instruction_count = 0usize;
    let mut total_bytes = 0usize;

    for insn in &disasm.instructions {
        *by_mnemonic.entry(insn.mnemonic.clone()).or_default() += 1;
        *by_class
            .entry(class_label(insn.class).to_string())
            .or_default() += 1;

        total_bytes += insn.size;

        if insn.is_branch {
            branch_count += 1;
        }
        if insn.is_call {
            call_count += 1;
            if let Some(name) = &insn.syscall_name {
                *syscall_counts.entry(name.clone()).or_default() += 1;
            }
        }
        if insn.is_exit {
            exit_count += 1;
        }
        if insn.mnemonic == ".byte" {
            unknown_count += 1;
        }
        if insn.size == 16 {
            wide_instruction_count += 1;
        }
    }

    let total_instructions = disasm.instructions.len();
    let entropy_bits = shannon_entropy(&by_mnemonic, total_instructions);

    OpcodeStats {
        total_instructions,
        total_bytes,
        unique_mnemonics: by_mnemonic.len(),
        by_mnemonic,
        by_class,
        syscall_counts,
        branch_count,
        call_count,
        exit_count,
        unknown_count,
        wide_instruction_count,
        entropy_bits,
    }
}

/// Compare opcode distribution between two programs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DistributionDelta {
    pub mnemonic: String,
    pub count_a: usize,
    pub count_b: usize,
    pub delta: i64,
}

pub fn compare_distributions(a: &OpcodeStats, b: &OpcodeStats) -> Vec<DistributionDelta> {
    let mut keys: BTreeMap<String, ()> = BTreeMap::new();
    for key in a.by_mnemonic.keys().chain(b.by_mnemonic.keys()) {
        keys.insert(key.clone(), ());
    }

    let mut deltas: Vec<DistributionDelta> = keys
        .into_keys()
        .map(|mnemonic| {
            let count_a = a.by_mnemonic.get(&mnemonic).copied().unwrap_or(0);
            let count_b = b.by_mnemonic.get(&mnemonic).copied().unwrap_or(0);
            DistributionDelta {
                mnemonic,
                count_a,
                count_b,
                delta: count_b as i64 - count_a as i64,
            }
        })
        .collect();

    deltas.sort_by(|x, y| {
        y.delta
            .abs()
            .cmp(&x.delta.abs())
            .then_with(|| x.mnemonic.cmp(&y.mnemonic))
    });
    deltas
}

pub fn format_stats_summary(stats: &OpcodeStats) -> String {
    let mut lines = Vec::new();
    lines.push(format!("instructions: {}", stats.total_instructions));
    lines.push(format!("bytes: {}", stats.total_bytes));
    lines.push(format!("unique_mnemonics: {}", stats.unique_mnemonics));
    lines.push(format!("entropy_bits: {:.3}", stats.entropy_bits));
    lines.push(format!(
        "branches: {} calls: {} exits: {} unknown: {}",
        stats.branch_count, stats.call_count, stats.exit_count, stats.unknown_count
    ));

    lines.push("top_mnemonics:".into());
    for (mnemonic, count) in stats.top_mnemonics(8) {
        lines.push(format!("  {mnemonic}: {count}"));
    }

    if !stats.syscall_counts.is_empty() {
        lines.push("syscalls:".into());
        for (name, count) in &stats.syscall_counts {
            lines.push(format!("  {name}: {count}"));
        }
    }

    lines.join("\n")
}

fn class_label(class: InstructionClass) -> &'static str {
    match class {
        InstructionClass::Alu32 => "alu32",
        InstructionClass::Alu64 => "alu64",
        InstructionClass::Jmp => "jmp",
        InstructionClass::Jmp32 => "jmp32",
        InstructionClass::Ld => "ld",
        InstructionClass::Ldx => "ldx",
        InstructionClass::St => "st",
        InstructionClass::Stx => "stx",
        InstructionClass::Misc => "misc",
        InstructionClass::Unknown => "unknown",
    }
}

fn shannon_entropy(counts: &BTreeMap<String, usize>, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    counts
        .values()
        .map(|&count| {
            if count == 0 {
                0.0
            } else {
                let p = count as f64 / total_f;
                -p * p.log2()
            }
        })
        .sum()
}

/// Scan instructions for repeated syscall sequences (potential CPI loops).
pub fn detect_syscall_streaks(instructions: &[Instruction], min_len: usize) -> Vec<(usize, String)> {
    let mut streaks = Vec::new();
    let mut run_start = 0usize;
    let mut run_name: Option<String> = None;
    let mut run_len = 0usize;

    for (idx, insn) in instructions.iter().enumerate() {
        let current = insn.syscall_name.clone();
        if current == run_name && current.is_some() {
            run_len += 1;
        } else {
            if run_len >= min_len {
                if let Some(name) = &run_name {
                    streaks.push((run_start, name.clone()));
                }
            }
            run_start = idx;
            run_name = current;
            run_len = if run_name.is_some() { 1 } else { 0 };
        }
    }

    if run_len >= min_len {
        if let Some(name) = &run_name {
            streaks.push((run_start, name.clone()));
        }
    }

    streaks
}
