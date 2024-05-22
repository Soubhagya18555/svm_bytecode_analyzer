//! Unified binary analysis report aggregating disassembly, CFG, stats, and validation.

use crate::anomaly_rules::{AnomalyReport, analyze_anomalies};
use crate::cfg_builder::{ControlFlowGraph, build_cfg};
use crate::cfg_export::{CfgMetrics, compute_metrics, to_graph_document};
use crate::elf_parser::ElfBinary;
use crate::opcode_stats::{OpcodeStats, compute_stats};
use crate::sbf_disasm::{DisassemblyResult, disassemble};
use crate::sbf_validator::{ValidationReport, validate_bytecode};
use serde::Serialize;

/// Full static analysis report for one SBF ELF binary.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BinaryReport {
    pub source_label: String,
    pub entry_point: u64,
    pub text_size: usize,
    pub section_count: usize,
    pub rodata_size: usize,
    pub disassembly: DisassemblySummary,
    pub opcode_stats: OpcodeStats,
    pub cfg_metrics: CfgMetrics,
    pub validation: ValidationReport,
    pub anomalies: AnomalyReport,
    pub risk_score: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DisassemblySummary {
    pub instruction_count: usize,
    pub error_count: usize,
    pub warnings: Vec<String>,
}

/// Options controlling report generation thresholds.
#[derive(Debug, Clone, Copy)]
pub struct ReportOptions {
    pub invoke_heavy_threshold: usize,
    pub call_density_threshold: usize,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            invoke_heavy_threshold: 1,
            call_density_threshold: 40,
        }
    }
}

/// Analyze an ELF binary and produce a unified report.
pub fn analyze_binary(
    elf: &ElfBinary,
    source_label: &str,
    options: ReportOptions,
) -> BinaryReport {
    let entry_offset = 0usize;
    let disasm = disassemble(&elf.text, entry_offset);
    let cfg = build_cfg(&disasm);
    build_report_from_parts(
        source_label,
        elf,
        &disasm,
        &cfg,
        options,
    )
}

/// Build report from precomputed disassembly and CFG (useful for tests).
pub fn build_report_from_parts(
    source_label: &str,
    elf: &ElfBinary,
    disasm: &DisassemblyResult,
    cfg: &ControlFlowGraph,
    options: ReportOptions,
) -> BinaryReport {
    let opcode_stats = compute_stats(disasm);
    let cfg_metrics = compute_metrics(cfg);
    let validation = validate_bytecode(disasm, &elf.text);
    let anomalies = analyze_anomalies(
        disasm,
        cfg,
        options.invoke_heavy_threshold,
        options.call_density_threshold,
    );
    let risk_score = compute_risk_score(&opcode_stats, &cfg_metrics, &validation, &anomalies);

    BinaryReport {
        source_label: source_label.to_string(),
        entry_point: elf.entry_point,
        text_size: elf.text.len(),
        section_count: elf.section_headers.len(),
        rodata_size: elf.rodata.len(),
        disassembly: DisassemblySummary {
            instruction_count: disasm.instructions.len(),
            error_count: disasm.errors.len(),
            warnings: disasm.errors.clone(),
        },
        opcode_stats,
        cfg_metrics,
        validation,
        anomalies,
        risk_score,
    }
}

/// Serialize report to pretty JSON.
pub fn report_to_json(report: &BinaryReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Human readable multi section report for CLI output.
pub fn format_report_text(report: &BinaryReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("binary report: {}", report.source_label));
    lines.push(format!("entry_point: 0x{:x}", report.entry_point));
    lines.push(format!("text_size: {} bytes", report.text_size));
    lines.push(format!("sections: {}", report.section_count));
    lines.push(format!("risk_score: {}/100", report.risk_score));
    lines.push(String::new());

    lines.push("disassembly".into());
    lines.push(format!(
        "  instructions: {} errors: {}",
        report.disassembly.instruction_count, report.disassembly.error_count
    ));

    lines.push(String::new());
    lines.push("opcode stats".into());
    for line in crate::opcode_stats::format_stats_summary(&report.opcode_stats)
        .lines()
    {
        lines.push(format!("  {line}"));
    }

    lines.push(String::new());
    lines.push("cfg metrics".into());
    lines.push(format!("  blocks: {}", report.cfg_metrics.block_count));
    lines.push(format!("  edges: {}", report.cfg_metrics.edge_count));
    lines.push(format!("  merge_points: {}", report.cfg_metrics.merge_points));
    lines.push(format!("  invoke_blocks: {}", report.cfg_metrics.invoke_blocks));

    lines.push(String::new());
    lines.push("validation".into());
    lines.push(format!(
        "  valid: {} issues: {}",
        report.validation.is_valid,
        report.validation.issues.len()
    ));
    for issue in &report.validation.issues {
        lines.push(format!("  [sev {}] {:?} @0x{:x}: {}", issue.severity, issue.kind, issue.offset, issue.message));
    }

    lines.push(String::new());
    lines.push("anomalies".into());
    lines.push(format!(
        "  {}",
        crate::anomaly_rules::format_report(&report.anomalies)
            .lines()
            .collect::<Vec<_>>()
            .join("\n  ")
    ));

    lines.join("\n")
}

/// Export CFG graph document alongside report metadata.
pub fn report_with_graph(report: &BinaryReport, cfg: &ControlFlowGraph) -> ReportBundle {
    ReportBundle {
        report: report.clone(),
        graph: to_graph_document(cfg),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReportBundle {
    pub report: BinaryReport,
    pub graph: crate::cfg_export::CfgGraphDocument,
}

fn compute_risk_score(
    stats: &OpcodeStats,
    metrics: &CfgMetrics,
    validation: &ValidationReport,
    anomalies: &AnomalyReport,
) -> u8 {
    let mut score = 0u8;

    score = score.saturating_add((stats.unknown_count * 5).min(20) as u8);
    score = score.saturating_add((validation.issues.len() * 4).min(24) as u8);
    score = score.saturating_add((anomalies.anomalies.len() * 3).min(30) as u8);
    score = score.saturating_add((metrics.invoke_blocks * 5).min(15) as u8);

    if stats.call_count > 20 {
        score = score.saturating_add(5);
    }
    if metrics.merge_points > 10 {
        score = score.saturating_add(5);
    }

    score.min(100)
}
