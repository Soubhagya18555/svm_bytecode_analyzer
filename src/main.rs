use clap::{Parser, Subcommand};
use std::path::PathBuf;
use svm_bytecode_analyzer::{
    analyze_anomalies, analyze_binary, build_cfg, disassemble, export_cfg, format_instruction_line,
    load_elf, validate_bytecode, CfgExportFormat, ReportOptions,
};
use svm_bytecode_analyzer::anomaly_rules::format_report;
use svm_bytecode_analyzer::binary_report::format_report_text;
use svm_bytecode_analyzer::cfg_builder::cfg_summary;
use svm_bytecode_analyzer::opcode_stats::compute_stats;

#[derive(Parser, Debug)]
#[command(
    name = "svm_bytecode_analyzer",
    author = "Soubhagya",
    version,
    about = "SBF/BPF bytecode disassembler and analyzer for Solana on chain programs"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Disassemble an ELF program binary or raw bytecode blob
    Disasm {
        /// Path to ELF binary or raw SBF bytecode
        binary_file: PathBuf,
        /// Emit control flow graph summary
        #[arg(long)]
        cfg: bool,
        /// Export CFG as DOT graph
        #[arg(long)]
        dot: bool,
        /// Emit JSON output
        #[arg(long)]
        json: bool,
    },
    /// Emit unified binary analysis report
    Report {
        /// Path to ELF binary or raw SBF bytecode
        binary_file: PathBuf,
        /// Emit JSON output
        #[arg(long)]
        json: bool,
        /// Export CFG as DOT graph
        #[arg(long)]
        dot: bool,
    },
}

#[derive(serde::Serialize)]
struct OutputDocument {
    entry_point: u64,
    text_size: usize,
    disassembly: svm_bytecode_analyzer::DisassemblyResult,
    control_flow_graph: Option<svm_bytecode_analyzer::ControlFlowGraph>,
    anomalies: Option<svm_bytecode_analyzer::AnomalyReport>,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Disasm {
            binary_file,
            cfg,
            dot,
            json,
        } => disasm_command(&binary_file, cfg, dot, json),
        Commands::Report {
            binary_file,
            json,
            dot,
        } => report_command(&binary_file, json, dot),
    }
}

fn report_command(path: &PathBuf, emit_json: bool, emit_dot: bool) -> Result<(), String> {
    let elf = load_elf(path).map_err(|e| e.to_string())?;
    let label = path.display().to_string();
    let report = analyze_binary(&elf, &label, ReportOptions::default());

    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("{}", format_report_text(&report));
    }

    if emit_dot {
        let disasm = disassemble(&elf.text, 0);
        let cfg = build_cfg(&disasm);
        let dot = export_cfg(&cfg, CfgExportFormat::Dot)?;
        println!();
        println!("{dot}");
    }

    Ok(())
}

fn disasm_command(path: &PathBuf, emit_cfg: bool, emit_dot: bool, emit_json: bool) -> Result<(), String> {
    let elf = load_elf(path).map_err(|e| e.to_string())?;
    let entry_offset = 0usize;
    let disasm = disassemble(&elf.text, entry_offset);
    let control_flow_graph = if emit_cfg || emit_json {
        Some(build_cfg(&disasm))
    } else {
        None
    };
    let anomalies = control_flow_graph
        .as_ref()
        .map(|cfg| analyze_anomalies(&disasm, cfg, 1, 40));

    if emit_json {
        let doc = OutputDocument {
            entry_point: elf.entry_point,
            text_size: elf.text.len(),
            disassembly: disasm,
            control_flow_graph,
            anomalies,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!("; svm_bytecode_analyzer disassembly");
    println!("; file: {}", path.display());
    println!("; entry_point: 0x{:x}", elf.entry_point);
    println!("; text_size: {} bytes", elf.text.len());
    println!("; sections: {}", elf.section_headers.len());
    println!();

    for insn in &disasm.instructions {
        println!("{}", format_instruction_line(insn));
    }

    if !disasm.errors.is_empty() {
        eprintln!();
        eprintln!("; disassembly warnings:");
        for warning in &disasm.errors {
            eprintln!(";   {warning}");
        }
    }

    if let Some(cfg) = control_flow_graph {
        println!();
        println!("; control flow graph");
        println!("{}", cfg_summary(&cfg));

        if emit_dot {
            let dot = export_cfg(&cfg, CfgExportFormat::Dot)?;
            println!();
            println!("{dot}");
        }

        let stats = compute_stats(&disasm);
        let validation = validate_bytecode(&disasm, &elf.text);
        println!();
        println!("; opcode stats: {} instructions, entropy {:.2} bits", stats.total_instructions, stats.entropy_bits);
        println!("; validation: {}", if validation.is_valid { "pass" } else { "fail" });
    }

    if let Some(report) = anomalies {
        println!();
        println!("; anomaly report");
        println!("{}", format_report(&report));
    }

    Ok(())
}
