use clap::{Parser, Subcommand};
use std::path::PathBuf;
use svm_bytecode_analyzer::{
    analyze_anomalies, build_cfg, disassemble, format_instruction_line, load_elf,
};
use svm_bytecode_analyzer::anomaly_rules::format_report;
use svm_bytecode_analyzer::cfg_builder::cfg_summary;

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
        /// Emit JSON output
        #[arg(long)]
        json: bool,
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
            json,
        } => disasm_command(&binary_file, cfg, json),
    }
}

fn disasm_command(path: &PathBuf, emit_cfg: bool, emit_json: bool) -> Result<(), String> {
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
    }

    if let Some(report) = anomalies {
        println!();
        println!("; anomaly report");
        println!("{}", format_report(&report));
    }

    Ok(())
}
