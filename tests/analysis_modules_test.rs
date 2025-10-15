use svm_bytecode_analyzer::{
    build_cfg, compute_stats, disassemble, export_cfg, export_json, validate_bytecode,
    CfgExportFormat, analyze_binary, compare_distributions, detect_syscall_streaks,
};
use svm_bytecode_analyzer::binary_report::ReportOptions;

fn encode_insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0] = opcode;
    bytes[1] = dst;
    bytes[2] = src;
    bytes[4..6].copy_from_slice(&off.to_le_bytes());
    bytes[4..8].copy_from_slice(&imm.to_le_bytes());
    bytes
}

fn sample_program_with_branch() -> Vec<u8> {
    [
        encode_insn(0xb7, 0, 0, 0, 0),
        encode_insn(0x15, 0, 1, 1, 0),
        encode_insn(0xb7, 2, 0, 0, 1),
        encode_insn(0x05, 0, 0, 1, 0),
        encode_insn(0xb7, 2, 0, 0, 2),
        encode_insn(0x95, 0, 0, 0, 0),
    ]
    .concat()
}

#[test]
fn opcode_stats_counts_mnemonics() {
    let code = sample_program_with_branch();
    let disasm = disassemble(&code, 0);
    let stats = compute_stats(&disasm);
    assert!(stats.total_instructions >= 5);
    assert!(stats.by_mnemonic.contains_key("mov64"));
    assert!(stats.branch_count >= 1);
    assert!(stats.entropy_bits > 0.0);
}

#[test]
fn opcode_stats_detects_syscall_streaks() {
    let code = [
        encode_insn(0x85, 0, 0, 0, 2),
        encode_insn(0x85, 0, 0, 0, 2),
        encode_insn(0x85, 0, 0, 0, 2),
        encode_insn(0x95, 0, 0, 0, 0),
    ]
    .concat();
    let disasm = disassemble(&code, 0);
    let streaks = detect_syscall_streaks(&disasm.instructions, 3);
    assert_eq!(streaks.len(), 1);
    assert!(streaks[0].1.contains("sol_log"));
}

#[test]
fn compare_distributions_finds_deltas() {
    let code_a = [encode_insn(0xb7, 0, 0, 0, 1), encode_insn(0x95, 0, 0, 0, 0)].concat();
    let code_b = [
        encode_insn(0xb7, 0, 0, 0, 1),
        encode_insn(0xb7, 1, 0, 0, 2),
        encode_insn(0x95, 0, 0, 0, 0),
    ]
    .concat();
    let stats_a = compute_stats(&disassemble(&code_a, 0));
    let stats_b = compute_stats(&disassemble(&code_b, 0));
    let deltas = compare_distributions(&stats_a, &stats_b);
    assert!(!deltas.is_empty());
    assert!(deltas.iter().any(|d| d.mnemonic == "mov64" && d.delta > 0));
}

#[test]
fn cfg_export_dot_contains_nodes() {
    let code = sample_program_with_branch();
    let disasm = disassemble(&code, 0);
    let cfg = build_cfg(&disasm);
    let dot = export_cfg(&cfg, CfgExportFormat::Dot).unwrap();
    assert!(dot.contains("digraph sbf_cfg"));
    assert!(dot.contains("block0"));
}

#[test]
fn cfg_export_json_is_valid() {
    let code = sample_program_with_branch();
    let disasm = disassemble(&code, 0);
    let cfg = build_cfg(&disasm);
    let json = export_json(&cfg).unwrap();
    assert!(json.contains("\"entry_block\""));
    assert!(json.contains("\"nodes\""));
}

#[test]
fn validator_rejects_unknown_opcode() {
    let code = encode_insn(0xff, 0, 0, 0, 0);
    let disasm = disassemble(&code, 0);
    let report = validate_bytecode(&disasm, &code);
    assert!(!report.is_valid);
    assert!(report.issues.iter().any(|i| matches!(
        i.kind,
        svm_bytecode_analyzer::ValidationKind::UnknownOpcode
    )));
}

#[test]
fn validator_accepts_minimal_exit_program() {
    let code = [encode_insn(0xb7, 0, 0, 0, 42), encode_insn(0x95, 0, 0, 0, 0)].concat();
    let disasm = disassemble(&code, 0);
    let report = validate_bytecode(&disasm, &code);
    assert!(report.is_valid);
}

#[test]
fn binary_report_computes_risk_score() {
    let code = [
        encode_insn(0x85, 0, 0, 0, 19),
        encode_insn(0x85, 0, 0, 0, 19),
        encode_insn(0x95, 0, 0, 0, 0),
    ]
    .concat();
    let elf = svm_bytecode_analyzer::ElfBinary {
        entry_point: 0,
        is_64bit: true,
        program_headers: vec![],
        section_headers: vec![],
        text: code,
        rodata: vec![],
        raw: vec![],
    };
    let report = analyze_binary(&elf, "test.so", ReportOptions::default());
    assert!(report.risk_score > 0);
    assert!(report.disassembly.instruction_count >= 3);
}
