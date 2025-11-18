use svm_bytecode_analyzer::{
    analyze_anomalies, build_cfg, disassemble, lookup_opcode, opcode_table, resolve_syscall,
};
use svm_bytecode_analyzer::anomaly_rules::count_invoke_calls;
use svm_bytecode_analyzer::cfg_builder::reachable_blocks;

fn encode_insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0] = opcode;
    bytes[1] = dst;
    bytes[2] = src;
    bytes[4..6].copy_from_slice(&off.to_le_bytes());
    bytes[4..8].copy_from_slice(&imm.to_le_bytes());
    bytes
}

#[test]
fn opcode_table_has_at_least_forty_entries() {
    assert!(
        opcode_table().len() >= 40,
        "expected >= 40 opcodes, got {}",
        opcode_table().len()
    );
}

#[test]
fn decodes_mov64_and_exit() {
    let code = [
        encode_insn(0xb7, 0, 0, 0, 42), // mov64 r0, 42
        encode_insn(0x95, 0, 0, 0, 0),  // exit
    ]
    .concat();

    let result = disassemble(&code, 0);
    assert_eq!(result.instructions.len(), 2);
    assert_eq!(result.instructions[0].mnemonic, "mov64");
    assert!(result.instructions[0].operands.contains("42"));
    assert_eq!(result.instructions[1].mnemonic, "exit");
    assert!(result.instructions[1].is_exit);
}

#[test]
fn decodes_lddw_wide_instruction() {
    let mut code = Vec::new();
    code.extend_from_slice(&encode_insn(0x18, 1, 0, 0, 0x89abcdefu32 as i32));
    code.extend_from_slice(&[0, 0, 0, 0, 0x12, 0x34, 0, 0]);
    code.extend_from_slice(&encode_insn(0x95, 0, 0, 0, 0));

    let result = disassemble(&code, 0);
    assert_eq!(result.instructions.len(), 2);
    assert_eq!(result.instructions[0].mnemonic, "lddw");
    assert_eq!(result.instructions[0].size, 16);
    assert!(result.instructions[0].operands.contains("r1"));
}

#[test]
fn decodes_conditional_branch_targets() {
    let code = [
        encode_insn(0xb7, 0, 0, 0, 0),   // mov64 r0, 0
        encode_insn(0x15, 0, 1, 1, 0),   // jeq r0, r1, +1
        encode_insn(0xb7, 2, 0, 0, 7),   // mov64 r2, 7
        encode_insn(0x05, 0, 0, 1, 0),   // ja +1
        encode_insn(0xb7, 2, 0, 0, 9),   // mov64 r2, 9
        encode_insn(0x95, 0, 0, 0, 0),   // exit
    ]
    .concat();

    let result = disassemble(&code, 0);
    let branches: Vec<_> = result
        .instructions
        .iter()
        .filter(|insn| insn.is_branch)
        .collect();
    assert!(!branches.is_empty());
    assert!(branches[0].branch_target.is_some());
}

#[test]
fn resolves_sol_log_syscall_on_call() {
    let code = [
        encode_insn(0x85, 0, 0, 0, 2), // call sol_log_
        encode_insn(0x95, 0, 0, 0, 0),
    ]
    .concat();

    let result = disassemble(&code, 0);
    assert_eq!(result.instructions[0].mnemonic, "call");
    assert_eq!(
        result.instructions[0].syscall_name.as_deref(),
        Some("sol_log_")
    );
    assert!(resolve_syscall(2).is_some());
}

#[test]
fn builds_cfg_with_multiple_blocks() {
    let code = [
        encode_insn(0xb7, 0, 0, 0, 0),
        encode_insn(0x15, 0, 1, 1, 0),
        encode_insn(0xb7, 2, 0, 0, 1),
        encode_insn(0x05, 0, 0, 1, 0),
        encode_insn(0xb7, 2, 0, 0, 2),
        encode_insn(0x95, 0, 0, 0, 0),
    ]
    .concat();

    let disasm = disassemble(&code, 0);
    let cfg = build_cfg(&disasm);
    assert!(cfg.blocks.len() >= 3);
    let reachable = reachable_blocks(&cfg);
    assert!(reachable.contains(&cfg.entry_block));
}

#[test]
fn detects_unreachable_block_anomaly() {
    let code = [
        encode_insn(0x05, 0, 0, 2, 0), // ja over dead block
        encode_insn(0xb7, 0, 0, 0, 0),
        encode_insn(0x95, 0, 0, 0, 0),
        encode_insn(0xb7, 3, 0, 0, 99), // unreachable
        encode_insn(0x95, 0, 0, 0, 0),
    ]
    .concat();

    let disasm = disassemble(&code, 0);
    let cfg = build_cfg(&disasm);
    let report = analyze_anomalies(&disasm, &cfg, 1, 40);
    assert!(!report.is_clean());
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, svm_bytecode_analyzer::anomaly_rules::AnomalyKind::UnreachableBlock))
    );
}

#[test]
fn detects_invoke_heavy_path() {
    let code = [
        encode_insn(0x85, 0, 0, 0, 19), // sol_invoke_signed_c
        encode_insn(0x85, 0, 0, 0, 19),
        encode_insn(0x95, 0, 0, 0, 0),
    ]
    .concat();

    let disasm = disassemble(&code, 0);
    assert_eq!(count_invoke_calls(&disasm.instructions), 2);
    let cfg = build_cfg(&disasm);
    let report = analyze_anomalies(&disasm, &cfg, 1, 40);
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, svm_bytecode_analyzer::anomaly_rules::AnomalyKind::InvokeHeavyPath))
    );
}

#[test]
fn unknown_opcode_surfaces_warning() {
    let code = encode_insn(0xff, 0, 0, 0, 0);
    let result = disassemble(&code, 0);
    assert_eq!(result.instructions[0].mnemonic, ".byte");
    assert!(!result.errors.is_empty());
    assert!(lookup_opcode(0xff).is_none());
}

#[test]
fn parses_minimal_sbf_elf_text_section() {
    let elf = build_minimal_elf(&[
        encode_insn(0xb7, 0, 0, 0, 11),
        encode_insn(0x95, 0, 0, 0, 0),
    ]);

    let parsed = svm_bytecode_analyzer::parse_elf_bytes(&elf).expect("elf parse");
    assert!(!parsed.text.is_empty());
    let disasm = disassemble(&parsed.text, 0);
    assert_eq!(disasm.instructions[0].mnemonic, "mov64");
}

fn build_minimal_elf(text: &[[u8; 8]]) -> Vec<u8> {
    let text_bytes: Vec<u8> = text.iter().flatten().copied().collect();
    let text_size = text_bytes.len() as u32;

    let mut elf = Vec::new();
    // ELF64 header (little endian)
    elf.extend_from_slice(&[
        0x7f, b'E', b'L', b'F',
        2, 1, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0x03, 0x00, // e_type ET_DYN
        0xfe, 0x07, // e_machine EM_BPF
    ]);
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&64u64.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&4u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&3u16.to_le_bytes()); // e_shstrndx
    assert_eq!(elf.len(), 64);

    // Section 0 null
    elf.extend_from_slice(&[0u8; 64]);
    // Section 1 .text
    let text_name_off = 1u32;
    elf.extend_from_slice(&text_name_off.to_le_bytes());
    elf.extend_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
    elf.extend_from_slice(&6u64.to_le_bytes()); // SHF_ALLOC | SHF_EXECINSTR
    elf.extend_from_slice(&0u64.to_le_bytes()); // addr
    let text_offset = 64 + 64 * 4;
    elf.extend_from_slice(&(text_offset as u64).to_le_bytes());
    elf.extend_from_slice(&(text_size as u64).to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes()); // link
    elf.extend_from_slice(&0u32.to_le_bytes()); // info
    elf.extend_from_slice(&8u64.to_le_bytes()); // align
    elf.extend_from_slice(&0u64.to_le_bytes()); // entsize
    // Section 2 .rodata (empty)
    let rodata_name_off = 7u32;
    elf.extend_from_slice(&rodata_name_off.to_le_bytes());
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&2u64.to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes());
    elf.extend_from_slice(&(text_offset as u64).to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&1u64.to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes());
    // Section 3 .shstrtab
    let shstr_name_off = 15u32;
    elf.extend_from_slice(&shstr_name_off.to_le_bytes());
    elf.extend_from_slice(&3u32.to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes());
    let shstr_off = text_offset + text_size as usize;
    elf.extend_from_slice(&(shstr_off as u64).to_le_bytes());
    let shstr = b"\0.text\0.rodata\0.shstrtab\0";
    elf.extend_from_slice(&(shstr.len() as u64).to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&1u64.to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes());

    elf.extend_from_slice(&text_bytes);
    elf.extend_from_slice(shstr);
    elf
}
