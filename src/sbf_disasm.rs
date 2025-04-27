use crate::syscall_registry::resolve_syscall;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InstructionClass {
    Alu32,
    Alu64,
    Jmp,
    Jmp32,
    Ld,
    Ldx,
    St,
    Stx,
    Misc,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpcodeInfo {
    pub mnemonic: &'static str,
    pub class: InstructionClass,
    pub has_dst: bool,
    pub has_src: bool,
    pub has_imm: bool,
    pub has_offset: bool,
    pub is_wide: bool,
    pub is_call: bool,
    pub is_exit: bool,
    pub is_branch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawInsn {
    pub offset: usize,
    pub opcode: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Instruction {
    pub offset: usize,
    pub raw: RawInsn,
    pub mnemonic: String,
    pub operands: String,
    pub class: InstructionClass,
    pub is_call: bool,
    pub is_exit: bool,
    pub is_branch: bool,
    pub branch_target: Option<usize>,
    pub syscall_name: Option<String>,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisassemblyResult {
    pub entry_offset: usize,
    pub instructions: Vec<Instruction>,
    pub errors: Vec<String>,
}

pub fn opcode_table() -> &'static [(u8, OpcodeInfo)] {
    static TABLE: &[(u8, OpcodeInfo)] = &[
        // ALU64 immediate
        (0x07, OpcodeInfo { mnemonic: "add64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x17, OpcodeInfo { mnemonic: "sub64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x27, OpcodeInfo { mnemonic: "mul64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x37, OpcodeInfo { mnemonic: "div64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x47, OpcodeInfo { mnemonic: "or64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x57, OpcodeInfo { mnemonic: "and64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x67, OpcodeInfo { mnemonic: "lsh64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x77, OpcodeInfo { mnemonic: "rsh64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x87, OpcodeInfo { mnemonic: "neg64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x97, OpcodeInfo { mnemonic: "mod64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xa7, OpcodeInfo { mnemonic: "xor64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xb7, OpcodeInfo { mnemonic: "mov64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xc7, OpcodeInfo { mnemonic: "arsh64", class: InstructionClass::Alu64, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        // ALU64 register
        (0x0f, OpcodeInfo { mnemonic: "add64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x1f, OpcodeInfo { mnemonic: "sub64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x2f, OpcodeInfo { mnemonic: "mul64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x3f, OpcodeInfo { mnemonic: "div64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x4f, OpcodeInfo { mnemonic: "or64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x5f, OpcodeInfo { mnemonic: "and64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x6f, OpcodeInfo { mnemonic: "lsh64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x7f, OpcodeInfo { mnemonic: "rsh64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x9f, OpcodeInfo { mnemonic: "mod64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xaf, OpcodeInfo { mnemonic: "xor64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xbf, OpcodeInfo { mnemonic: "mov64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xcf, OpcodeInfo { mnemonic: "arsh64", class: InstructionClass::Alu64, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        // ALU32 immediate
        (0x04, OpcodeInfo { mnemonic: "add32", class: InstructionClass::Alu32, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x14, OpcodeInfo { mnemonic: "sub32", class: InstructionClass::Alu32, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xb4, OpcodeInfo { mnemonic: "mov32", class: InstructionClass::Alu32, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        // ALU32 register
        (0x0c, OpcodeInfo { mnemonic: "add32", class: InstructionClass::Alu32, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xbc, OpcodeInfo { mnemonic: "mov32", class: InstructionClass::Alu32, has_dst: true, has_src: true, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        // JMP
        (0x05, OpcodeInfo { mnemonic: "ja", class: InstructionClass::Jmp, has_dst: false, has_src: false, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x15, OpcodeInfo { mnemonic: "jeq", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x1d, OpcodeInfo { mnemonic: "jgt", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x25, OpcodeInfo { mnemonic: "jge", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x2d, OpcodeInfo { mnemonic: "jlt", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x35, OpcodeInfo { mnemonic: "jle", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x55, OpcodeInfo { mnemonic: "jne", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x65, OpcodeInfo { mnemonic: "jsgt", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x6d, OpcodeInfo { mnemonic: "jsge", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x75, OpcodeInfo { mnemonic: "jslt", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0x7d, OpcodeInfo { mnemonic: "jsle", class: InstructionClass::Jmp, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        // JMP32
        (0xa5, OpcodeInfo { mnemonic: "jeq32", class: InstructionClass::Jmp32, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        (0xb5, OpcodeInfo { mnemonic: "jne32", class: InstructionClass::Jmp32, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: true }),
        // LD
        (0x18, OpcodeInfo { mnemonic: "lddw", class: InstructionClass::Ld, has_dst: true, has_src: false, has_imm: true, has_offset: false, is_wide: true, is_call: false, is_exit: false, is_branch: false }),
        // LDX
        (0x71, OpcodeInfo { mnemonic: "ldxb", class: InstructionClass::Ldx, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x69, OpcodeInfo { mnemonic: "ldxh", class: InstructionClass::Ldx, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x61, OpcodeInfo { mnemonic: "ldxw", class: InstructionClass::Ldx, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x79, OpcodeInfo { mnemonic: "ldxdw", class: InstructionClass::Ldx, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        // ST
        (0x72, OpcodeInfo { mnemonic: "stb", class: InstructionClass::St, has_dst: true, has_src: false, has_imm: true, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x6a, OpcodeInfo { mnemonic: "sth", class: InstructionClass::St, has_dst: true, has_src: false, has_imm: true, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x62, OpcodeInfo { mnemonic: "stw", class: InstructionClass::St, has_dst: true, has_src: false, has_imm: true, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x7a, OpcodeInfo { mnemonic: "stdw", class: InstructionClass::St, has_dst: true, has_src: false, has_imm: true, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        // STX
        (0x73, OpcodeInfo { mnemonic: "stxb", class: InstructionClass::Stx, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x6b, OpcodeInfo { mnemonic: "stxh", class: InstructionClass::Stx, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x63, OpcodeInfo { mnemonic: "stxw", class: InstructionClass::Stx, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0x7b, OpcodeInfo { mnemonic: "stxdw", class: InstructionClass::Stx, has_dst: true, has_src: true, has_imm: false, has_offset: true, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        // MISC
        (0x85, OpcodeInfo { mnemonic: "call", class: InstructionClass::Misc, has_dst: false, has_src: false, has_imm: true, has_offset: false, is_wide: false, is_call: true, is_exit: false, is_branch: false }),
        (0x95, OpcodeInfo { mnemonic: "exit", class: InstructionClass::Misc, has_dst: false, has_src: false, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: true, is_branch: false }),
        (0xd4, OpcodeInfo { mnemonic: "le", class: InstructionClass::Misc, has_dst: true, has_src: false, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
        (0xdc, OpcodeInfo { mnemonic: "be", class: InstructionClass::Misc, has_dst: true, has_src: false, has_imm: false, has_offset: false, is_wide: false, is_call: false, is_exit: false, is_branch: false }),
    ];
    TABLE
}

pub fn lookup_opcode(opcode: u8) -> Option<&'static OpcodeInfo> {
    opcode_table()
        .iter()
        .find(|(op, _)| *op == opcode)
        .map(|(_, info)| info)
}

pub fn disassemble(code: &[u8], entry_offset: usize) -> DisassemblyResult {
    let mut instructions = Vec::new();
    let mut errors = Vec::new();
    let mut offset = 0usize;

    while offset + 8 <= code.len() {
        let insn_offset = entry_offset + offset;
        let raw = decode_raw(code, offset, insn_offset);

        if let Some(info) = lookup_opcode(raw.opcode) {
            if info.is_wide {
                if offset + 16 > code.len() {
                    errors.push(format!(
                        "lddw at 0x{insn_offset:x} requires 16 bytes but only {} remain",
                        code.len() - offset
                    ));
                    break;
                }
                let low = raw.imm as u32 as u64;
                let high = i32::from_le_bytes([
                    code[offset + 12],
                    code[offset + 13],
                    code[offset + 14],
                    code[offset + 15],
                ]) as u64;
                let value = low | (high << 32);
                let operands = format!("r{}, {value}", raw.dst);
                instructions.push(Instruction {
                    offset: insn_offset,
                    raw: raw.clone(),
                    mnemonic: info.mnemonic.to_string(),
                    operands,
                    class: info.class,
                    is_call: false,
                    is_exit: false,
                    is_branch: false,
                    branch_target: None,
                    syscall_name: None,
                    size: 16,
                });
                offset += 16;
                continue;
            }

            let (operands, branch_target, syscall_name) =
                format_operands(&raw, info, insn_offset);

            instructions.push(Instruction {
                offset: insn_offset,
                raw,
                mnemonic: info.mnemonic.to_string(),
                operands,
                class: info.class,
                is_call: info.is_call,
                is_exit: info.is_exit,
                is_branch: info.is_branch,
                branch_target,
                syscall_name,
                size: 8,
            });
        } else {
            errors.push(format!(
                "unknown opcode 0x{:02x} at offset 0x{insn_offset:x}",
                raw.opcode
            ));
            instructions.push(Instruction {
                offset: insn_offset,
                raw,
                mnemonic: ".byte".into(),
                operands: format!("0x{:02x}", code[offset]),
                class: InstructionClass::Unknown,
                is_call: false,
                is_exit: false,
                is_branch: false,
                branch_target: None,
                syscall_name: None,
                size: 8,
            });
        }

        offset += 8;
    }

    if offset < code.len() {
        errors.push(format!(
            "trailing {} bytes after last full instruction",
            code.len() - offset
        ));
    }

    DisassemblyResult {
        entry_offset,
        instructions,
        errors,
    }
}

fn decode_raw(code: &[u8], offset: usize, insn_offset: usize) -> RawInsn {
    RawInsn {
        offset: insn_offset,
        opcode: code[offset],
        dst: code[offset + 1],
        src: code[offset + 2],
        off: i16::from_le_bytes([code[offset + 4], code[offset + 5]]),
        imm: i32::from_le_bytes([
            code[offset + 4],
            code[offset + 5],
            code[offset + 6],
            code[offset + 7],
        ]),
    }
}

fn format_operands(
    raw: &RawInsn,
    info: &OpcodeInfo,
    insn_offset: usize,
) -> (String, Option<usize>, Option<String>) {
    let reg = |n: u8| format!("r{n}");
    let mut branch_target = None;
    let mut syscall_name = None;

    let operands = match info.class {
        InstructionClass::Alu64 | InstructionClass::Alu32 => {
            if info.has_src {
                format!("{}, {}", reg(raw.dst), reg(raw.src))
            } else if info.has_imm {
                format!("{}, {}", reg(raw.dst), raw.imm)
            } else {
                format!("{}", reg(raw.dst))
            }
        }
        InstructionClass::Jmp | InstructionClass::Jmp32 => {
            let target = (insn_offset as i64 + 8 + (raw.off as i64 * 8)) as usize;
            branch_target = Some(target);
            if info.has_dst && info.has_src {
                format!("{}, {}, 0x{target:x}", reg(raw.dst), reg(raw.src))
            } else {
                format!("0x{target:x}")
            }
        }
        InstructionClass::Ldx | InstructionClass::Stx => {
            format!("{}, [{}+{}]", reg(raw.dst), reg(raw.src), raw.off)
        }
        InstructionClass::St => {
            format!("[{}+{}], {}", reg(raw.dst), raw.off, raw.imm)
        }
        InstructionClass::Misc if info.is_call => {
            syscall_name = resolve_syscall(raw.imm as u32).map(|s| s.name.to_string());
            if let Some(name) = &syscall_name {
                format!("{name} ; imm={}", raw.imm)
            } else {
                format!("0x{:x} ; imm={}", raw.imm as u32, raw.imm)
            }
        }
        InstructionClass::Misc if info.is_exit => "return".into(),
        InstructionClass::Misc => format!("{}", reg(raw.dst)),
        _ => format!(
            "r{}, r{}, off={}, imm={}",
            raw.dst, raw.src, raw.off, raw.imm
        ),
    };

    (operands, branch_target, syscall_name)
}

pub fn format_instruction_line(insn: &Instruction) -> String {
    format!(
        "0x{:04x}: {:<8} {}",
        insn.offset,
        insn.mnemonic,
        insn.operands
    )
}
