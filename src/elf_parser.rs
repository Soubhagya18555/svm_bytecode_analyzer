use std::fs;
use std::path::Path;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;
const SHT_PROGBITS: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfParseError {
    Io(String),
    InvalidMagic,
    UnsupportedClass,
    UnsupportedEndian,
    MissingSection(String),
    Truncated(String),
    InvalidHeader(String),
}

impl std::fmt::Display for ElfParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "io error: {msg}"),
            Self::InvalidMagic => write!(f, "invalid ELF magic"),
            Self::UnsupportedClass => write!(f, "unsupported ELF class"),
            Self::UnsupportedEndian => write!(f, "unsupported endianness"),
            Self::MissingSection(name) => write!(f, "missing section: {name}"),
            Self::Truncated(ctx) => write!(f, "truncated ELF while reading {ctx}"),
            Self::InvalidHeader(msg) => write!(f, "invalid ELF header: {msg}"),
        }
    }
}

impl std::error::Error for ElfParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramHeader {
    pub segment_type: u32,
    pub offset: u64,
    pub virtual_addr: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: String,
    pub section_type: u32,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: u64,
}

#[derive(Debug, Clone)]
pub struct ElfBinary {
    pub entry_point: u64,
    pub is_64bit: bool,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    pub text: Vec<u8>,
    pub rodata: Vec<u8>,
    pub raw: Vec<u8>,
}

pub fn load_elf(path: &Path) -> Result<ElfBinary, ElfParseError> {
    let raw = fs::read(path).map_err(|e| ElfParseError::Io(e.to_string()))?;
    parse_elf_bytes(&raw)
}

pub fn parse_elf_bytes(raw: &[u8]) -> Result<ElfBinary, ElfParseError> {
    if raw.len() < 64 {
        return Err(ElfParseError::Truncated("ELF header".into()));
    }
    if raw[0..4] != ELF_MAGIC {
        return Err(ElfParseError::InvalidMagic);
    }

    let class = raw[4];
    let endian = raw[5];
    let is_64bit = match class {
        1 => false,
        2 => true,
        _ => return Err(ElfParseError::UnsupportedClass),
    };
    let little = match endian {
        1 => true,
        2 => false,
        _ => return Err(ElfParseError::UnsupportedEndian),
    };

    let read_u16 = |off: usize| -> Result<u16, ElfParseError> {
        let end = off + 2;
        if end > raw.len() {
            return Err(ElfParseError::Truncated(format!("u16@{off}")));
        }
        Ok(if little {
            u16::from_le_bytes([raw[off], raw[off + 1]])
        } else {
            u16::from_be_bytes([raw[off], raw[off + 1]])
        })
    };

    let read_u32 = |off: usize| -> Result<u32, ElfParseError> {
        let end = off + 4;
        if end > raw.len() {
            return Err(ElfParseError::Truncated(format!("u32@{off}")));
        }
        Ok(if little {
            u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
        } else {
            u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
        })
    };

    let read_u64 = |off: usize| -> Result<u64, ElfParseError> {
        let end = off + 8;
        if end > raw.len() {
            return Err(ElfParseError::Truncated(format!("u64@{off}")));
        }
        Ok(if little {
            u64::from_le_bytes([
                raw[off],
                raw[off + 1],
                raw[off + 2],
                raw[off + 3],
                raw[off + 4],
                raw[off + 5],
                raw[off + 6],
                raw[off + 7],
            ])
        } else {
            u64::from_be_bytes([
                raw[off],
                raw[off + 1],
                raw[off + 2],
                raw[off + 3],
                raw[off + 4],
                raw[off + 5],
                raw[off + 6],
                raw[off + 7],
            ])
        })
    };

    let entry_point = if is_64bit {
        read_u64(24)?
    } else {
        read_u32(24)? as u64
    };

    let phoff = if is_64bit {
        read_u64(32)?
    } else {
        read_u32(28)? as u64
    };
    let shoff = if is_64bit {
        read_u64(40)?
    } else {
        read_u32(32)? as u64
    };
    let shstrndx = read_u16(if is_64bit { 62 } else { 50 })? as usize;

    let program_headers = parse_program_headers(raw, is_64bit, little, phoff)?;
    let (section_headers, _shstrtab) =
        parse_section_headers(raw, is_64bit, little, shoff, shstrndx)?;

    let text = extract_section(raw, &section_headers, ".text")?;
    let rodata = extract_section(raw, &section_headers, ".rodata").unwrap_or_default();

    Ok(ElfBinary {
        entry_point,
        is_64bit,
        program_headers,
        section_headers,
        text,
        rodata,
        raw: raw.to_vec(),
    })
}

fn parse_program_headers(
    raw: &[u8],
    is_64bit: bool,
    little: bool,
    phoff: u64,
) -> Result<Vec<ProgramHeader>, ElfParseError> {
    let e_phnum = read_u16(raw, little, if is_64bit { 56 } else { 44 })? as usize;
    let e_phentsize = read_u16(raw, little, if is_64bit { 54 } else { 42 })? as usize;
    let mut headers = Vec::with_capacity(e_phnum);

    for i in 0..e_phnum {
        let base = phoff as usize + i * e_phentsize;
        if is_64bit {
            if base + 56 > raw.len() {
                return Err(ElfParseError::Truncated("program header".into()));
            }
            headers.push(ProgramHeader {
                segment_type: read_u32(raw, little, base)?,
                offset: read_u64(raw, little, base + 8)?,
                virtual_addr: read_u64(raw, little, base + 16)?,
                file_size: read_u64(raw, little, base + 32)?,
                memory_size: read_u64(raw, little, base + 40)?,
                flags: read_u32(raw, little, base + 4)?,
            });
        } else if base + 32 > raw.len() {
            return Err(ElfParseError::Truncated("program header".into()));
        } else {
            headers.push(ProgramHeader {
                segment_type: read_u32(raw, little, base)?,
                offset: read_u32(raw, little, base + 4)? as u64,
                virtual_addr: read_u32(raw, little, base + 8)? as u64,
                file_size: read_u32(raw, little, base + 16)? as u64,
                memory_size: read_u32(raw, little, base + 20)? as u64,
                flags: read_u32(raw, little, base + 24)?,
            });
        }
    }

    let _ = little;
    Ok(headers)
}

fn parse_section_headers(
    raw: &[u8],
    is_64bit: bool,
    little: bool,
    shoff: u64,
    shstrndx: usize,
) -> Result<(Vec<SectionHeader>, Vec<u8>), ElfParseError> {
    let e_shnum = read_u16(raw, little, if is_64bit { 60 } else { 48 })? as usize;
    let e_shentsize = read_u16(raw, little, if is_64bit { 58 } else { 46 })? as usize;
    let mut headers = Vec::with_capacity(e_shnum);

    for i in 0..e_shnum {
        let base = shoff as usize + i * e_shentsize;
        if is_64bit {
            if base + 64 > raw.len() {
                return Err(ElfParseError::Truncated("section header".into()));
            }
            headers.push(SectionHeader {
                name: String::new(),
                section_type: read_u32(raw, little, base + 4)?,
                address: read_u64(raw, little, base + 16)?,
                offset: read_u64(raw, little, base + 24)?,
                size: read_u64(raw, little, base + 32)?,
                flags: read_u64(raw, little, base + 8)?,
            });
        } else if base + 40 > raw.len() {
            return Err(ElfParseError::Truncated("section header".into()));
        } else {
            headers.push(SectionHeader {
                name: String::new(),
                section_type: read_u32(raw, little, base + 4)?,
                address: read_u32(raw, little, base + 12)? as u64,
                offset: read_u32(raw, little, base + 16)? as u64,
                size: read_u32(raw, little, base + 20)? as u64,
                flags: read_u64(raw, little, base + 8)?,
            });
        }
    }

    if shstrndx >= headers.len() {
        return Err(ElfParseError::InvalidHeader("shstrndx out of range".into()));
    }

    let shstr = &headers[shstrndx];
    let shstr_start = shstr.offset as usize;
    let shstr_end = shstr_start + shstr.size as usize;
    if shstr_end > raw.len() {
        return Err(ElfParseError::Truncated("section header string table".into()));
    }
    let shstrtab = raw[shstr_start..shstr_end].to_vec();

    for (i, header) in headers.iter_mut().enumerate() {
        let name_off = read_u32(raw, little, shoff as usize + i * e_shentsize)? as usize;
        header.name = read_cstring(&shstrtab, name_off);
    }

    let _ = little;
    Ok((headers, shstrtab))
}

fn read_u16(raw: &[u8], little: bool, off: usize) -> Result<u16, ElfParseError> {
    let end = off + 2;
    if end > raw.len() {
        return Err(ElfParseError::Truncated(format!("u16@{off}")));
    }
    Ok(if little {
        u16::from_le_bytes([raw[off], raw[off + 1]])
    } else {
        u16::from_be_bytes([raw[off], raw[off + 1]])
    })
}

fn read_u32(raw: &[u8], little: bool, off: usize) -> Result<u32, ElfParseError> {
    let end = off + 4;
    if end > raw.len() {
        return Err(ElfParseError::Truncated(format!("u32@{off}")));
    }
    Ok(if little {
        u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
    } else {
        u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
    })
}

fn read_u64(raw: &[u8], little: bool, off: usize) -> Result<u64, ElfParseError> {
    let end = off + 8;
    if end > raw.len() {
        return Err(ElfParseError::Truncated(format!("u64@{off}")));
    }
    Ok(if little {
        u64::from_le_bytes([
            raw[off],
            raw[off + 1],
            raw[off + 2],
            raw[off + 3],
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ])
    } else {
        u64::from_be_bytes([
            raw[off],
            raw[off + 1],
            raw[off + 2],
            raw[off + 3],
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ])
    })
}

fn read_cstring(table: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < table.len() && table[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&table[offset..end]).into_owned()
}

fn extract_section(
    raw: &[u8],
    sections: &[SectionHeader],
    name: &str,
) -> Result<Vec<u8>, ElfParseError> {
    let section = sections
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| ElfParseError::MissingSection(name.into()))?;

    if section.section_type != SHT_PROGBITS {
        return Err(ElfParseError::InvalidHeader(format!(
            "section {name} is not PROGBITS"
        )));
    }

    let start = section.offset as usize;
    let end = start + section.size as usize;
    if end > raw.len() {
        return Err(ElfParseError::Truncated(format!("section {name}")));
    }

    Ok(raw[start..end].to_vec())
}

pub fn extract_loadable_segments(binary: &ElfBinary) -> Vec<(u64, Vec<u8>)> {
    binary
        .program_headers
        .iter()
        .filter(|ph| ph.segment_type == PT_LOAD && ph.file_size > 0)
        .filter_map(|ph| {
            let start = ph.offset as usize;
            let end = start + ph.file_size as usize;
            if end <= binary.raw.len() {
                Some((ph.virtual_addr, binary.raw[start..end].to_vec()))
            } else {
                None
            }
        })
        .collect()
}
