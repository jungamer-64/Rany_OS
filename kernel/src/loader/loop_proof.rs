// ============================================================================
// src/loader/loop_proof.rs - Loop Boundary Proof Metadata Validation
// 設計書 4.4.2: ループ境界静的証明
// ============================================================================

#![allow(dead_code)]

use core::str;

pub const LOOP_PROOF_SECTION_NAME: &str = ".rany_loop_proof";
const LOOP_PROOF_MAGIC: [u8; 4] = *b"RLOP";
const LOOP_PROOF_VERSION: u32 = 1;
const LOOP_PROOF_SECTION_MIN_SIZE: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopProofMetadata {
    pub version: u32,
    pub policy_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopProofError {
    MissingSection,
    InvalidElf(&'static str),
    InvalidSize(usize),
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u32),
}

impl core::fmt::Display for LoopProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingSection => write!(f, "missing .rany_loop_proof section"),
            Self::InvalidElf(msg) => write!(f, "invalid ELF for loop proof: {}", msg),
            Self::InvalidSize(size) => write!(
                f,
                "invalid .rany_loop_proof size: {} (expected >= {})",
                size, LOOP_PROOF_SECTION_MIN_SIZE
            ),
            Self::InvalidMagic(magic) => write!(
                f,
                "invalid .rany_loop_proof magic: {:02x}{:02x}{:02x}{:02x}",
                magic[0], magic[1], magic[2], magic[3]
            ),
            Self::UnsupportedVersion(v) => write!(f, "unsupported .rany_loop_proof version: {}", v),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name_offset: u32,
    data_offset: u64,
    data_size: u64,
}

#[inline]
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[inline]
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_section_header(
    elf_data: &[u8],
    section_table_offset: usize,
    section_entry_size: usize,
    index: usize,
) -> Option<SectionHeader> {
    let base = section_table_offset.checked_add(index.checked_mul(section_entry_size)?)?;
    let _ = elf_data.get(base..base + section_entry_size)?;

    Some(SectionHeader {
        name_offset: read_u32(elf_data, base)?,
        data_offset: read_u64(elf_data, base + 0x18)?,
        data_size: read_u64(elf_data, base + 0x20)?,
    })
}

fn find_loop_proof_section(elf_data: &[u8]) -> Result<&[u8], LoopProofError> {
    if elf_data.len() < 64 {
        return Err(LoopProofError::InvalidElf("ELF header too small"));
    }

    if elf_data.get(0..4) != Some(&[0x7f, b'E', b'L', b'F']) {
        return Err(LoopProofError::InvalidElf("ELF magic mismatch"));
    }

    if elf_data.get(4).copied() != Some(2) {
        return Err(LoopProofError::InvalidElf("unsupported ELF class (expected 64-bit)"));
    }

    if elf_data.get(5).copied() != Some(1) {
        return Err(LoopProofError::InvalidElf("unsupported ELF endianness (expected little-endian)"));
    }

    let section_table_offset =
        read_u64(elf_data, 0x28).ok_or(LoopProofError::InvalidElf("missing e_shoff"))? as usize;
    let section_entry_size =
        read_u16(elf_data, 0x3A).ok_or(LoopProofError::InvalidElf("missing e_shentsize"))?
            as usize;
    let section_count =
        read_u16(elf_data, 0x3C).ok_or(LoopProofError::InvalidElf("missing e_shnum"))?
            as usize;
    let shstr_index =
        read_u16(elf_data, 0x3E).ok_or(LoopProofError::InvalidElf("missing e_shstrndx"))?
            as usize;

    if section_count == 0 {
        return Err(LoopProofError::InvalidElf("ELF has no section headers"));
    }

    if section_entry_size < 64 {
        return Err(LoopProofError::InvalidElf("section header entry too small"));
    }

    if shstr_index >= section_count {
        return Err(LoopProofError::InvalidElf("e_shstrndx out of range"));
    }

    let section_table_len = section_entry_size
        .checked_mul(section_count)
        .ok_or(LoopProofError::InvalidElf("section table size overflow"))?;
    let section_table_end = section_table_offset
        .checked_add(section_table_len)
        .ok_or(LoopProofError::InvalidElf("section table end overflow"))?;
    if section_table_end > elf_data.len() {
        return Err(LoopProofError::InvalidElf("section table outside ELF bounds"));
    }

    let shstr_header = read_section_header(
        elf_data,
        section_table_offset,
        section_entry_size,
        shstr_index,
    )
    .ok_or(LoopProofError::InvalidElf("failed to parse shstrtab header"))?;

    let shstr_start = shstr_header.data_offset as usize;
    let shstr_size = shstr_header.data_size as usize;
    let shstr_end = shstr_start
        .checked_add(shstr_size)
        .ok_or(LoopProofError::InvalidElf("shstrtab end overflow"))?;
    if shstr_end > elf_data.len() {
        return Err(LoopProofError::InvalidElf("shstrtab outside ELF bounds"));
    }
    let shstr = &elf_data[shstr_start..shstr_end];

    for index in 0..section_count {
        let section_header = read_section_header(
            elf_data,
            section_table_offset,
            section_entry_size,
            index,
        )
        .ok_or(LoopProofError::InvalidElf("failed to parse section header"))?;

        let name_offset = section_header.name_offset as usize;
        if name_offset >= shstr.len() {
            continue;
        }

        let name_tail = &shstr[name_offset..];
        let name_len = name_tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(LoopProofError::InvalidElf("unterminated section name"))?;
        let name = str::from_utf8(&name_tail[..name_len])
            .map_err(|_| LoopProofError::InvalidElf("section name is not UTF-8"))?;

        if name != LOOP_PROOF_SECTION_NAME {
            continue;
        }

        let section_start = section_header.data_offset as usize;
        let section_size = section_header.data_size as usize;
        let section_end = section_start
            .checked_add(section_size)
            .ok_or(LoopProofError::InvalidElf("loop proof section end overflow"))?;
        if section_end > elf_data.len() {
            return Err(LoopProofError::InvalidElf(
                "loop proof section outside ELF bounds",
            ));
        }

        return Ok(&elf_data[section_start..section_end]);
    }

    Err(LoopProofError::MissingSection)
}

pub fn verify_loop_proof_metadata(elf_data: &[u8]) -> Result<LoopProofMetadata, LoopProofError> {
    let section = find_loop_proof_section(elf_data)?;
    parse_loop_proof_section(section)
}

fn parse_loop_proof_section(section_data: &[u8]) -> Result<LoopProofMetadata, LoopProofError> {
    if section_data.len() < LOOP_PROOF_SECTION_MIN_SIZE {
        return Err(LoopProofError::InvalidSize(section_data.len()));
    }

    let magic = [
        section_data[0],
        section_data[1],
        section_data[2],
        section_data[3],
    ];
    if magic != LOOP_PROOF_MAGIC {
        return Err(LoopProofError::InvalidMagic(magic));
    }

    let version = u32::from_le_bytes([
        section_data[4],
        section_data[5],
        section_data[6],
        section_data[7],
    ]);
    if version != LOOP_PROOF_VERSION {
        return Err(LoopProofError::UnsupportedVersion(version));
    }

    let policy_flags = u32::from_le_bytes([
        section_data[8],
        section_data[9],
        section_data[10],
        section_data[11],
    ]);

    Ok(LoopProofMetadata {
        version,
        policy_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn align_up(value: usize, align: usize) -> usize {
        (value + (align - 1)) & !(align - 1)
    }

    fn build_test_elf(loop_proof_section: Option<&[u8]>) -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 64;
        const SECTION_HEADER_SIZE: usize = 64;

        let has_loop_proof = loop_proof_section.is_some();
        let loop_name = if has_loop_proof {
            LOOP_PROOF_SECTION_NAME
        } else {
            ".dummy"
        };

        let mut shstrtab = Vec::new();
        shstrtab.push(0);
        let shstrtab_name_offset = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab");
        shstrtab.push(0);
        let loop_name_offset = shstrtab.len() as u32;
        shstrtab.extend_from_slice(loop_name.as_bytes());
        shstrtab.push(0);

        let payload = loop_proof_section.unwrap_or(b"dummy");

        let mut cursor = ELF_HEADER_SIZE;
        let payload_offset = align_up(cursor, 8);
        cursor = payload_offset + payload.len();
        let shstrtab_offset = align_up(cursor, 8);
        cursor = shstrtab_offset + shstrtab.len();
        let section_table_offset = align_up(cursor, 8);

        let section_count = 3usize;
        let total_size = section_table_offset + section_count * SECTION_HEADER_SIZE;
        let mut elf = vec![0u8; total_size];

        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // ELF64
        elf[5] = 1; // little-endian
        elf[6] = 1; // ELF version
        write_u16(&mut elf, 0x10, 1); // ET_REL
        write_u16(&mut elf, 0x12, 0x3E); // x86_64
        write_u32(&mut elf, 0x14, 1);
        write_u16(&mut elf, 0x34, ELF_HEADER_SIZE as u16);
        write_u64(&mut elf, 0x28, section_table_offset as u64);
        write_u16(&mut elf, 0x3A, SECTION_HEADER_SIZE as u16);
        write_u16(&mut elf, 0x3C, section_count as u16);
        write_u16(&mut elf, 0x3E, 1); // shstrtab index

        elf[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
        elf[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(&shstrtab);

        // Section #1: .shstrtab
        let sh1 = section_table_offset + SECTION_HEADER_SIZE;
        write_u32(&mut elf, sh1, shstrtab_name_offset);
        write_u32(&mut elf, sh1 + 0x04, 3); // SHT_STRTAB
        write_u64(&mut elf, sh1 + 0x18, shstrtab_offset as u64);
        write_u64(&mut elf, sh1 + 0x20, shstrtab.len() as u64);

        // Section #2: loop proof or dummy payload
        let sh2 = section_table_offset + 2 * SECTION_HEADER_SIZE;
        write_u32(&mut elf, sh2, loop_name_offset);
        write_u32(&mut elf, sh2 + 0x04, 1); // SHT_PROGBITS
        write_u64(&mut elf, sh2 + 0x18, payload_offset as u64);
        write_u64(&mut elf, sh2 + 0x20, payload.len() as u64);

        elf
    }

    #[test_case]
    fn verify_loop_proof_metadata_accepts_valid_section() {
        let valid_section = [b'R', b'L', b'O', b'P', 1, 0, 0, 0, 7, 0, 0, 0];
        let elf = build_test_elf(Some(&valid_section));

        let meta = verify_loop_proof_metadata(&elf).expect("valid section");
        assert_eq!(meta.version, 1);
        assert_eq!(meta.policy_flags, 7);
    }

    #[test_case]
    fn verify_loop_proof_metadata_rejects_missing_section() {
        let elf = build_test_elf(None);
        let err = verify_loop_proof_metadata(&elf).expect_err("missing section must fail");
        assert_eq!(err, LoopProofError::MissingSection);
    }

    #[test_case]
    fn verify_loop_proof_metadata_rejects_invalid_magic() {
        let bad_magic = [b'X', b'L', b'O', b'P', 1, 0, 0, 0, 0, 0, 0, 0];
        let elf = build_test_elf(Some(&bad_magic));

        let err = verify_loop_proof_metadata(&elf).expect_err("invalid magic must fail");
        assert!(matches!(err, LoopProofError::InvalidMagic(_)));
    }

    #[test_case]
    fn verify_loop_proof_metadata_rejects_unsupported_version() {
        let bad_version = [b'R', b'L', b'O', b'P', 2, 0, 0, 0, 0, 0, 0, 0];
        let elf = build_test_elf(Some(&bad_version));

        let err = verify_loop_proof_metadata(&elf).expect_err("unsupported version must fail");
        assert_eq!(err, LoopProofError::UnsupportedVersion(2));
    }

    #[test_case]
    fn verify_loop_proof_metadata_rejects_short_section() {
        let short = [b'R', b'L', b'O'];
        let elf = build_test_elf(Some(&short));

        let err = verify_loop_proof_metadata(&elf).expect_err("short section must fail");
        assert_eq!(err, LoopProofError::InvalidSize(short.len()));
    }
}
