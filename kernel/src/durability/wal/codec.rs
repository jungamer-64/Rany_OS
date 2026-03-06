use alloc::vec::Vec;

use super::{WalOperation, WalRecord, WalRecordKind};

pub const SUPERBLOCK_SIZE: usize = 4096;

const SUPER_MAGIC: u32 = 0x594C_4157; // "WALY"
const SUPER_VERSION: u16 = 1;

const RECORD_MAGIC: u32 = 0x524C_4157; // "WALR"
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_SIZE: usize = 40;

const KIND_BEGIN: u16 = 1;
const KIND_APPEND: u16 = 2;
const KIND_COMMIT: u16 = 3;

const OP_WRITE: u8 = 1;
const OP_TRIM: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalCodecError {
    InvalidSuperblock,
    InvalidRecord,
    InvalidPayload,
    ChecksumMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperblockState {
    pub ring_len: u64,
    pub write_offset: u64,
}

#[inline]
fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let chunk = bytes.get(off..end)?;
    Some(u16::from_le_bytes([chunk[0], chunk[1]]))
}

#[inline]
fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let chunk = bytes.get(off..end)?;
    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

#[inline]
fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let chunk = bytes.get(off..end)?;
    Some(u64::from_le_bytes([
        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
    ]))
}

#[inline]
fn write_u16_le(bytes: &mut [u8], off: usize, value: u16) {
    let out = value.to_le_bytes();
    bytes[off..off + 2].copy_from_slice(&out);
}

#[inline]
fn write_u32_le(bytes: &mut [u8], off: usize, value: u32) {
    let out = value.to_le_bytes();
    bytes[off..off + 4].copy_from_slice(&out);
}

#[inline]
fn write_u64_le(bytes: &mut [u8], off: usize, value: u64) {
    let out = value.to_le_bytes();
    bytes[off..off + 8].copy_from_slice(&out);
}

#[inline]
fn align_up_8(v: usize) -> usize {
    (v + 7) & !7
}

pub fn encode_superblock(state: &SuperblockState, out: &mut [u8; SUPERBLOCK_SIZE]) {
    out.fill(0);
    write_u32_le(out, 0, SUPER_MAGIC);
    write_u16_le(out, 4, SUPER_VERSION);
    write_u16_le(out, 6, 32);
    write_u64_le(out, 8, state.ring_len);
    write_u64_le(out, 16, state.write_offset);
    let csum = crc32(&out[..24]);
    write_u32_le(out, 24, csum);
}

pub fn decode_superblock(bytes: &[u8]) -> Result<SuperblockState, WalCodecError> {
    if bytes.len() < SUPERBLOCK_SIZE {
        return Err(WalCodecError::InvalidSuperblock);
    }
    let magic = read_u32_le(bytes, 0).ok_or(WalCodecError::InvalidSuperblock)?;
    if magic != SUPER_MAGIC {
        return Err(WalCodecError::InvalidSuperblock);
    }
    let version = read_u16_le(bytes, 4).ok_or(WalCodecError::InvalidSuperblock)?;
    if version != SUPER_VERSION {
        return Err(WalCodecError::InvalidSuperblock);
    }
    let ring_len = read_u64_le(bytes, 8).ok_or(WalCodecError::InvalidSuperblock)?;
    let write_offset = read_u64_le(bytes, 16).ok_or(WalCodecError::InvalidSuperblock)?;
    let stored_crc = read_u32_le(bytes, 24).ok_or(WalCodecError::InvalidSuperblock)?;
    let actual_crc = crc32(&bytes[..24]);
    if stored_crc != actual_crc {
        return Err(WalCodecError::ChecksumMismatch);
    }
    if write_offset > ring_len {
        return Err(WalCodecError::InvalidSuperblock);
    }
    Ok(SuperblockState {
        ring_len,
        write_offset,
    })
}

pub fn encode_record(rec: &WalRecord, out: &mut Vec<u8>) -> Result<(), WalCodecError> {
    let mut payload = Vec::new();
    let kind = match &rec.kind {
        WalRecordKind::Begin => KIND_BEGIN,
        WalRecordKind::Commit => KIND_COMMIT,
        WalRecordKind::Append(op) => {
            match op {
                WalOperation::Write { offset, data } => {
                    payload.push(OP_WRITE);
                    payload.extend_from_slice(&offset.to_le_bytes());
                    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    payload.extend_from_slice(data);
                }
                WalOperation::Trim { new_len } => {
                    payload.push(OP_TRIM);
                    payload.extend_from_slice(&new_len.to_le_bytes());
                }
            }
            KIND_APPEND
        }
    };

    let payload_len = payload.len() as u32;
    let total = align_up_8(RECORD_HEADER_SIZE + payload.len());
    out.clear();
    out.resize(total, 0);

    write_u32_le(out, 0, RECORD_MAGIC);
    write_u16_le(out, 4, RECORD_VERSION);
    write_u16_le(out, 6, kind);
    write_u32_le(out, 8, payload_len);
    write_u64_le(out, 16, rec.tx_id);
    write_u64_le(out, 24, rec.seq);
    write_u32_le(out, 32, crc32(&payload));
    out[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + payload.len()].copy_from_slice(&payload);
    Ok(())
}

pub fn decode_record(bytes: &[u8]) -> Result<(WalRecord, usize), WalCodecError> {
    if bytes.len() < RECORD_HEADER_SIZE {
        return Err(WalCodecError::InvalidRecord);
    }
    let magic = read_u32_le(bytes, 0).ok_or(WalCodecError::InvalidRecord)?;
    if magic != RECORD_MAGIC {
        return Err(WalCodecError::InvalidRecord);
    }
    let version = read_u16_le(bytes, 4).ok_or(WalCodecError::InvalidRecord)?;
    if version != RECORD_VERSION {
        return Err(WalCodecError::InvalidRecord);
    }
    let kind = read_u16_le(bytes, 6).ok_or(WalCodecError::InvalidRecord)?;
    let payload_len = read_u32_le(bytes, 8).ok_or(WalCodecError::InvalidRecord)? as usize;
    let tx_id = read_u64_le(bytes, 16).ok_or(WalCodecError::InvalidRecord)?;
    let seq = read_u64_le(bytes, 24).ok_or(WalCodecError::InvalidRecord)?;
    let crc = read_u32_le(bytes, 32).ok_or(WalCodecError::InvalidRecord)?;

    let total = align_up_8(RECORD_HEADER_SIZE + payload_len);
    if total > bytes.len() {
        return Err(WalCodecError::InvalidRecord);
    }
    let payload = &bytes[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + payload_len];
    if crc32(payload) != crc {
        return Err(WalCodecError::ChecksumMismatch);
    }

    let rec_kind = match kind {
        KIND_BEGIN => WalRecordKind::Begin,
        KIND_COMMIT => WalRecordKind::Commit,
        KIND_APPEND => {
            if payload.is_empty() {
                return Err(WalCodecError::InvalidPayload);
            }
            match payload[0] {
                OP_WRITE => {
                    if payload.len() < 1 + 8 + 4 {
                        return Err(WalCodecError::InvalidPayload);
                    }
                    let offset = read_u64_le(payload, 1).ok_or(WalCodecError::InvalidPayload)?;
                    let data_len =
                        read_u32_le(payload, 9).ok_or(WalCodecError::InvalidPayload)? as usize;
                    if payload.len() != 13 + data_len {
                        return Err(WalCodecError::InvalidPayload);
                    }
                    let data = payload[13..].to_vec();
                    WalRecordKind::Append(WalOperation::Write { offset, data })
                }
                OP_TRIM => {
                    if payload.len() != 1 + 8 {
                        return Err(WalCodecError::InvalidPayload);
                    }
                    let new_len = read_u64_le(payload, 1).ok_or(WalCodecError::InvalidPayload)?;
                    WalRecordKind::Append(WalOperation::Trim { new_len })
                }
                _ => return Err(WalCodecError::InvalidPayload),
            }
        }
        _ => return Err(WalCodecError::InvalidRecord),
    };

    Ok((
        WalRecord {
            tx_id,
            seq,
            kind: rec_kind,
        },
        total,
    ))
}

/// Simple CRC32 (IEEE) implementation for WAL framing.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in bytes {
        crc ^= *b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg() & 0xEDB8_8320;
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}
