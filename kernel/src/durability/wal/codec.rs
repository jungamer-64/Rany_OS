use alloc::vec::Vec;

use super::{WalOperation, WalRecord, WalRecordKind};

pub const SUPERBLOCK_SIZE: usize = 4096;

const SUPER_MAGIC: u32 = 0x594C_4157; // "WALY"
const SUPER_VERSION: u16 = 2;

const RECORD_MAGIC: u32 = 0x524C_4157; // "WALR"
const RECORD_VERSION: u16 = 2;
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
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogBank {
    First,
    Second,
}

impl LogBank {
    pub const fn other(self) -> Self {
        match self {
            Self::First => Self::Second,
            Self::Second => Self::First,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootState {
    pub generation: u64,
    pub bank_len: u64,
    pub bank: LogBank,
    pub log_len: u64,
    pub next_tx: u64,
    pub next_seq: u64,
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

pub fn encode_root(state: &RootState, out: &mut [u8; SUPERBLOCK_SIZE]) {
    out.fill(0);
    write_u32_le(out, 0, SUPER_MAGIC);
    write_u16_le(out, 4, SUPER_VERSION);
    write_u16_le(out, 6, 64);
    write_u64_le(out, 8, state.generation);
    write_u64_le(out, 16, state.bank_len);
    write_u32_le(
        out,
        24,
        match state.bank {
            LogBank::First => 0,
            LogBank::Second => 1,
        },
    );
    write_u64_le(out, 32, state.log_len);
    write_u64_le(out, 40, state.next_tx);
    write_u64_le(out, 48, state.next_seq);
    let csum = crc32(&out[..56]);
    write_u32_le(out, 56, csum);
}

pub fn decode_root(bytes: &[u8]) -> Result<RootState, WalCodecError> {
    if bytes.len() < SUPERBLOCK_SIZE {
        return Err(WalCodecError::InvalidSuperblock);
    }
    let magic = read_u32_le(bytes, 0).ok_or(WalCodecError::InvalidSuperblock)?;
    if magic != SUPER_MAGIC {
        return Err(WalCodecError::InvalidSuperblock);
    }
    let version = read_u16_le(bytes, 4).ok_or(WalCodecError::InvalidSuperblock)?;
    if version != SUPER_VERSION || read_u16_le(bytes, 6) != Some(64) {
        return Err(WalCodecError::InvalidSuperblock);
    }
    let generation = read_u64_le(bytes, 8).ok_or(WalCodecError::InvalidSuperblock)?;
    let bank_len = read_u64_le(bytes, 16).ok_or(WalCodecError::InvalidSuperblock)?;
    let bank = match read_u32_le(bytes, 24) {
        Some(0) => LogBank::First,
        Some(1) => LogBank::Second,
        _ => return Err(WalCodecError::InvalidSuperblock),
    };
    let log_len = read_u64_le(bytes, 32).ok_or(WalCodecError::InvalidSuperblock)?;
    let next_tx = read_u64_le(bytes, 40).ok_or(WalCodecError::InvalidSuperblock)?;
    let next_seq = read_u64_le(bytes, 48).ok_or(WalCodecError::InvalidSuperblock)?;
    let stored_crc = read_u32_le(bytes, 56).ok_or(WalCodecError::InvalidSuperblock)?;
    let actual_crc = crc32(&bytes[..56]);
    if stored_crc != actual_crc {
        return Err(WalCodecError::ChecksumMismatch);
    }
    if generation == 0 || log_len > bank_len || next_tx == 0 || next_seq == 0 {
        return Err(WalCodecError::InvalidSuperblock);
    }
    Ok(RootState {
        generation,
        bank_len,
        bank,
        log_len,
        next_tx,
        next_seq,
    })
}

pub fn encode_record(rec: &WalRecord, out: &mut Vec<u8>) -> Result<(), WalCodecError> {
    let mut payload = Vec::new();
    let payload_bytes = match &rec.kind {
        WalRecordKind::Append(WalOperation::Write { data, .. }) => data.len().checked_add(13),
        WalRecordKind::Append(WalOperation::Trim { .. }) => Some(9),
        _ => Some(0),
    }
    .ok_or(WalCodecError::InvalidPayload)?;
    payload
        .try_reserve_exact(payload_bytes)
        .map_err(|_| WalCodecError::Allocation)?;
    let kind = match &rec.kind {
        WalRecordKind::Begin => KIND_BEGIN,
        WalRecordKind::Commit => KIND_COMMIT,
        WalRecordKind::Append(op) => {
            match op {
                WalOperation::Write { offset, data } => {
                    payload.push(OP_WRITE);
                    payload.extend_from_slice(&offset.to_le_bytes());
                    let len =
                        u32::try_from(data.len()).map_err(|_| WalCodecError::InvalidPayload)?;
                    payload.extend_from_slice(&len.to_le_bytes());
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

    let payload_len = u32::try_from(payload.len()).map_err(|_| WalCodecError::InvalidPayload)?;
    let unaligned = RECORD_HEADER_SIZE
        .checked_add(payload.len())
        .and_then(|n| n.checked_add(7))
        .ok_or(WalCodecError::InvalidPayload)?;
    let total = unaligned & !7;
    out.clear();
    out.try_reserve_exact(total)
        .map_err(|_| WalCodecError::Allocation)?;
    out.resize(total, 0);

    write_u32_le(out, 0, RECORD_MAGIC);
    write_u16_le(out, 4, RECORD_VERSION);
    write_u16_le(out, 6, kind);
    write_u32_le(out, 8, payload_len);
    write_u64_le(out, 16, rec.tx_id);
    write_u64_le(out, 24, rec.seq);
    write_u32_le(out, 32, crc32(&payload));
    let header_crc = crc32(&out[..36]);
    write_u32_le(out, 36, header_crc);
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
    let header_crc = read_u32_le(bytes, 36).ok_or(WalCodecError::InvalidRecord)?;
    if crc32(&bytes[..36]) != header_crc || tx_id == 0 || seq == 0 {
        return Err(WalCodecError::ChecksumMismatch);
    }

    let total = RECORD_HEADER_SIZE
        .checked_add(payload_len)
        .and_then(|n| n.checked_add(7))
        .ok_or(WalCodecError::InvalidRecord)?
        & !7;
    if total > bytes.len() {
        return Err(WalCodecError::InvalidRecord);
    }
    let payload = &bytes[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + payload_len];
    if crc32(payload) != crc {
        return Err(WalCodecError::ChecksumMismatch);
    }

    let rec_kind = match kind {
        KIND_BEGIN if payload.is_empty() => WalRecordKind::Begin,
        KIND_COMMIT if payload.is_empty() => WalRecordKind::Commit,
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
                    let mut data = Vec::new();
                    data.try_reserve_exact(data_len)
                        .map_err(|_| WalCodecError::Allocation)?;
                    data.extend_from_slice(&payload[13..]);
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
