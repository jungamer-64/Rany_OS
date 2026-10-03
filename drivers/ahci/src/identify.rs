//! ATA IDENTIFY データ構造体
//!
//! IDENTIFYコマンドの結果をパースして情報を取得

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Geometry accepted by the driver's 48-bit, 512-byte ATA data commands.
/// Strings and feature observations do not grant this validated geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtaBlockGeometry {
    sectors: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifyGeometryError {
    Truncated,
    NoLba48,
    Empty,
    AddressRange,
    UnsupportedSectorSize,
}

impl AtaBlockGeometry {
    /// Parses little-endian IDENTIFY words without allocating diagnostic strings.
    ///
    /// # Errors
    /// Rejects truncated data, absent 48-bit addressing, an empty/out-of-range
    /// extent, and logical sector sizes unsupported by the data command encoder.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentifyGeometryError> {
        if bytes.len() < 512 {
            return Err(IdentifyGeometryError::Truncated);
        }
        let word = |index: usize| u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
        if word(83) & (1 << 10) == 0 {
            return Err(IdentifyGeometryError::NoLba48);
        }
        let sectors = u64::from(word(100))
            | (u64::from(word(101)) << 16)
            | (u64::from(word(102)) << 32)
            | (u64::from(word(103)) << 48);
        if sectors == 0 {
            return Err(IdentifyGeometryError::Empty);
        }
        if sectors > 1 << 48 {
            return Err(IdentifyGeometryError::AddressRange);
        }
        let sector_words = if word(106) & 0xc000 == 0x4000 && word(106) & (1 << 12) != 0 {
            u32::from(word(117)) | (u32::from(word(118)) << 16)
        } else {
            256
        };
        if sector_words != 256 {
            return Err(IdentifyGeometryError::UnsupportedSectorSize);
        }
        Ok(Self { sectors })
    }

    pub const fn sector_count(self) -> u64 {
        self.sectors
    }
    pub const fn sector_bytes(self) -> u32 {
        512
    }
}

#[cfg(test)]
mod geometry_tests {
    use super::*;

    #[test]
    fn geometry_uses_full_lba48_capacity_and_valid_logical_sector_words() {
        let mut bytes = [0u8; 512];
        bytes[166..168].copy_from_slice(&0x4400u16.to_le_bytes());
        bytes[200..208].copy_from_slice(&0x0000_0001_2345_6789u64.to_le_bytes());
        let geometry = AtaBlockGeometry::from_bytes(&bytes).unwrap();
        assert_eq!(geometry.sector_count(), 0x0000_0001_2345_6789);
        assert_eq!(geometry.sector_bytes(), 512);
        bytes[212..214].copy_from_slice(&0x5000u16.to_le_bytes());
        bytes[234..238].copy_from_slice(&2048u32.to_le_bytes());
        assert_eq!(
            AtaBlockGeometry::from_bytes(&bytes),
            Err(IdentifyGeometryError::UnsupportedSectorSize)
        );
        bytes[212..214].copy_from_slice(&0x1000u16.to_le_bytes());
        assert!(AtaBlockGeometry::from_bytes(&bytes).is_ok());
        bytes[200..208].fill(0);
        assert_eq!(
            AtaBlockGeometry::from_bytes(&bytes),
            Err(IdentifyGeometryError::Empty)
        );
        assert_eq!(
            AtaBlockGeometry::from_bytes(&bytes[..511]),
            Err(IdentifyGeometryError::Truncated)
        );
    }
}

/// ATA IDENTIFY データ
#[derive(Debug, Clone)]
pub struct IdentifyData {
    /// モデル名
    pub model: String,
    /// シリアル番号
    pub serial: String,
    /// ファームウェアリビジョン
    pub firmware: String,
    /// 総セクタ数（LBA48）
    pub total_sectors: u64,
    /// セクタサイズ（バイト）
    pub sector_size: u32,
    /// 48-bit LBA対応
    pub lba48_supported: bool,
    /// NCQ対応
    pub ncq_supported: bool,
    /// NCQキュー深度
    pub ncq_queue_depth: u8,
}

impl IdentifyData {
    /// ワード配列からパース
    pub fn from_words(words: &[u16; 256]) -> Self {
        // モデル名（ワード27-46）
        let model = Self::parse_string(&words[27..47]);
        // シリアル番号（ワード10-19）
        let serial = Self::parse_string(&words[10..20]);
        // ファームウェア（ワード23-26）
        let firmware = Self::parse_string(&words[23..27]);

        // 総セクタ数
        let total_sectors = if (words[83] & (1 << 10)) != 0 {
            // LBA48対応
            (words[100] as u64)
                | ((words[101] as u64) << 16)
                | ((words[102] as u64) << 32)
                | ((words[103] as u64) << 48)
        } else {
            // LBA28
            (words[60] as u64) | ((words[61] as u64) << 16)
        };

        // セクタサイズ
        let sector_size = if (words[106] & (1 << 12)) != 0 {
            // 論理セクタサイズが設定されている
            ((words[117] as u32) | ((words[118] as u32) << 16)) * 2
        } else {
            512
        };

        let lba48_supported = (words[83] & (1 << 10)) != 0;
        let ncq_supported = (words[76] & (1 << 8)) != 0;
        let ncq_queue_depth = if ncq_supported {
            (words[75] & 0x1F) as u8 + 1
        } else {
            0
        };

        Self {
            model,
            serial,
            firmware,
            total_sectors,
            sector_size,
            lba48_supported,
            ncq_supported,
            ncq_queue_depth,
        }
    }

    /// ATA文字列をパース（バイトスワップ）
    fn parse_string(words: &[u16]) -> String {
        let mut bytes = Vec::with_capacity(words.len() * 2);
        for &word in words {
            bytes.push((word >> 8) as u8);
            bytes.push((word & 0xFF) as u8);
        }

        // 末尾のスペースを削除
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while bytes.last() == Some(&0x20) || bytes.last() == Some(&0x00) {
            bytes.pop();
        }

        String::from_utf8_lossy(&bytes).to_string()
    }

    /// 容量を取得（バイト）
    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors * self.sector_size as u64
    }

    /// 容量を取得（GB）
    pub fn capacity_gb(&self) -> f64 {
        self.capacity_bytes() as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}
