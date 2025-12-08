//! ATA IDENTIFY データ構造体
//!
//! IDENTIFYコマンドの結果をパースして情報を取得

use alloc::string::{String, ToString};
use alloc::vec::Vec;

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
