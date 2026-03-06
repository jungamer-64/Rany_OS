// ============================================================================
// drivers/mlx5/src/structs/health.rs - Health Buffer Layout
// ============================================================================

use crate::structs::get_bits_u32;

/// Health Buffer Layout (ConnectX Family)
///
/// マップされた初期化セグメントのオフセット 0x0200 に配置される。
pub struct HealthLayout<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> HealthLayout<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// アサート変数 (5 dwords)
    pub fn assert_var(&self, i: usize) -> u32 {
        if i >= 5 {
            return 0;
        }
        get_bits_u32(self.data, i * 32, 32)
    }

    /// FW バージョン
    pub fn fw_ver(&self) -> u32 {
        get_bits_u32(self.data, 10 * 32, 32)
    }

    /// HW ID
    pub fn hw_id(&self) -> u32 {
        get_bits_u32(self.data, 11 * 32, 32)
    }

    /// 症候群 (Syndrome)
    /// 0x00: OK
    /// 0x01: HW 致命的エラー
    /// 0x08: SW 致命的エラー
    /// 0x09: FW アサート
    pub fn syndrome(&self) -> u8 {
        get_bits_u32(self.data, 13 * 32 + 24, 8) as u8
    }

    /// 拡張症候群 (Extended Syndrome)
    pub fn ext_syndrome(&self) -> u16 {
        get_bits_u32(self.data, 13 * 32 + 0, 16) as u16
    }

    /// 全リセット要求フラグ
    pub fn full_reset_required(&self) -> bool {
        (get_bits_u32(self.data, 13 * 32 + 16, 8) & 0x80) != 0
    }
}
