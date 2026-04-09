//! PKRU権限ビットマップ
//!
//! 設計書セクション 9.2.2.1 参照

use super::mpk_protection_key::ProtectionKeyClass;

/// PKRU権限ビットマップ
///
/// 各Protection Keyに対して2ビット: [Write Disable, Access Disable]
/// - Bit 0: Write Disable (WD) - 1で書き込み禁止
/// - Bit 1: Access Disable (AD) - 1で読み取りも禁止
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PkruValue(pub u32);

impl PkruValue {
    /// 全アクセス禁止
    pub const DENY_ALL: Self = Self(0xFFFFFFFF);

    /// 全アクセス許可
    pub const ALLOW_ALL: Self = Self(0x00000000);

    /// 指定されたキーへの読み取りを許可
    pub fn allow_read(mut self, key: ProtectionKeyClass) -> Self {
        let bit = (key as u32) * 2 + 1; // Access Disable bit
        self.0 &= !(1 << bit);
        self
    }

    /// 指定されたキーへの読み書きを許可
    pub fn allow_read_write(mut self, key: ProtectionKeyClass) -> Self {
        let bits = (key as u32) * 2;
        self.0 &= !(0b11 << bits); // Both AD and WD cleared
        self
    }

    /// 指定されたキーへの書き込みを禁止（読み取りは許可）
    pub fn deny_write(mut self, key: ProtectionKeyClass) -> Self {
        let wd_bit = (key as u32) * 2;
        let ad_bit = wd_bit + 1;
        self.0 |= 1 << wd_bit; // WD = 1
        self.0 &= !(1 << ad_bit); // AD = 0
        self
    }

    /// 指定されたキーへのすべてのアクセスを禁止
    pub fn deny_all(mut self, key: ProtectionKeyClass) -> Self {
        let bits = (key as u32) * 2;
        self.0 |= 0b11 << bits; // Both AD and WD set
        self
    }
}
