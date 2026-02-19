// ============================================================================
// src/loader/sha512.rs - SHA-512 Hash Implementation
// ============================================================================
//!
//! SHA-512ハッシュ計算（sha2クレートのラッパー）
//!
//! ## 参照
//! - FIPS 180-4: Secure Hash Standard (SHS)
//! - RFC 6234: US Secure Hash Algorithms
//!
//! ## 注意
//! SHA-512のブロックサイズは128バイト（SHA-256の64バイトとは異なる）。
//! HMAC-SHA512計算時にはipad/opadも128バイトで処理する必要がある。
//!
//! ## 実装
//! 監査済みの `sha2` クレートを使用し、no_std環境で動作します。

use sha2::{Digest, Sha512 as Sha512Impl};

/// SHA-512ハッシュを計算
///
/// # Arguments
/// * `data` - ハッシュ対象のデータ
///
/// # Returns
/// 64バイトのSHA-512ハッシュ値
pub fn compute(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512Impl::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// SHA-512 hasher構造体
///
/// ストリーミングハッシュ計算用のラッパー
pub struct Sha512 {
    inner: Sha512Impl,
}

impl Sha512 {
    /// 新しいSHA-512 hasherを作成
    pub fn new() -> Self {
        Self {
            inner: Sha512Impl::new(),
        }
    }

    /// データを追加
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// ハッシュを確定して出力
    pub fn finalize(self) -> [u8; 64] {
        let result = self.inner.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        output
    }

    /// ハッシュをリセット
    pub fn reset(&mut self) {
        self.inner = Sha512Impl::new();
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}
