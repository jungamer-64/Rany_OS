// ============================================================================
// src/loader/sha384.rs - SHA-384 Hash Implementation
// Wave8 Phase B: TLS 1.2完全対応
// ============================================================================
//!
//! SHA-384ハッシュ計算（sha2クレートのラッパー）
//!
//! ## 参照
//! - FIPS 180-4: Secure Hash Standard (SHS)
//! - RFC 6234: US Secure Hash Algorithms
//!
//! ## 注意
//! SHA-384はSHA-512の切り詰め版であり、ブロックサイズは128バイト。
//! HMAC-SHA384計算時にはipad/opadも128バイトで処理する必要がある。
//!
//! ## 実装
//! 監査済みの `sha2` クレートを使用し、no_std環境で動作します。

use sha2::{Digest, Sha384 as Sha384Impl};

/// SHA-384ハッシュを計算
///
/// # Arguments
/// * `data` - ハッシュ対象のデータ
///
/// # Returns
/// 48バイトのSHA-384ハッシュ値
pub fn compute(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384Impl::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 48];
    output.copy_from_slice(&result);
    output
}

/// SHA-384 hasher構造体
///
/// ストリーミングハッシュ計算用のラッパー
pub struct Sha384 {
    inner: Sha384Impl,
}

impl Sha384 {
    /// 新しいSHA-384 hasherを作成
    pub fn new() -> Self {
        Self {
            inner: Sha384Impl::new(),
        }
    }

    /// データを追加
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// ハッシュを確定して出力
    pub fn finalize(self) -> [u8; 48] {
        let result = self.inner.finalize();
        let mut output = [0u8; 48];
        output.copy_from_slice(&result);
        output
    }

    /// ハッシュをリセット
    pub fn reset(&mut self) {
        self.inner = Sha384Impl::new();
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}
