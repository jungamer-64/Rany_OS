// ============================================================================
// src/loader/sha256.rs - SHA-256 Hash Implementation
// 設計書 3.3: コンパイラ署名とロード時検証
// ============================================================================
//!
//! SHA-256ハッシュ計算（sha2クレートのラッパー）
//!
//! ## 参照
//! - FIPS 180-4: Secure Hash Standard (SHS)
//! - RFC 6234: US Secure Hash Algorithms
//!
//! ## 実装
//! 監査済みの `sha2` クレートを使用し、no_std環境で動作します。

use sha2::{Digest, Sha256 as Sha256Impl};

/// SHA-256ハッシュを計算
///
/// # Arguments
/// * `data` - ハッシュ対象のデータ
///
/// # Returns
/// 32バイトのSHA-256ハッシュ値
///
/// # Example
/// ```ignore
/// let hash = sha256::compute(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn compute(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Impl::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// SHA-256 hasher構造体
///
/// ストリーミングハッシュ計算用のラッパー
pub struct Sha256 {
    inner: Sha256Impl,
}

impl Sha256 {
    /// 新しいSHA-256 hasherを作成
    pub fn new() -> Self {
        Self {
            inner: Sha256Impl::new(),
        }
    }

    /// データを追加
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// ハッシュを確定して出力
    pub fn finalize(self) -> [u8; 32] {
        let result = self.inner.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// ハッシュをリセット
    pub fn reset(&mut self) {
        self.inner = Sha256Impl::new();
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

