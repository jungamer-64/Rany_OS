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

use sha2::{Sha256 as Sha256Impl, Digest};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        // SHA-256 of empty string
        let hash = compute(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256 of "abc"
        let hash = compute(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_streaming() {
        let mut hasher = Sha256::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let streaming_hash = hasher.finalize();
        
        let direct_hash = compute(b"hello world");
        assert_eq!(streaming_hash, direct_hash);
    }
}
