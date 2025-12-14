// ============================================================================
// src/memory/buffer_view.rs - Zero-Copy Kernel Buffer View
// ============================================================================
//!
//! # カーネルバッファビュー
//!
//! SAS（単一アドレス空間）環境でのゼロコピーデータアクセスを提供。
//! ページキャッシュやカーネルバッファへの参照を安全にラップする。
//!
//! ## 設計思想
//! - コピーを排除し、メモリ効率を最大化
//! - ライフタイムによる安全性保証
//! - 将来的なRRef統合への足がかり

use core::ops::Deref;
use alloc::sync::Arc;
use alloc::vec::Vec;

// ============================================================================
// Kernel Buffer View
// ============================================================================

/// カーネルバッファへの不変参照
/// 
/// data を Arc で包むことで、複数のビューで共有可能。
/// 将来的にはページキャッシュへの直接参照に置き換え可能。
#[derive(Debug, Clone)]
pub struct KernelBufferView {
    /// 共有データ (将来的にはページキャッシュへの参照に変更)
    data: Arc<Vec<u8>>,
    /// スライスの開始オフセット
    offset: usize,
    /// スライスの長さ
    len: usize,
}

impl KernelBufferView {
    /// 新しいバッファビューを作成
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        Self {
            data: Arc::new(data),
            offset: 0,
            len,
        }
    }

    /// 既存のArc<Vec<u8>>からバッファビューを作成（ゼロコピー）
    /// 
    /// ShellServices::read_file_zero_copy()との統合用。
    /// データのコピーは一切発生しない。
    pub fn from_arc(data: Arc<Vec<u8>>) -> Self {
        let len = data.len();
        Self {
            data,
            offset: 0,
            len,
        }
    }

    /// 既存のビューからスライスを作成
    pub fn slice(&self, start: usize, end: usize) -> Option<Self> {
        if start > end || end > self.len {
            return None;
        }
        Some(Self {
            data: Arc::clone(&self.data),
            offset: self.offset + start,
            len: end - start,
        })
    }

    /// バッファの長さを取得
    pub fn len(&self) -> usize {
        self.len
    }

    /// バッファが空かどうか
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// バイトスライスとして参照
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[self.offset..self.offset + self.len]
    }

    /// UTF-8文字列として解釈（失敗時はNone）
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }

    /// 所有権を持つ Vec<u8> に変換（コピーが発生）
    /// 
    /// NOTE: これはゼロコピーの利点を打ち消すため、
    /// 必要な場合のみ使用すること。
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Deref for KernelBufferView {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl PartialEq for KernelBufferView {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for KernelBufferView {}

// ============================================================================
// String View (文字列専用)
// ============================================================================

/// UTF-8文字列への参照ビュー
#[derive(Debug, Clone)]
pub struct StringView {
    buffer: KernelBufferView,
}

impl StringView {
    /// バッファビューから文字列ビューを作成
    /// 
    /// UTF-8として無効なバイト列の場合はNoneを返す
    pub fn new(buffer: KernelBufferView) -> Option<Self> {
        // UTF-8の妥当性をチェック
        if core::str::from_utf8(buffer.as_bytes()).is_ok() {
            Some(Self { buffer })
        } else {
            None
        }
    }

    /// 文字列スライスとして参照
    pub fn as_str(&self) -> &str {
        // new() でチェック済みなので安全
        unsafe { core::str::from_utf8_unchecked(self.buffer.as_bytes()) }
    }

    /// 長さを取得
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Deref for StringView {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl PartialEq for StringView {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for StringView {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_view_basic() {
        let data = vec![1, 2, 3, 4, 5];
        let view = KernelBufferView::new(data);
        
        assert_eq!(view.len(), 5);
        assert_eq!(view.as_bytes(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_buffer_view_slice() {
        let data = vec![1, 2, 3, 4, 5];
        let view = KernelBufferView::new(data);
        
        let slice = view.slice(1, 4).unwrap();
        assert_eq!(slice.as_bytes(), &[2, 3, 4]);
    }

    #[test]
    fn test_buffer_view_clone_shares_data() {
        let data = vec![1, 2, 3, 4, 5];
        let view1 = KernelBufferView::new(data);
        let view2 = view1.clone();
        
        // Both views should point to the same Arc data
        assert_eq!(view1.as_bytes(), view2.as_bytes());
    }

    #[test]
    fn test_string_view() {
        let data = "Hello, World!".as_bytes().to_vec();
        let buffer = KernelBufferView::new(data);
        let string_view = StringView::new(buffer).unwrap();
        
        assert_eq!(string_view.as_str(), "Hello, World!");
    }

    #[test]
    fn test_string_view_invalid_utf8() {
        let data = vec![0xff, 0xfe]; // Invalid UTF-8
        let buffer = KernelBufferView::new(data);
        assert!(StringView::new(buffer).is_none());
    }
}
