// ============================================================================
// kernel/src/fs/page.rs - Page-Based File Content Management
// ============================================================================
//!
//! # ページベースファイルコンテンツ管理
//!
//! ExoRustのZero-Copy/CoW設計に準拠したページ管理システム。
//! ファイル内容を4KiBページ単位で管理し、以下を実現:
//!
//! - **スパースファイル**: 未割り当てページはゼロ埋め扱い
//! - **Copy-on-Write**: Arc共有によりスナップショットが O(1)
//! - **メモリ効率**: 必要なページだけ割り当て
//!
//! ## Example
//! ```ignore
//! let mut content = PagedContent::new();
//! content.write(0, b"Hello");  // ページ0を割り当て
//! let snapshot = content.clone();  // CoWスナップショット
//! content.write(0, b"World");  // ページ0を複製して書き込み
//! ```

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// ページサイズ (4 KiB)
pub const PAGE_SIZE: usize = 4096;

/// ページシフト量 (log2(PAGE_SIZE))
pub const PAGE_SHIFT: usize = 12;

/// ページマスク
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

// ============================================================================
// Page Type
// ============================================================================

/// 固定サイズのページデータ
pub type Page = [u8; PAGE_SIZE];

/// 新しいゼロ初期化ページを作成
#[inline]
pub fn new_zero_page() -> Arc<Page> {
    Arc::new([0u8; PAGE_SIZE])
}

// ============================================================================
// PagedContent - CoW対応ページコンテンツ
// ============================================================================

/// ページベースのファイルコンテンツ（Copy-on-Write対応）
///
/// ファイル内容を`BTreeMap<u64, Arc<Page>>`で管理し、
/// スパースファイルとCoWを効率的にサポート。
#[derive(Clone)]
pub struct PagedContent {
    /// ページインデックス → ページデータ
    /// 存在しないインデックスはスパース（ゼロ）として扱う
    pages: BTreeMap<u64, Arc<Page>>,
}

impl PagedContent {
    /// 新しい空のPagedContentを作成
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
        }
    }

    /// ページ数を取得
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// 実際に割り当てられているバイト数
    pub fn allocated_bytes(&self) -> usize {
        self.pages.len() * PAGE_SIZE
    }

    /// 指定オフセットからデータを読み取り
    ///
    /// スパース領域はゼロで埋められる
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let mut bytes_read = 0;
        let mut current_offset = offset;

        while bytes_read < buf.len() {
            let page_idx = current_offset >> PAGE_SHIFT;
            let offset_in_page = (current_offset as usize) & PAGE_MASK;
            let remaining_in_page = PAGE_SIZE - offset_in_page;
            let to_read = remaining_in_page.min(buf.len() - bytes_read);

            match self.pages.get(&page_idx) {
                Some(page) => {
                    buf[bytes_read..bytes_read + to_read]
                        .copy_from_slice(&page[offset_in_page..offset_in_page + to_read]);
                }
                None => {
                    // スパース: ゼロ埋め
                    buf[bytes_read..bytes_read + to_read].fill(0);
                }
            }

            bytes_read += to_read;
            current_offset += to_read as u64;
        }

        bytes_read
    }

    /// 指定オフセットにデータを書き込み（CoW対応）
    ///
    /// 共有されているページは書き込み時にコピーされる
    pub fn write(&mut self, offset: u64, data: &[u8]) -> usize {
        let mut bytes_written = 0;
        let mut current_offset = offset;

        while bytes_written < data.len() {
            let page_idx = current_offset >> PAGE_SHIFT;
            let offset_in_page = (current_offset as usize) & PAGE_MASK;
            let remaining_in_page = PAGE_SIZE - offset_in_page;
            let to_write = remaining_in_page.min(data.len() - bytes_written);

            // CoW: ページを取得または作成、共有されていればコピー
            let page = self
                .pages
                .entry(page_idx)
                .or_insert_with(new_zero_page);

            // Arc::make_mut は参照カウント > 1 の場合のみコピーを作成
            let page_mut = Arc::make_mut(page);

            page_mut[offset_in_page..offset_in_page + to_write]
                .copy_from_slice(&data[bytes_written..bytes_written + to_write]);

            bytes_written += to_write;
            current_offset += to_write as u64;
        }

        bytes_written
    }

    /// 指定ページを取得（ゼロコピー読み取り用）
    pub fn get_page(&self, page_idx: u64) -> Option<Arc<Page>> {
        self.pages.get(&page_idx).cloned()
    }

    /// ファイルを指定サイズに切り詰め
    ///
    /// サイズを超えるページは削除される
    pub fn truncate(&mut self, size: u64) {
        if size == 0 {
            self.pages.clear();
            return;
        }

        let last_page_idx = (size - 1) >> PAGE_SHIFT;

        // 最終ページより後のページを削除
        self.pages.retain(|&idx, _| idx <= last_page_idx);

        // 最終ページ内の余分なバイトをゼロ埋め
        let offset_in_last_page = (size as usize) & PAGE_MASK;
        if offset_in_last_page > 0 {
            if let Some(page) = self.pages.get_mut(&last_page_idx) {
                let page_mut = Arc::make_mut(page);
                page_mut[offset_in_last_page..].fill(0);
            }
        }
    }

    /// 全データをVec<u8>としてコピー（互換性用）
    pub fn to_vec(&self, size: u64) -> Vec<u8> {
        let mut result = vec![0u8; size as usize];
        self.read(0, &mut result);
        result
    }
}

impl Default for PagedContent {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_constants() {
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(1 << PAGE_SHIFT, PAGE_SIZE);
    }

    #[test]
    fn test_paged_content_basic_write_read() {
        let mut content = PagedContent::new();

        content.write(0, b"Hello, World!");

        let mut buf = [0u8; 13];
        content.read(0, &mut buf);
        assert_eq!(&buf, b"Hello, World!");
    }

    #[test]
    fn test_paged_content_sparse() {
        let content = PagedContent::new();

        // 未割り当て領域はゼロ
        let mut buf = [0xFFu8; 10];
        content.read(0, &mut buf);
        assert_eq!(&buf, &[0u8; 10]);
    }

    #[test]
    fn test_paged_content_cross_page_write() {
        let mut content = PagedContent::new();

        // ページ境界を跨ぐ書き込み
        let offset = PAGE_SIZE as u64 - 5;
        let data = b"0123456789"; // 10 bytes across boundary
        content.write(offset, data);

        let mut buf = [0u8; 10];
        content.read(offset, &mut buf);
        assert_eq!(&buf, data);

        // 2ページ使用
        assert_eq!(content.page_count(), 2);
    }

    #[test]
    fn test_cow_clone() {
        let mut original = PagedContent::new();
        original.write(0, b"Original");

        // CoWクローン
        let snapshot = original.clone();

        // 元データを変更
        original.write(0, b"Modified");

        // スナップショットは影響を受けない
        let mut buf = [0u8; 8];
        snapshot.read(0, &mut buf);
        assert_eq!(&buf, b"Original");

        original.read(0, &mut buf);
        assert_eq!(&buf, b"Modified");
    }

    #[test]
    fn test_truncate() {
        let mut content = PagedContent::new();
        content.write(0, &[0xAA; PAGE_SIZE * 3]);

        assert_eq!(content.page_count(), 3);

        content.truncate(PAGE_SIZE as u64 + 100);
        assert_eq!(content.page_count(), 2);

        content.truncate(0);
        assert_eq!(content.page_count(), 0);
    }

    #[test]
    fn test_get_page_zero_copy() {
        let mut content = PagedContent::new();
        content.write(0, b"Test data");

        let page = content.get_page(0).unwrap();
        assert_eq!(&page[0..9], b"Test data");

        // ページが存在しない場合はNone
        assert!(content.get_page(100).is_none());
    }
}
