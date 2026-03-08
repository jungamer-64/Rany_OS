// ============================================================================
// kernel/src/collections/maple_tree.rs
// ============================================================================
//! Maple Tree - Range-Based B-tree
//!
//! Linux カーネルの Maple Tree にインスパイアされた範囲ベースの B-tree。
//! 非重複範囲の管理に最適化（VMA 管理向け）。
//!
//! ## 特徴
//!
//! - **範囲最適化**: 非重複範囲の格納と検索に最適化
//! - **範囲結合**: 隣接する同値範囲を自動マージ
//! - **ギャップトラッキング**: 範囲間のギャップを追跡

#![allow(dead_code)]

use alloc::vec::Vec;
use core::cmp::max;

// ============================================================================
// Constants
// ============================================================================

const MAPLE_LEAF_SLOTS: usize = 16;
const MAPLE_NODE_SLOTS: usize = 10;

// ============================================================================
// Range Entry
// ============================================================================

#[derive(Clone)]
pub struct RangeEntry<T> {
    pub start: usize,
    pub end: usize,
    pub value: T,
}

impl<T> RangeEntry<T> {
    #[inline]
    fn new(start: usize, end: usize, value: T) -> Self {
        debug_assert!(start < end, "Invalid range");
        Self { start, end, value }
    }

    #[inline]
    fn contains(&self, index: usize) -> bool {
        index >= self.start && index < self.end
    }

    #[inline]
    fn overlaps(&self, start: usize, end: usize) -> bool {
        self.start < end && start < self.end
    }
}

// ============================================================================
// Maple Tree (Simple Vec-based implementation)
// ============================================================================

/// 範囲ベースのコレクション
pub struct MapleTree<T> {
    entries: Vec<RangeEntry<T>>,
}

impl<T: Clone + PartialEq> MapleTree<T> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 範囲 [start, end) に値を格納
    pub fn store_range(&mut self, start: usize, end: usize, value: T) {
        if start >= end {
            return;
        }

        // 重複を削除
        self.entries.retain(|e| !e.overlaps(start, end));

        // 挿入位置を見つける（ソート順維持）
        let pos = self
            .entries
            .iter()
            .position(|e| e.start >= start)
            .unwrap_or(self.entries.len());

        self.entries.insert(pos, RangeEntry::new(start, end, value));

        // 範囲結合
        self.coalesce();
    }

    /// 単一インデックスを検索
    pub fn load(&self, index: usize) -> Option<&T> {
        self.entries
            .iter()
            .find(|e| e.contains(index))
            .map(|e| &e.value)
    }

    /// 単一インデックスを可変で検索
    pub fn load_mut(&mut self, index: usize) -> Option<&mut T> {
        self.entries
            .iter_mut()
            .find(|e| e.contains(index))
            .map(|e| &mut e.value)
    }

    /// 範囲を削除
    pub fn erase_range(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        self.entries.retain(|e| !e.overlaps(start, end));
    }

    /// 隣接する同値範囲を結合
    fn coalesce(&mut self) {
        if self.entries.len() < 2 {
            return;
        }

        let mut i = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i + 1 < self.entries.len() {
            let merge = {
                let a = &self.entries[i];
                let b = &self.entries[i + 1];
                a.end == b.start && a.value == b.value
            };

            if merge {
                let new_end = self.entries[i + 1].end;
                self.entries[i].end = new_end;
                self.entries.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }

    /// ギャップを検索
    pub fn find_gap(&self, start: usize, min_size: usize) -> Option<(usize, usize)> {
        let mut current = start;

        for entry in &self.entries {
            if entry.start > current {
                let gap_size = entry.start - current;
                if gap_size >= min_size {
                    return Some((current, entry.start));
                }
            }
            current = max(current, entry.end);
        }

        Some((current, current + min_size))
    }

    /// 全エントリをイテレート
    pub fn iter(&self) -> impl Iterator<Item = &RangeEntry<T>> {
        self.entries.iter()
    }
}

impl<T: Clone + PartialEq> Default for MapleTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<T: Send> Send for MapleTree<T> {}
unsafe impl<T: Sync> Sync for MapleTree<T> {}

// ============================================================================
// QEMU smoke tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn maple_empty_smoke() -> bool {
        let mt: MapleTree<u32> = MapleTree::new();
        mt.is_empty() && mt.load(0).is_none()
    }

    pub fn maple_single_range_smoke() -> bool {
        let mut mt: MapleTree<u32> = MapleTree::new();
        mt.store_range(10, 20, 42);

        mt.len() == 1
            && mt.load(9).is_none()
            && mt.load(10) == Some(&42)
            && mt.load(19) == Some(&42)
            && mt.load(20).is_none()
    }

    pub fn maple_multiple_ranges_smoke() -> bool {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(200, 300, 2);
        mt.store_range(500, 600, 3);

        mt.len() == 3
            && mt.load(50) == Some(&1)
            && mt.load(150).is_none()
            && mt.load(250) == Some(&2)
    }

    pub fn maple_overlapping_store_smoke() -> bool {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(50, 150, 2);

        mt.len() == 1 && mt.load(75) == Some(&2)
    }

    pub fn maple_erase_smoke() -> bool {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(200, 300, 2);
        mt.erase_range(0, 100);

        mt.len() == 1 && mt.load(50).is_none() && mt.load(250) == Some(&2)
    }

    pub fn maple_find_gap_smoke() -> bool {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(200, 300, 2);

        match mt.find_gap(0, 50) {
            Some((start, end)) => start == 100 && end == 200,
            None => false,
        }
    }

    pub fn maple_range_coalescing_smoke() -> bool {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(100, 200, 1);

        mt.len() == 1 && mt.load(50) == Some(&1) && mt.load(150) == Some(&1)
    }

    pub fn maple_many_ranges_smoke() -> bool {
        let mut mt: MapleTree<u32> = MapleTree::new();

        for i in 0..50u32 {
            mt.store_range((i as usize) * 100, (i as usize) * 100 + 50, i);
        }

        if mt.len() != 50 {
            return false;
        }

        for i in 0..50u32 {
            if mt.load((i as usize) * 100 + 25) != Some(&i) {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_empty() {
        let mt: MapleTree<u32> = MapleTree::new();
        assert!(mt.is_empty());
        assert_eq!(mt.load(0), None);
    }

    #[test_case]
    fn test_single_range() {
        let mut mt: MapleTree<u32> = MapleTree::new();
        mt.store_range(10, 20, 42);

        assert_eq!(mt.len(), 1);
        assert_eq!(mt.load(9), None);
        assert_eq!(mt.load(10), Some(&42));
        assert_eq!(mt.load(19), Some(&42));
        assert_eq!(mt.load(20), None);
    }

    #[test_case]
    fn test_multiple_ranges() {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(200, 300, 2);
        mt.store_range(500, 600, 3);

        assert_eq!(mt.len(), 3);
        assert_eq!(mt.load(50), Some(&1));
        assert_eq!(mt.load(150), None);
        assert_eq!(mt.load(250), Some(&2));
    }

    #[test_case]
    fn test_overlapping_store() {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(50, 150, 2);

        assert_eq!(mt.len(), 1);
        assert_eq!(mt.load(75), Some(&2));
    }

    #[test_case]
    fn test_erase() {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(200, 300, 2);
        mt.erase_range(0, 100);

        assert_eq!(mt.len(), 1);
        assert_eq!(mt.load(50), None);
        assert_eq!(mt.load(250), Some(&2));
    }

    #[test_case]
    fn test_find_gap() {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(200, 300, 2);

        let gap = mt.find_gap(0, 50).unwrap();
        assert_eq!(gap, (100, 200));
    }

    #[test_case]
    fn test_range_coalescing() {
        let mut mt: MapleTree<u32> = MapleTree::new();

        mt.store_range(0, 100, 1);
        mt.store_range(100, 200, 1);

        // マージされて1つになる
        assert_eq!(mt.len(), 1);
        assert_eq!(mt.load(50), Some(&1));
        assert_eq!(mt.load(150), Some(&1));
    }

    #[test_case]
    fn test_many_ranges() {
        let mut mt: MapleTree<u32> = MapleTree::new();

        for i in 0..50 {
            mt.store_range(i * 100, i * 100 + 50, i as u32);
        }

        assert_eq!(mt.len(), 50);

        for i in 0..50 {
            assert_eq!(mt.load(i * 100 + 25), Some(&(i as u32)));
        }
    }
}
