// ============================================================================
// kernel/src/collections/xarray.rs
// ============================================================================
//! XArray - Sparse Array Implementation
//!
//! Linux カーネルの XArray にインスパイアされた Radix Tree ベースのスパース配列。
//! `usize` インデックスから値へのマッピングを効率的に管理する。
//!
//! ## 特徴
//!
//! - **スパース効率**: 空エントリはメモリを消費しない
//! - **自動リサイズ**: 必要に応じてツリーを拡張
//!
//! ## 使用例
//!
//! ```rust,ignore
//! use crate::collections::xarray::XArray;
//!
//! let mut xa: XArray<u32> = XArray::new();
//!
//! xa.store(0, 42);
//! xa.store(1000, 123);
//!
//! assert_eq!(xa.load(0), Some(&42));
//! assert_eq!(xa.load(500), None);  // スパース - 割り当てなし
//! assert_eq!(xa.load(1000), Some(&123));
//!
//! xa.erase(0);
//! assert_eq!(xa.load(0), None);
//! ```

#![allow(dead_code)]

use alloc::boxed::Box;
use core::marker::PhantomData;

// ============================================================================
// Constants
// ============================================================================

/// Radix Tree のファンアウト（各ノードのスロット数）
/// 64 = 2^6 なので、6ビットずつインデックスを分割
const XA_CHUNK_SHIFT: usize = 6;
const XA_CHUNK_SIZE: usize = 1 << XA_CHUNK_SHIFT;
const XA_CHUNK_MASK: usize = XA_CHUNK_SIZE - 1;

/// usize のビット数
const INDEX_BITS: usize = core::mem::size_of::<usize>() * 8;

// ============================================================================
// Marks
// ============================================================================

/// マークビットの型
pub type XAMark = u8;

/// マーク 0 (例: Dirty)
pub const XA_MARK_0: XAMark = 0b001;
/// マーク 1 (例: Writeback)
pub const XA_MARK_1: XAMark = 0b010;
/// マーク 2 (例: LRU)
pub const XA_MARK_2: XAMark = 0b100;

// ============================================================================
// XArray Node
// ============================================================================

/// Radix Tree ノード
struct XANode<T> {
    /// スロット（中間ノードまたはリーフへのポインタ）
    slots: [Option<XASlot<T>>; XA_CHUNK_SIZE],
    /// 有効なエントリ数
    count: u8,
}

/// スロットの内容
enum XASlot<T> {
    /// リーフエントリ（値 + マーク）
    Entry { value: Box<T>, marks: XAMark },
    /// 中間ノード
    Node(Box<XANode<T>>),
}

impl<T> XANode<T> {
    /// 新しい空ノードを作成
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            count: 0,
        }
    }
}

// ============================================================================
// XArray
// ============================================================================

/// スパース配列（Radix Tree ベース）
pub struct XArray<T> {
    /// ルートスロット
    root: Option<XASlot<T>>,
    /// 現在のツリーの深さ（レベル数, 0 = ルートがエントリ）
    height: u8,
    /// エントリ数
    len: usize,
    _marker: PhantomData<T>,
}

impl<T> XArray<T> {
    /// 空の XArray を作成
    pub const fn new() -> Self {
        Self {
            root: None,
            height: 0,
            len: 0,
            _marker: PhantomData,
        }
    }

    /// エントリ数を取得
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// 空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 現在の高さで表現可能な最大インデックス
    #[inline]
    fn max_index(&self) -> usize {
        if self.height == 0 {
            0
        } else {
            (1usize << (self.height as usize * XA_CHUNK_SHIFT)) - 1
        }
    }

    /// インデックスに必要な高さを計算
    fn required_height(index: usize) -> u8 {
        if index == 0 {
            return 0;
        }
        // 必要なビット数を計算
        let bits_needed = INDEX_BITS - index.leading_zeros() as usize;
        // 必要なレベル数
        ((bits_needed + XA_CHUNK_SHIFT - 1) / XA_CHUNK_SHIFT) as u8
    }

    /// エントリを格納
    ///
    /// 既存のエントリがある場合は置き換え、古い値を返す。
    pub fn store(&mut self, index: usize, value: T) -> Option<T> {
        // 必要に応じてツリーを拡張
        self.grow_for_index(index);
        
        let old = self.store_at(index, value);
        if old.is_none() {
            self.len += 1;
        }
        old
    }

    /// エントリを読み取り
    pub fn load(&self, index: usize) -> Option<&T> {
        if index > self.max_index() {
            return None;
        }
        
        self.get_at(index)
    }

    /// エントリを可変で読み取り
    pub fn load_mut(&mut self, index: usize) -> Option<&mut T> {
        if index > self.max_index() {
            return None;
        }
        
        self.get_at_mut(index)
    }

    /// エントリを削除
    pub fn erase(&mut self, index: usize) -> Option<T> {
        if index > self.max_index() {
            return None;
        }
        
        let old = self.remove_at(index);
        if old.is_some() {
            self.len -= 1;
        }
        old
    }

    // ========================================================================
    // Mark Operations
    // ========================================================================

    /// エントリにマークを設定
    pub fn set_mark(&mut self, index: usize, mark: XAMark) -> bool {
        if let Some(slot) = self.get_slot_mut(index) {
            if let XASlot::Entry { marks, .. } = slot {
                *marks |= mark;
                return true;
            }
        }
        false
    }

    /// エントリのマークをクリア
    pub fn clear_mark(&mut self, index: usize, mark: XAMark) -> bool {
        if let Some(slot) = self.get_slot_mut(index) {
            if let XASlot::Entry { marks, .. } = slot {
                *marks &= !mark;
                return true;
            }
        }
        false
    }

    /// エントリがマークを持つか確認
    pub fn has_mark(&self, index: usize, mark: XAMark) -> bool {
        if let Some(slot) = self.get_slot(index) {
            if let XASlot::Entry { marks, .. } = slot {
                return (*marks & mark) != 0;
            }
        }
        false
    }

    /// 指定スロットを取得（内部用）
    fn get_slot(&self, index: usize) -> Option<&XASlot<T>> {
        if index > self.max_index() {
            return None;
        }
        
        if self.height == 0 {
            return self.root.as_ref();
        }

        let mut current = self.root.as_ref()?;
        
        for level in (1..self.height).rev() {
            let shift = level as usize * XA_CHUNK_SHIFT;
            let slot_idx = (index >> shift) & XA_CHUNK_MASK;
            
            match current {
                XASlot::Node(node) => {
                    current = node.slots[slot_idx].as_ref()?;
                }
                XASlot::Entry { .. } => return None,
            }
        }

        let slot_idx = index & XA_CHUNK_MASK;
        match current {
            XASlot::Node(node) => node.slots[slot_idx].as_ref(),
            _ => None,
        }
    }

    /// 指定スロットを可変で取得（内部用）
    fn get_slot_mut(&mut self, index: usize) -> Option<&mut XASlot<T>> {
        if index > self.max_index() {
            return None;
        }
        
        if self.height == 0 {
            return self.root.as_mut();
        }

        let mut current = self.root.as_mut()?;
        
        for level in (1..self.height).rev() {
            let shift = level as usize * XA_CHUNK_SHIFT;
            let slot_idx = (index >> shift) & XA_CHUNK_MASK;
            
            match current {
                XASlot::Node(node) => {
                    current = node.slots[slot_idx].as_mut()?;
                }
                XASlot::Entry { .. } => return None,
            }
        }

        let slot_idx = index & XA_CHUNK_MASK;
        match current {
            XASlot::Node(node) => node.slots[slot_idx].as_mut(),
            _ => None,
        }
    }

    /// ツリーを拡張
    fn grow_for_index(&mut self, index: usize) {
        let required = Self::required_height(index);
        
        while self.height < required {
            match self.root.take() {
                None => {
                    // 空 - 高さだけ設定
                    self.height = required;
                    return;
                }
                Some(old_root) => {
                    // 新しいルートノードを作成し、古いルートをスロット0に
                    let mut new_node = Box::new(XANode::new());
                    new_node.slots[0] = Some(old_root);
                    new_node.count = 1;
                    self.root = Some(XASlot::Node(new_node));
                    self.height += 1;
                }
            }
        }
    }

    /// 指定インデックスに格納
    fn store_at(&mut self, index: usize, value: T) -> Option<T> {
        if self.height == 0 {
            // 高さ0 = インデックス0のみ
            debug_assert_eq!(index, 0);
            let old = self.root.take();
            self.root = Some(XASlot::Entry { value: Box::new(value), marks: 0 });
            return match old {
                Some(XASlot::Entry { value: e, .. }) => Some(*e),
                _ => None,
            };
        }

        // ルートノードを確保
        if self.root.is_none() {
            self.root = Some(XASlot::Node(Box::new(XANode::new())));
        }

        let mut current: &mut Option<XASlot<T>> = &mut self.root;
        
        // 上位レベルから下位レベルへ
        for level in (1..self.height).rev() {
            let shift = level as usize * XA_CHUNK_SHIFT;
            let slot_idx = (index >> shift) & XA_CHUNK_MASK;
            
            // ノードを取得/作成
            match current {
                Some(XASlot::Node(node)) => {
                    if node.slots[slot_idx].is_none() {
                        node.slots[slot_idx] = Some(XASlot::Node(Box::new(XANode::new())));
                        node.count += 1;
                    }
                    current = &mut node.slots[slot_idx];
                }
                _ => unreachable!("Expected node at non-leaf level"),
            }
        }

        // 最下位レベル
        let slot_idx = index & XA_CHUNK_MASK;
        
        match current {
            Some(XASlot::Node(node)) => {
                let old = node.slots[slot_idx].take();
                node.slots[slot_idx] = Some(XASlot::Entry { value: Box::new(value), marks: 0 });
                if old.is_none() {
                    node.count += 1;
                }
                match old {
                    Some(XASlot::Entry { value: e, .. }) => Some(*e),
                    _ => None,
                }
            }
            _ => unreachable!("Expected node at leaf level"),
        }
    }

    /// 指定インデックスを取得
    fn get_at(&self, index: usize) -> Option<&T> {
        if self.height == 0 {
            return match &self.root {
                Some(XASlot::Entry { value: e, .. }) if index == 0 => Some(e.as_ref()),
                _ => None,
            };
        }

        let mut current = self.root.as_ref()?;
        
        for level in (1..self.height).rev() {
            let shift = level as usize * XA_CHUNK_SHIFT;
            let slot_idx = (index >> shift) & XA_CHUNK_MASK;
            
            match current {
                XASlot::Node(node) => {
                    current = node.slots[slot_idx].as_ref()?;
                }
                XASlot::Entry { .. } => return None,
            }
        }

        // 最下位レベル
        let slot_idx = index & XA_CHUNK_MASK;
        
        match current {
            XASlot::Node(node) => {
                match node.slots[slot_idx].as_ref()? {
                    XASlot::Entry { value: e, .. } => Some(e.as_ref()),
                    _ => None,
                }
            }
            XASlot::Entry { value: e, .. } if index == 0 => Some(e.as_ref()),
            _ => None,
        }
    }

    /// 指定インデックスを可変で取得
    fn get_at_mut(&mut self, index: usize) -> Option<&mut T> {
        if self.height == 0 {
            return match &mut self.root {
                Some(XASlot::Entry { value: e, .. }) if index == 0 => Some(e.as_mut()),
                _ => None,
            };
        }

        let mut current = self.root.as_mut()?;
        
        for level in (1..self.height).rev() {
            let shift = level as usize * XA_CHUNK_SHIFT;
            let slot_idx = (index >> shift) & XA_CHUNK_MASK;
            
            match current {
                XASlot::Node(node) => {
                    current = node.slots[slot_idx].as_mut()?;
                }
                XASlot::Entry { .. } => return None,
            }
        }

        let slot_idx = index & XA_CHUNK_MASK;
        
        match current {
            XASlot::Node(node) => {
                match node.slots[slot_idx].as_mut()? {
                    XASlot::Entry { value: e, .. } => Some(e.as_mut()),
                    _ => None,
                }
            }
            XASlot::Entry { value: e, .. } if index == 0 => Some(e.as_mut()),
            _ => None,
        }
    }

    /// 指定インデックスを削除
    fn remove_at(&mut self, index: usize) -> Option<T> {
        if self.height == 0 {
            return match self.root.take() {
                Some(XASlot::Entry { value: e, .. }) if index == 0 => Some(*e),
                other => {
                    self.root = other;
                    None
                }
            };
        }

        let mut current = self.root.as_mut()?;
        
        for level in (1..self.height).rev() {
            let shift = level as usize * XA_CHUNK_SHIFT;
            let slot_idx = (index >> shift) & XA_CHUNK_MASK;
            
            match current {
                XASlot::Node(node) => {
                    current = node.slots[slot_idx].as_mut()?;
                }
                XASlot::Entry { .. } => return None,
            }
        }

        let slot_idx = index & XA_CHUNK_MASK;
        
        match current {
            XASlot::Node(node) => {
                match node.slots[slot_idx].take() {
                    Some(XASlot::Entry { value: e, .. }) => {
                        node.count = node.count.saturating_sub(1);
                        Some(*e)
                    }
                    other => {
                        node.slots[slot_idx] = other;
                        None
                    }
                }
            }
            _ => None,
        }
    }

    /// イテレータを取得（インデックス順）
    pub fn iter(&self) -> XArrayIter<'_, T> {
        XArrayIter {
            xa: self,
            next_index: 0,
            max_index: self.max_index(),
        }
    }
}

impl<T> Default for XArray<T> {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: XArray は内部で Box を使用、適切に同期すれば Send/Sync 可能
unsafe impl<T: Send> Send for XArray<T> {}
unsafe impl<T: Sync> Sync for XArray<T> {}

// ============================================================================
// Iterator
// ============================================================================

/// XArray のイテレータ
pub struct XArrayIter<'a, T> {
    xa: &'a XArray<T>,
    next_index: usize,
    max_index: usize,
}

impl<'a, T> Iterator for XArrayIter<'a, T> {
    type Item = (usize, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_index <= self.max_index {
            let idx = self.next_index;
            self.next_index += 1;
            
            if let Some(entry) = self.xa.load(idx) {
                return Some((idx, entry));
            }
        }
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use alloc::vec;

    #[test_case]
    fn test_empty() {
        let xa: XArray<u32> = XArray::new();
        assert!(xa.is_empty());
        assert_eq!(xa.len(), 0);
        assert_eq!(xa.load(0), None);
        assert_eq!(xa.load(100), None);
    }

    #[test_case]
    fn test_store_load() {
        let mut xa: XArray<u32> = XArray::new();
        
        assert_eq!(xa.store(0, 42), None);
        assert_eq!(xa.len(), 1);
        assert_eq!(xa.load(0), Some(&42));
        
        // 上書き
        assert_eq!(xa.store(0, 100), Some(42));
        assert_eq!(xa.len(), 1);
        assert_eq!(xa.load(0), Some(&100));
    }

    #[test_case]
    fn test_sparse() {
        let mut xa: XArray<u32> = XArray::new();
        
        xa.store(0, 1);
        xa.store(100, 2);
        xa.store(10000, 3);
        
        assert_eq!(xa.len(), 3);
        assert_eq!(xa.load(0), Some(&1));
        assert_eq!(xa.load(50), None);  // スパース
        assert_eq!(xa.load(100), Some(&2));
        assert_eq!(xa.load(5000), None);  // スパース
        assert_eq!(xa.load(10000), Some(&3));
    }

    #[test_case]
    fn test_erase() {
        let mut xa: XArray<u32> = XArray::new();
        
        xa.store(10, 42);
        assert_eq!(xa.len(), 1);
        
        assert_eq!(xa.erase(10), Some(42));
        assert_eq!(xa.len(), 0);
        assert_eq!(xa.load(10), None);
        
        // 存在しないエントリの削除
        assert_eq!(xa.erase(10), None);
    }

    #[test_case]
    fn test_large_indices() {
        let mut xa: XArray<u32> = XArray::new();
        
        let indices = [0, 63, 64, 4095, 4096, 262143, 262144];
        
        for (i, &idx) in indices.iter().enumerate() {
            xa.store(idx, i as u32);
        }
        
        assert_eq!(xa.len(), indices.len());
        
        for (i, &idx) in indices.iter().enumerate() {
            assert_eq!(xa.load(idx), Some(&(i as u32)), "Failed at index {}", idx);
        }
    }

    #[test_case]
    fn test_iter() {
        let mut xa: XArray<u32> = XArray::new();
        
        xa.store(5, 50);
        xa.store(10, 100);
        xa.store(15, 150);
        
        let collected: Vec<(usize, u32)> = xa.iter().map(|(i, v)| (i, *v)).collect();
        assert_eq!(collected, vec![(5, 50), (10, 100), (15, 150)]);
    }

    #[test_case]
    fn test_load_mut() {
        let mut xa: XArray<u32> = XArray::new();
        
        xa.store(0, 100);
        
        if let Some(v) = xa.load_mut(0) {
            *v = 200;
        }
        
        assert_eq!(xa.load(0), Some(&200));
    }

    #[test_case]
    fn test_marks() {
        let mut xa: XArray<u32> = XArray::new();
        
        xa.store(0, 100);
        xa.store(1, 200);
        
        // 初期状態: マークなし
        assert!(!xa.has_mark(0, super::XA_MARK_0));
        assert!(!xa.has_mark(1, super::XA_MARK_1));
        
        // マーク設定
        assert!(xa.set_mark(0, super::XA_MARK_0));
        assert!(xa.set_mark(1, super::XA_MARK_1));
        
        assert!(xa.has_mark(0, super::XA_MARK_0));
        assert!(xa.has_mark(1, super::XA_MARK_1));
        assert!(!xa.has_mark(0, super::XA_MARK_1));
        
        // マーククリア
        assert!(xa.clear_mark(0, super::XA_MARK_0));
        assert!(!xa.has_mark(0, super::XA_MARK_0));
    }
}

// ============================================================================
// XArrayUsize - Zero-allocation Integer Storage
// ============================================================================

/// usize 値専用の XArray（ヒープ割り当てなし）
///
/// ポインタタギングにより、usize 値を直接スロットに格納。
/// ページキャッシュなどの整数インデックスマッピングに最適。
pub struct XArrayUsize {
    slots: [UsizeSlot; XA_CHUNK_SIZE],
    len: usize,
}

/// usize スロット（ゼロアロケーション）
#[derive(Clone, Copy)]
struct UsizeSlot {
    /// 値（0 = 空、それ以外 = value + 1）
    value: usize,
    marks: XAMark,
}

impl Default for UsizeSlot {
    fn default() -> Self {
        Self { value: 0, marks: 0 }
    }
}

impl XArrayUsize {
    /// 空の XArrayUsize を作成
    pub const fn new() -> Self {
        Self {
            slots: [UsizeSlot { value: 0, marks: 0 }; XA_CHUNK_SIZE],
            len: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 値を格納（インデックスは 0..63）
    pub fn store(&mut self, index: usize, value: usize) -> Option<usize> {
        if index >= XA_CHUNK_SIZE {
            return None;
        }
        
        let old = if self.slots[index].value != 0 {
            Some(self.slots[index].value - 1)
        } else {
            self.len += 1;
            None
        };
        
        // value + 1 で格納（0 を空と区別）
        self.slots[index].value = value.checked_add(1)?;
        old
    }

    /// 値を取得
    pub fn load(&self, index: usize) -> Option<usize> {
        if index >= XA_CHUNK_SIZE {
            return None;
        }
        
        if self.slots[index].value != 0 {
            Some(self.slots[index].value - 1)
        } else {
            None
        }
    }

    /// 値を削除
    pub fn erase(&mut self, index: usize) -> Option<usize> {
        if index >= XA_CHUNK_SIZE {
            return None;
        }
        
        if self.slots[index].value != 0 {
            let old = self.slots[index].value - 1;
            self.slots[index] = UsizeSlot::default();
            self.len -= 1;
            Some(old)
        } else {
            None
        }
    }

    /// マーク設定
    pub fn set_mark(&mut self, index: usize, mark: XAMark) -> bool {
        if index >= XA_CHUNK_SIZE || self.slots[index].value == 0 {
            return false;
        }
        self.slots[index].marks |= mark;
        true
    }

    /// マーククリア
    pub fn clear_mark(&mut self, index: usize, mark: XAMark) -> bool {
        if index >= XA_CHUNK_SIZE || self.slots[index].value == 0 {
            return false;
        }
        self.slots[index].marks &= !mark;
        true
    }

    /// マーク確認
    pub fn has_mark(&self, index: usize, mark: XAMark) -> bool {
        if index >= XA_CHUNK_SIZE {
            return false;
        }
        self.slots[index].value != 0 && (self.slots[index].marks & mark) != 0
    }
}

impl Default for XArrayUsize {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests_usize {
    use super::*;

    #[test_case]
    fn test_usize_basic() {
        let mut xa = XArrayUsize::new();
        
        assert!(xa.is_empty());
        
        xa.store(0, 42);
        xa.store(10, 100);
        
        assert_eq!(xa.len(), 2);
        assert_eq!(xa.load(0), Some(42));
        assert_eq!(xa.load(10), Some(100));
        assert_eq!(xa.load(5), None);
        
        assert_eq!(xa.erase(0), Some(42));
        assert_eq!(xa.load(0), None);
        assert_eq!(xa.len(), 1);
    }

    #[test_case]
    fn test_usize_marks() {
        let mut xa = XArrayUsize::new();
        
        xa.store(0, 100);
        
        assert!(!xa.has_mark(0, XA_MARK_0));
        xa.set_mark(0, XA_MARK_0);
        assert!(xa.has_mark(0, XA_MARK_0));
        
        xa.clear_mark(0, XA_MARK_0);
        assert!(!xa.has_mark(0, XA_MARK_0));
    }

    #[test_case]
    fn test_usize_zero_value() {
        let mut xa = XArrayUsize::new();
        
        // 0 も正しく格納できる
        xa.store(0, 0);
        assert_eq!(xa.load(0), Some(0));
        assert_eq!(xa.len(), 1);
    }
}

