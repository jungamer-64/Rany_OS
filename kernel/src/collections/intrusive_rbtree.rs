// ============================================================================
// kernel/src/collections/intrusive_rbtree.rs
// ============================================================================
#![allow(unsafe_op_in_unsafe_fn)]
//! Intrusive Red-Black Tree Implementation
//!
//! Linux カーネルの rbtree スタイルの侵入型赤黒木。
//! 各ノードは構造体内に `RBLink` を埋め込み、外部からツリーに挿入される。
//!
//! ## 特徴
//!
//! - **ゼロアロケーション**: ツリー操作自体はヒープ割り当てを行わない
//! - **侵入型**: ノードデータ内にリンク構造を埋め込む
//! - **KeyAdapter**: キー抽出とリンク取得を抽象化
//!
//! ## 使用例
//!
//! ```rust,ignore
//! use crate::collections::intrusive_rbtree::{RBLink, RBTree, KeyAdapter};
//!
//! struct MyEntry {
//!     link: RBLink,
//!     key: u64,
//!     value: u32,
//! }
//!
//! struct MyAdapter;
//!
//! unsafe impl KeyAdapter for MyAdapter {
//!     type Key = u64;
//!     type Entry = MyEntry;
//!
//!     fn get_key(entry: &Self::Entry) -> &Self::Key { &entry.key }
//!     fn get_link(entry: &Self::Entry) -> &RBLink { &entry.link }
//!     fn get_link_mut(entry: &mut Self::Entry) -> &mut RBLink { &mut entry.link }
//!     unsafe fn entry_from_link(link: *mut RBLink) -> *mut Self::Entry {
//!         // container_of equivalent
//!         link.cast::<u8>().sub(offset_of!(MyEntry, link)).cast()
//!     }
//! }
//! ```

#![allow(dead_code)]

use core::cmp::Ordering;
use core::marker::PhantomData;
use core::ptr;

// ============================================================================
// Color
// ============================================================================

/// 赤黒木ノードの色
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Color {
    Red = 0,
    Black = 1,
}

// ============================================================================
// RBLink
// ============================================================================

/// 侵入型リンク（構造体内に埋め込む）
///
/// Linux カーネルの `rb_node` に相当。
/// 親ポインタの最下位ビットに色を格納する。
#[repr(C)]
pub struct RBLink {
    /// 親ポインタ + 色 (LSB = 色)
    parent_color: usize,
    /// 左子ノード
    left: *mut RBLink,
    /// 右子ノード
    right: *mut RBLink,
}

impl RBLink {
    /// 新しい未リンク状態のRBLinkを作成
    pub const fn new() -> Self {
        Self {
            parent_color: 0,
            left: ptr::null_mut(),
            right: ptr::null_mut(),
        }
    }

    /// このリンクがツリーに接続されているかどうか
    #[inline]
    pub fn is_linked(&self) -> bool {
        // 親がある、または左右の子がある場合はリンク済み
        self.parent_color != 0 || !self.left.is_null() || !self.right.is_null()
    }

    /// 親ポインタを取得
    #[inline]
    fn parent(&self) -> *mut RBLink {
        (self.parent_color & !1) as *mut RBLink
    }

    /// 色を取得
    #[inline]
    fn color(&self) -> Color {
        if self.parent_color & 1 == 0 {
            Color::Red
        } else {
            Color::Black
        }
    }

    /// 親と色を設定
    #[inline]
    fn set_parent_color(&mut self, parent: *mut RBLink, color: Color) {
        self.parent_color = (parent as usize) | (color as usize);
    }

    /// 色のみを設定
    #[inline]
    fn set_color(&mut self, color: Color) {
        self.parent_color = (self.parent_color & !1) | (color as usize);
    }

    /// 親のみを設定（色は維持）
    #[inline]
    fn set_parent(&mut self, parent: *mut RBLink) {
        self.parent_color = (parent as usize) | (self.parent_color & 1);
    }

    /// リンクをクリア（削除後のクリーンアップ用）
    #[inline]
    fn clear(&mut self) {
        self.parent_color = 0;
        self.left = ptr::null_mut();
        self.right = ptr::null_mut();
    }
}

impl Default for RBLink {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: RBLink自体はポインタを含むが、ツリー操作は適切に同期される
unsafe impl Send for RBLink {}
unsafe impl Sync for RBLink {}

// ============================================================================
// KeyAdapter Trait
// ============================================================================

/// キー抽出とリンク取得を抽象化するトレイト
///
/// # Safety
///
/// `entry_from_link` は有効なポインタを返す必要がある。
pub unsafe trait KeyAdapter {
    /// キーの型（Ord を実装する必要がある）
    type Key: Ord;
    
    /// エントリの型
    type Entry;

    /// エントリからキーを取得
    fn get_key(entry: &Self::Entry) -> &Self::Key;
    
    /// エントリからRBLinkを取得（不変）
    fn get_link(entry: &Self::Entry) -> &RBLink;
    
    /// エントリからRBLinkを取得（可変）
    fn get_link_mut(entry: &mut Self::Entry) -> &mut RBLink;
    
    /// RBLinkポインタからエントリポインタを取得
    ///
    /// # Safety
    ///
    /// `link` は有効なエントリ内の RBLink を指している必要がある。
    unsafe fn entry_from_link(link: *mut RBLink) -> *mut Self::Entry;
}

// ============================================================================
// RBTree
// ============================================================================

/// 侵入型赤黒木
pub struct RBTree<A: KeyAdapter> {
    root: *mut RBLink,
    len: usize,
    /// 直近アクセスノード（ヒントキャッシュ）
    last_hint: *mut RBLink,
    _marker: PhantomData<A>,
}

impl<A: KeyAdapter> RBTree<A> {
    /// 空のツリーを作成
    pub const fn new() -> Self {
        Self {
            root: ptr::null_mut(),
            len: 0,
            last_hint: ptr::null_mut(),
            _marker: PhantomData,
        }
    }

    /// ツリーが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.root.is_null()
    }

    /// ツリー内のエントリ数
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// キーで検索
    ///
    /// # Safety
    ///
    /// 返されるポインタはツリーが変更されるまで有効。
    pub fn find(&self, key: &A::Key) -> Option<*mut A::Entry> {
        let mut node = self.root;
        
        while !node.is_null() {
            let entry = unsafe { A::entry_from_link(node) };
            let node_key = unsafe { A::get_key(&*entry) };
            
            match key.cmp(node_key) {
                Ordering::Less => {
                    node = unsafe { (*node).left };
                }
                Ordering::Greater => {
                    node = unsafe { (*node).right };
                }
                Ordering::Equal => {
                    return Some(entry);
                }
            }
        }
        
        None
    }

    /// ヒントを使った高速検索
    ///
    /// 直近アクセスノードから開始し、近傍キーへのアクセスを O(1) に近づける。
    /// シーケンシャルアクセスや局所性の高いパターンで効果的。
    pub fn find_near(&mut self, key: &A::Key) -> Option<*mut A::Entry> {
        // ヒントが有効か確認
        if !self.last_hint.is_null() {
            let hint_entry = unsafe { A::entry_from_link(self.last_hint) };
            let hint_key = unsafe { A::get_key(&*hint_entry) };
            
            match key.cmp(hint_key) {
                Ordering::Equal => {
                    return Some(hint_entry);
                }
                Ordering::Less => {
                    // ヒントより小さい - 親を辿るか左部分木を探索
                    // 単純化のため通常検索にフォールバック
                }
                Ordering::Greater => {
                    // ヒントより大きい - 後継者を試す
                    let succ = unsafe { self.successor(self.last_hint) };
                    if let Some(succ_link) = succ {
                        let succ_entry = unsafe { A::entry_from_link(succ_link) };
                        let succ_key = unsafe { A::get_key(&*succ_entry) };
                        if key == succ_key {
                            self.last_hint = succ_link;
                            return Some(succ_entry);
                        }
                    }
                }
            }
        }
        
        // フォールバック: 通常検索 + ヒント更新
        let result = self.find(key);
        if let Some(entry) = result {
            self.last_hint = unsafe { A::get_link(&*entry) as *const RBLink as *mut RBLink };
        }
        result
    }

    /// 後継ノードを取得（内部用）
    unsafe fn successor(&self, node: *mut RBLink) -> Option<*mut RBLink> {
        if (*node).right.is_null() {
            // 親を辿る
            let mut n = node;
            loop {
                let parent = (*n).parent();
                if parent.is_null() {
                    return None;
                }
                if n == (*parent).left {
                    return Some(parent);
                }
                n = parent;
            }
        } else {
            // 右部分木の最小
            let mut n = (*node).right;
            while !(*n).left.is_null() {
                n = (*n).left;
            }
            Some(n)
        }
    }

    /// エントリを挿入
    ///
    /// 同じキーが既に存在する場合は `false` を返し、挿入しない。
    ///
    /// # Safety
    ///
    /// `entry` は有効なポインタで、ツリーに挿入されている間は有効である必要がある。
    /// また、エントリの RBLink は未リンク状態である必要がある。
    pub unsafe fn insert(&mut self, entry: *mut A::Entry) -> bool {
        // &mut を保持せず、shared ref から raw ptr を取得（参照エイリアシング回避）
        let new_link = A::get_link(&*entry) as *const RBLink as *mut RBLink;
        
        debug_assert!(!(*new_link).is_linked(), "Entry is already linked");
        // RBLink は 2byte 以上にアラインされている必要がある（LSB に色を格納）
        debug_assert_eq!((new_link as usize) & 1, 0, "RBLink must be at least 2-byte aligned");
        
        // 挿入位置を見つける
        let mut parent: *mut RBLink = ptr::null_mut();
        let mut node_ptr: *mut *mut RBLink = &mut self.root;
        
        // key 参照は探索中のみ有効（スコープで借用を終わらせる）
        {
            let key = A::get_key(&*entry);
            
            while !(*node_ptr).is_null() {
                parent = *node_ptr;
                let parent_entry = A::entry_from_link(parent);
                let parent_key = A::get_key(&*parent_entry);
                
                match key.cmp(parent_key) {
                    Ordering::Less => {
                        node_ptr = &mut (*parent).left;
                    }
                    Ordering::Greater => {
                        node_ptr = &mut (*parent).right;
                    }
                    Ordering::Equal => {
                        // 重複キー
                        return false;
                    }
                }
            }
        } // <- key の借用をここで終わらせる
        
        // ノードを挿入（初期色: 赤）
        (*new_link).set_parent_color(parent, Color::Red);
        (*new_link).left = ptr::null_mut();
        (*new_link).right = ptr::null_mut();
        *node_ptr = new_link;
        
        self.len += 1;
        
        // リバランス
        self.insert_fixup(new_link);
        
        true
    }

    /// エントリを削除
    ///
    /// # Safety
    ///
    /// `entry` はこのツリーに含まれている必要がある。
    pub unsafe fn remove(&mut self, entry: *mut A::Entry) {
        // &mut を保持せず raw ptr を取得
        let link = A::get_link(&*entry) as *const RBLink as *mut RBLink;
        
        debug_assert!((*link).is_linked(), "Entry is not linked");
        
        self.remove_node(link);
        (*link).clear();
        self.len -= 1;
    }

    /// 最小のエントリを取得
    pub fn first(&self) -> Option<*mut A::Entry> {
        if self.root.is_null() {
            return None;
        }
        
        let mut node = self.root;
        while !unsafe { (*node).left }.is_null() {
            node = unsafe { (*node).left };
        }
        
        Some(unsafe { A::entry_from_link(node) })
    }

    /// 最大のエントリを取得
    pub fn last(&self) -> Option<*mut A::Entry> {
        if self.root.is_null() {
            return None;
        }
        
        let mut node = self.root;
        while !unsafe { (*node).right }.is_null() {
            node = unsafe { (*node).right };
        }
        
        Some(unsafe { A::entry_from_link(node) })
    }

    /// イテレータを取得（昇順）
    ///
    /// # Safety
    ///
    /// 返されるポインタはツリーが変更されるまで、かつエントリが有効である間のみ使用可能。
    /// 侵入型コンテナはエントリを所有しないため、参照ではなくポインタを返す。
    pub fn iter(&self) -> RBTreeIter<A> {
        RBTreeIter {
            current: self.first_link(),
            _marker: PhantomData,
        }
    }
    
    /// 最小ノードの RBLink を取得（内部用）
    fn first_link(&self) -> Option<*mut RBLink> {
        if self.root.is_null() {
            return None;
        }
        
        let mut node = self.root;
        while !unsafe { (*node).left }.is_null() {
            node = unsafe { (*node).left };
        }
        
        Some(node)
    }

    // ========================================================================
    // 内部ヘルパー
    // ========================================================================

    /// 挿入後のリバランス
    unsafe fn insert_fixup(&mut self, mut node: *mut RBLink) {
        while let Some(parent) = self.red_parent(node) {
            let grandparent = (*parent).parent();
            if grandparent.is_null() {
                break;
            }
            
            if parent == (*grandparent).left {
                let uncle = (*grandparent).right;
                
                if !uncle.is_null() && (*uncle).color() == Color::Red {
                    // Case 1: 叔父が赤
                    (*parent).set_color(Color::Black);
                    (*uncle).set_color(Color::Black);
                    (*grandparent).set_color(Color::Red);
                    node = grandparent;
                } else {
                    if node == (*parent).right {
                        // Case 2: node は右子 -> 左回転
                        node = parent;
                        self.rotate_left(node);
                    }
                    // Case 3: node は左子 -> 右回転
                    let parent = (*node).parent();
                    let grandparent = (*parent).parent();
                    (*parent).set_color(Color::Black);
                    (*grandparent).set_color(Color::Red);
                    self.rotate_right(grandparent);
                }
            } else {
                // 対称ケース
                let uncle = (*grandparent).left;
                
                if !uncle.is_null() && (*uncle).color() == Color::Red {
                    (*parent).set_color(Color::Black);
                    (*uncle).set_color(Color::Black);
                    (*grandparent).set_color(Color::Red);
                    node = grandparent;
                } else {
                    if node == (*parent).left {
                        node = parent;
                        self.rotate_right(node);
                    }
                    let parent = (*node).parent();
                    let grandparent = (*parent).parent();
                    (*parent).set_color(Color::Black);
                    (*grandparent).set_color(Color::Red);
                    self.rotate_left(grandparent);
                }
            }
        }
        
        // ルートは常に黒
        if !self.root.is_null() {
            (*self.root).set_color(Color::Black);
        }
    }

    /// 親が赤の場合、親ポインタを返す
    #[inline]
    unsafe fn red_parent(&self, node: *mut RBLink) -> Option<*mut RBLink> {
        let parent = (*node).parent();
        if !parent.is_null() && (*parent).color() == Color::Red {
            Some(parent)
        } else {
            None
        }
    }

    /// 左回転
    unsafe fn rotate_left(&mut self, x: *mut RBLink) {
        let y = (*x).right;
        debug_assert!(!y.is_null(), "rotate_left: right child must not be null");
        
        (*x).right = (*y).left;
        
        if !(*y).left.is_null() {
            (*(*y).left).set_parent(x);
        }
        
        (*y).set_parent((*x).parent());
        
        if (*x).parent().is_null() {
            self.root = y;
        } else if x == (*(*x).parent()).left {
            (*(*x).parent()).left = y;
        } else {
            (*(*x).parent()).right = y;
        }
        
        (*y).left = x;
        (*x).set_parent(y);
    }

    /// 右回転
    unsafe fn rotate_right(&mut self, y: *mut RBLink) {
        let x = (*y).left;
        debug_assert!(!x.is_null(), "rotate_right: left child must not be null");
        
        (*y).left = (*x).right;
        
        if !(*x).right.is_null() {
            (*(*x).right).set_parent(y);
        }
        
        (*x).set_parent((*y).parent());
        
        if (*y).parent().is_null() {
            self.root = x;
        } else if y == (*(*y).parent()).right {
            (*(*y).parent()).right = x;
        } else {
            (*(*y).parent()).left = x;
        }
        
        (*x).right = y;
        (*y).set_parent(x);
    }

    /// ノードを削除
    unsafe fn remove_node(&mut self, node: *mut RBLink) {
        let mut child: *mut RBLink;
        let mut parent: *mut RBLink;
        let color: Color;

        if (*node).left.is_null() {
            child = (*node).right;
            parent = (*node).parent();
            color = (*node).color();
            self.transplant(node, child);
        } else if (*node).right.is_null() {
            child = (*node).left;
            parent = (*node).parent();
            color = (*node).color();
            self.transplant(node, child);
        } else {
            // 両方の子がある場合、後継ノードを見つける
            let mut successor = (*node).right;
            while !(*successor).left.is_null() {
                successor = (*successor).left;
            }

            color = (*successor).color();
            child = (*successor).right;

            if (*successor).parent() == node {
                parent = successor;
            } else {
                parent = (*successor).parent();
                self.transplant(successor, child);
                (*successor).right = (*node).right;
                (*(*successor).right).set_parent(successor);
            }

            self.transplant(node, successor);
            (*successor).left = (*node).left;
            (*(*successor).left).set_parent(successor);
            (*successor).set_color((*node).color());
        }

        // 黒ノードが削除された場合、リバランス
        if color == Color::Black {
            self.remove_fixup(child, parent);
        }
    }

    /// ノードu をノードv で置き換え
    unsafe fn transplant(&mut self, u: *mut RBLink, v: *mut RBLink) {
        let parent = (*u).parent();
        if parent.is_null() {
            self.root = v;
        } else if u == (*parent).left {
            (*parent).left = v;
        } else {
            (*parent).right = v;
        }
        if !v.is_null() {
            (*v).set_parent(parent);
        }
    }

    /// 削除後のリバランス
    unsafe fn remove_fixup(&mut self, mut node: *mut RBLink, mut parent: *mut RBLink) {
        unsafe {
            while node != self.root && (node.is_null() || (*node).color() == Color::Black) {
                if parent.is_null() {
                    break;
                }

                if node == (*parent).left {
                    let mut sibling = (*parent).right;

                    if !sibling.is_null() && (*sibling).color() == Color::Red {
                        (*sibling).set_color(Color::Black);
                        (*parent).set_color(Color::Red);
                        self.rotate_left(parent);
                        sibling = (*parent).right;
                    }

                    if sibling.is_null() {
                        node = parent;
                        parent = (*node).parent();
                        continue;
                    }

                    let left_black = (*sibling).left.is_null() || (*(*sibling).left).color() == Color::Black;
                    let right_black = (*sibling).right.is_null() || (*(*sibling).right).color() == Color::Black;

                    if left_black && right_black {
                        (*sibling).set_color(Color::Red);
                        node = parent;
                        parent = (*node).parent();
                    } else {
                        if right_black {
                            if !(*sibling).left.is_null() {
                                (*(*sibling).left).set_color(Color::Black);
                            }
                            (*sibling).set_color(Color::Red);
                            self.rotate_right(sibling);
                            sibling = (*parent).right;
                        }

                        if !sibling.is_null() {
                            (*sibling).set_color((*parent).color());
                        }
                        (*parent).set_color(Color::Black);
                        if !sibling.is_null() && !(*sibling).right.is_null() {
                            (*(*sibling).right).set_color(Color::Black);
                        }
                        self.rotate_left(parent);
                        node = self.root;
                        break;
                    }
                } else {
                    // 対称ケース
                    let mut sibling = (*parent).left;

                    if !sibling.is_null() && (*sibling).color() == Color::Red {
                        (*sibling).set_color(Color::Black);
                        (*parent).set_color(Color::Red);
                        self.rotate_right(parent);
                        sibling = (*parent).left;
                    }

                    if sibling.is_null() {
                        node = parent;
                        parent = (*node).parent();
                        continue;
                    }

                    let left_black = (*sibling).left.is_null() || (*(*sibling).left).color() == Color::Black;
                    let right_black = (*sibling).right.is_null() || (*(*sibling).right).color() == Color::Black;

                    if left_black && right_black {
                        (*sibling).set_color(Color::Red);
                        node = parent;
                        parent = (*node).parent();
                    } else {
                        if left_black {
                            if !(*sibling).right.is_null() {
                                (*(*sibling).right).set_color(Color::Black);
                            }
                            (*sibling).set_color(Color::Red);
                            self.rotate_left(sibling);
                            sibling = (*parent).left;
                        }

                        if !sibling.is_null() {
                            (*sibling).set_color((*parent).color());
                        }
                        (*parent).set_color(Color::Black);
                        if !sibling.is_null() && !(*sibling).left.is_null() {
                            (*(*sibling).left).set_color(Color::Black);
                        }
                        self.rotate_right(parent);
                        node = self.root;
                        break;
                    }
                }
            }

            if !node.is_null() {
                (*node).set_color(Color::Black);
            }
        }
    }
}

impl<A: KeyAdapter> Default for RBTree<A> {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: RBTree は内部で生ポインタを使用するが、操作は適切に同期される
unsafe impl<A: KeyAdapter> Send for RBTree<A> where A::Entry: Send {}
unsafe impl<A: KeyAdapter> Sync for RBTree<A> where A::Entry: Sync {}

// ============================================================================
// Iterator
// ============================================================================

/// RBTree のイテレータ（昇順走査）
///
/// 侵入型コンテナはエントリを所有しないため、参照ではなくポインタを返す。
/// 参照への変換は呼び出し側が `unsafe` で行う。
pub struct RBTreeIter<A: KeyAdapter> {
    current: Option<*mut RBLink>,
    _marker: PhantomData<A>,
}

impl<A: KeyAdapter> Iterator for RBTreeIter<A> {
    type Item = *mut A::Entry;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;
        
        // 現在のエントリを取得
        let entry = unsafe { A::entry_from_link(current) };
        
        // 次のノードを見つける（中順走査）
        self.current = unsafe { Self::successor(current) };
        
        Some(entry)
    }
}

impl<A: KeyAdapter> RBTreeIter<A> {
    /// 後継ノードを見つける
    unsafe fn successor(node: *mut RBLink) -> Option<*mut RBLink> {
        // 右子がある場合、その左端
        if !(*node).right.is_null() {
            let mut n = (*node).right;
            while !(*n).left.is_null() {
                n = (*n).left;
            }
            return Some(n);
        }
        
        // 右子がない場合、親を辿る
        let mut n = node;
        loop {
            let parent = (*n).parent();
            if parent.is_null() {
                return None;
            }
            if n == (*parent).left {
                return Some(parent);
            }
            n = parent;
        }
    }
}

// ============================================================================
// Helper Macro
// ============================================================================

/// 構造体フィールドのオフセットを計算するマクロ
#[macro_export]
macro_rules! offset_of {
    ($ty:ty, $field:ident) => {{
        // Safety: ヌルポインタからのオフセット計算のみ
        let uninit = core::mem::MaybeUninit::<$ty>::uninit();
        let base_ptr = uninit.as_ptr();
        let field_ptr = unsafe { core::ptr::addr_of!((*base_ptr).$field) };
        (field_ptr as usize) - (base_ptr as usize)
    }};
}

/// KeyAdapter を簡単に実装するためのマクロ
///
/// # 使用例
///
/// ```rust,ignore
/// struct MyEntry {
///     link: RBLink,
///     key: u64,
///     value: u32,
/// }
///
/// intrusive_adapter!(MyAdapter, MyEntry, u64, key, link);
/// ```
#[macro_export]
macro_rules! intrusive_adapter {
    ($adapter:ident, $entry:ty, $key_ty:ty, $key_field:ident, $link_field:ident) => {
        pub struct $adapter;

        unsafe impl $crate::collections::intrusive_rbtree::KeyAdapter for $adapter {
            type Key = $key_ty;
            type Entry = $entry;

            #[inline]
            fn get_key(entry: &Self::Entry) -> &Self::Key {
                &entry.$key_field
            }

            #[inline]
            fn get_link(entry: &Self::Entry) -> &$crate::collections::intrusive_rbtree::RBLink {
                &entry.$link_field
            }

            #[inline]
            fn get_link_mut(entry: &mut Self::Entry) -> &mut $crate::collections::intrusive_rbtree::RBLink {
                &mut entry.$link_field
            }

            #[inline]
            unsafe fn entry_from_link(link: *mut $crate::collections::intrusive_rbtree::RBLink) -> *mut Self::Entry {
                let offset = $crate::offset_of!($entry, $link_field);
                (link as *mut u8).sub(offset) as *mut Self::Entry
            }
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    struct TestEntry {
        link: RBLink,
        key: u64,
        value: u32,
    }

    impl TestEntry {
        fn new(key: u64, value: u32) -> Self {
            Self {
                link: RBLink::new(),
                key,
                value,
            }
        }
    }

    struct TestAdapter;

    unsafe impl KeyAdapter for TestAdapter {
        type Key = u64;
        type Entry = TestEntry;

        fn get_key(entry: &Self::Entry) -> &Self::Key {
            &entry.key
        }

        fn get_link(entry: &Self::Entry) -> &RBLink {
            &entry.link
        }

        fn get_link_mut(entry: &mut Self::Entry) -> &mut RBLink {
            &mut entry.link
        }

        unsafe fn entry_from_link(link: *mut RBLink) -> *mut Self::Entry {
            let offset = offset_of!(TestEntry, link);
            (link as *mut u8).sub(offset) as *mut Self::Entry
        }
    }

    #[test]
    fn test_empty_tree() {
        let tree: RBTree<TestAdapter> = RBTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert!(tree.first().is_none());
        assert!(tree.last().is_none());
    }

    #[test]
    fn test_insert_find() {
        let mut tree: RBTree<TestAdapter> = RBTree::new();
        let mut entry = Box::new(TestEntry::new(42, 100));

        unsafe {
            assert!(tree.insert(entry.as_mut()));
        }

        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());

        // 検索
        let found = tree.find(&42);
        assert!(found.is_some());
        unsafe {
            assert_eq!((*found.unwrap()).value, 100);
        }

        // 存在しないキー
        assert!(tree.find(&999).is_none());

        // クリーンアップ
        unsafe {
            tree.remove(entry.as_mut());
        }
    }

    #[test]
    fn test_multiple_inserts() {
        let mut tree: RBTree<TestAdapter> = RBTree::new();
        let mut entries: Vec<Box<TestEntry>> = (0..10)
            .map(|i| Box::new(TestEntry::new(i * 10, i as u32)))
            .collect();

        // 挿入
        for entry in entries.iter_mut() {
            unsafe {
                assert!(tree.insert(entry.as_mut()));
            }
        }

        assert_eq!(tree.len(), 10);

        // 全て検索可能
        for i in 0..10u64 {
            assert!(tree.find(&(i * 10)).is_some());
        }

        // クリーンアップ
        for entry in entries.iter_mut() {
            unsafe {
                tree.remove(entry.as_mut());
            }
        }
    }

    #[test]
    fn test_ordering() {
        let mut tree: RBTree<TestAdapter> = RBTree::new();
        let keys = [50, 30, 70, 20, 40, 60, 80];
        let mut entries: Vec<Box<TestEntry>> = keys
            .iter()
            .map(|&k| Box::new(TestEntry::new(k, k as u32)))
            .collect();

        for entry in entries.iter_mut() {
            unsafe {
                tree.insert(entry.as_mut());
            }
        }

        // first は最小
        unsafe {
            assert_eq!((*tree.first().unwrap()).key, 20);
        }

        // last は最大
        unsafe {
            assert_eq!((*tree.last().unwrap()).key, 80);
        }

        // イテレータは昇順（ポインタを返すので unsafe でデリファレンス）
        let collected: Vec<u64> = tree.iter().map(|e| unsafe { (*e).key }).collect();
        assert_eq!(collected, vec![20, 30, 40, 50, 60, 70, 80]);

        // クリーンアップ
        for entry in entries.iter_mut() {
            unsafe {
                tree.remove(entry.as_mut());
            }
        }
    }

    #[test]
    fn test_duplicate_key() {
        let mut tree: RBTree<TestAdapter> = RBTree::new();
        let mut entry1 = Box::new(TestEntry::new(42, 100));
        let mut entry2 = Box::new(TestEntry::new(42, 200));

        unsafe {
            assert!(tree.insert(entry1.as_mut()));
            // 重複は拒否
            assert!(!tree.insert(entry2.as_mut()));
        }

        assert_eq!(tree.len(), 1);

        // クリーンアップ
        unsafe {
            tree.remove(entry1.as_mut());
        }
    }

    #[test]
    fn test_remove() {
        let mut tree: RBTree<TestAdapter> = RBTree::new();
        let mut entries: Vec<Box<TestEntry>> = (0..5)
            .map(|i| Box::new(TestEntry::new(i, i as u32)))
            .collect();

        for entry in entries.iter_mut() {
            unsafe {
                tree.insert(entry.as_mut());
            }
        }

        assert_eq!(tree.len(), 5);

        // 中間を削除
        unsafe {
            tree.remove(entries[2].as_mut());
        }
        assert_eq!(tree.len(), 4);
        assert!(tree.find(&2).is_none());

        // 最初を削除
        unsafe {
            tree.remove(entries[0].as_mut());
        }
        assert_eq!(tree.len(), 3);

        // 最後を削除
        unsafe {
            tree.remove(entries[4].as_mut());
        }
        assert_eq!(tree.len(), 2);

        // 残りを確認
        assert!(tree.find(&1).is_some());
        assert!(tree.find(&3).is_some());

        // クリーンアップ
        unsafe {
            tree.remove(entries[1].as_mut());
            tree.remove(entries[3].as_mut());
        }
    }
}
