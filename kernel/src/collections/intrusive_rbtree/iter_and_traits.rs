use super::*;


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
    pub(crate) current: Option<*mut RBLink>,
    pub(crate) _marker: PhantomData<A>,
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
// QEMU smoke tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
#[path = "qemu_tests.rs"]
pub mod qemu_tests;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

