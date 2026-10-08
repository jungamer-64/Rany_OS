//! Buddy free lists over one exclusively retained heap extent.
use super::HeapMemory;
use core::alloc::Layout;
use core::ptr::null_mut;

/// カーネルヒープ用のBuddy Allocator
#[derive(Debug)]
pub(super) struct BuddyHeapAllocator {
    /// ヒープの開始アドレス
    pub(super) heap_start: usize,
    /// ヒープのサイズ
    pub(super) heap_size: usize,
    /// Sole backing owner. Geometry fields below/above are immutable projections
    /// after admission; metadata cannot manufacture or repair this ownership.
    pub(super) backing: Option<HeapMemory>,
    /// Buddy システム: 各オーダーの空きブロックリスト
    /// オーダー0 = 最小ブロック (MIN_BLOCK_SIZE)
    /// オーダーN = 2^N * MIN_BLOCK_SIZE
    pub(super) free_lists: [Option<usize>; Self::MAX_ORDER + 1],
}

impl BuddyHeapAllocator {
    /// 最小ブロックサイズ（64バイト = キャッシュライン）
    pub(super) const MIN_BLOCK_SIZE: usize = 64;
    /// 最大オーダー（64バイト * 2^20 = 64MB最大ブロック）
    pub(super) const MAX_ORDER: usize = 20;

    pub(super) const fn new() -> Self {
        Self {
            heap_start: 0,
            heap_size: 0,
            backing: None,
            free_lists: [None; Self::MAX_ORDER + 1],
        }
    }

    /// 現在のアドレスに対するアラインメント対応ブロックオーダーを計算
    fn find_aligned_order(current: usize, end: usize) -> Option<(usize, usize)> {
        let remaining = end - current;
        if remaining < Self::MIN_BLOCK_SIZE {
            return None;
        }
        let mut order = Self::size_to_order(remaining).min(Self::MAX_ORDER);
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while order > 0 {
            let block_size = Self::order_to_size(order);
            if current % block_size == 0 && current + block_size <= end {
                break;
            }
            order -= 1;
        }
        Some((order, Self::order_to_size(order)))
    }

    /// ヒープを初期化
    pub(super) fn init(&mut self, memory: HeapMemory) -> Result<(), HeapMemory> {
        if self.backing.is_some() {
            return Err(memory);
        }
        let heap_start = memory.start();
        let heap_size = memory.size();
        self.heap_start = heap_start;
        self.heap_size = heap_size;
        self.backing = Some(memory);

        // 全てのフリーリストをクリア
        for list in self.free_lists.iter_mut() {
            *list = None;
        }

        // ヒープ全体を適切なオーダーのブロックとして登録
        // 各オーダーのブロックは自身のサイズでアラインされている必要がある
        let mut current = heap_start;
        let end = heap_start + heap_size;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while current < end {
            let (order, block_size) = match Self::find_aligned_order(current, end) {
                Some(v) => v,
                None => break,
            };

            // Order 0のアラインメントチェック（MIN_BLOCK_SIZE=64バイト）
            if current % block_size != 0 {
                // アラインメントを満たすまで進める
                let aligned = (current + block_size - 1) & !(block_size - 1);
                if aligned >= end {
                    break;
                }
                current = aligned;
                continue;
            }

            if current + block_size <= end {
                self.add_to_free_list(current, order);
                current += block_size;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// サイズから必要なオーダーを計算
    #[inline]
    fn size_to_order(size: usize) -> usize {
        let blocks = size.div_ceil(Self::MIN_BLOCK_SIZE);
        if blocks <= 1 {
            0
        } else {
            (usize::BITS - (blocks - 1).leading_zeros()) as usize
        }
    }

    /// オーダーからサイズを計算
    #[inline]
    const fn order_to_size(order: usize) -> usize {
        Self::MIN_BLOCK_SIZE << order
    }

    fn layout_order(layout: Layout) -> usize {
        Self::size_to_order(layout.size().max(layout.align()).max(Self::MIN_BLOCK_SIZE))
    }

    /// フリーリストにブロックを追加
    fn add_to_free_list(&mut self, addr: usize, order: usize) {
        // Security check: Range validation
        if addr < self.heap_start || addr >= self.heap_start + self.heap_size {
            crate::io::log::early_print("[BUD] WARN: add_to_free_list invalid addr=");
            crate::io::log::early_print_hex(addr as u64);
            crate::io::log::early_print(" order=");
            crate::io::log::early_print_dec(order as u64);
            crate::io::log::early_print(" heap=");
            crate::io::log::early_print_hex(self.heap_start as u64);
            crate::io::log::early_print("-");
            crate::io::log::early_print_hex((self.heap_start + self.heap_size) as u64);
            crate::io::log::early_print("\n");
            return; // graceful skip
        }

        // Security check: Alignment validation
        let block_size = Self::order_to_size(order);
        if addr % block_size != 0 {
            crate::io::log::early_print("[BUD] WARN: add_to_free_list unaligned addr=");
            crate::io::log::early_print_hex(addr as u64);
            crate::io::log::early_print(" order=");
            crate::io::log::early_print_dec(order as u64);
            crate::io::log::early_print("\n");
            return; // graceful skip
        }

        let old_head = self.free_lists[order].unwrap_or(0);

        // アドレスに次のフリーブロックへのポインタを格納
        let ptr_addr = addr as usize;

        // SAFETY: the lock exclusively owns this free block in backing RAM.
        // Its aligned header is initialized before the head is published.
        unsafe {
            core::ptr::write(ptr_addr as *mut usize, old_head);
        }
        self.free_lists[order] = Some(addr);
    }

    /// フリーリストからブロックを取得
    fn remove_from_free_list(&mut self, order: usize) -> Option<usize> {
        let addr = self.free_lists[order].take()?;

        let head_valid = addr >= self.heap_start
            && addr < self.heap_start + self.heap_size
            && addr % Self::MIN_BLOCK_SIZE == 0;
        if !head_valid {
            crate::io::log::early_print("[BUD] WARN: remove_from_free_list corrupt head=");
            crate::io::log::early_print_hex(addr as u64);
            crate::io::log::early_print(" order=");
            crate::io::log::early_print_dec(order as u64);
            crate::io::log::early_print("\n");
            self.free_lists[order] = None;
            return None;
        }

        // SAFETY: the free-list header was initialized on insertion, belongs
        // to retained backing RAM, and metadata access is exclusive under lock.
        let next = unsafe { core::ptr::read(addr as *const usize) };
        if next != 0 {
            let next_valid = next >= self.heap_start
                && next < self.heap_start + self.heap_size
                && next % Self::MIN_BLOCK_SIZE == 0;
            if !next_valid {
                crate::io::log::early_print("[BUD] WARN: remove_from_free_list corrupt next=");
                crate::io::log::early_print_hex(next as u64);
                crate::io::log::early_print(" at head=");
                crate::io::log::early_print_hex(addr as u64);
                crate::io::log::early_print(" order=");
                crate::io::log::early_print_dec(order as u64);
                crate::io::log::early_print("\n");
                self.free_lists[order] = None;
                return Some(addr);
            }
        }

        self.free_lists[order] = if next == 0 { None } else { Some(next) };
        Some(addr)
    }

    /// 特定アドレスのブロックをフリーリストから削除
    fn remove_specific(&mut self, addr: usize, order: usize) -> bool {
        let mut prev: Option<usize> = None;
        let mut current = self.free_lists[order];

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(curr_addr) = current {
            if curr_addr == addr {
                // 見つかった - リストから削除
                let next_ptr = curr_addr as usize;
                // SAFETY: linked free blocks have initialized usize headers,
                // and this allocator lock excludes simultaneous list mutation.
                let next = unsafe { core::ptr::read(next_ptr as *const usize) };
                let next_opt = if next == 0 { None } else { Some(next) };

                if let Some(prev_addr) = prev {
                    // SAFETY: prev_addr is an initialized free block reached
                    // under the same exclusive allocator lock.
                    unsafe {
                        core::ptr::write(prev_addr as *mut usize, next);
                    }
                } else {
                    self.free_lists[order] = next_opt;
                }
                return true;
            }
            prev = current;
            let next_ptr = curr_addr as *const usize;
            // SAFETY: current is a retained, initialized free-list header.
            let next = unsafe { core::ptr::read(next_ptr) };
            current = if next == 0 { None } else { Some(next) };
        }
        false
    }

    /// Cold observation under the same exclusive borrow as free-list mutation.
    /// A corrupt link/cycle is terminal rather than fabricated usable capacity.
    pub(super) fn free_bytes(&self) -> usize {
        let mut free = 0;
        let mut visited = 0;
        for order in 0..=Self::MAX_ORDER {
            let mut cursor = self.free_lists[order];
            // LOOP_PROOF: mode=condition; reason=The cursor advances through free blocks, with a finite backing-sized bound rejecting corrupt cycles.;
            while let Some(address) = cursor {
                visited += 1;
                let bytes = Self::order_to_size(order);
                assert!(visited <= self.heap_size / Self::MIN_BLOCK_SIZE);
                assert!(
                    address >= self.heap_start
                        && address
                            .checked_add(bytes)
                            .is_some_and(|end| end <= self.heap_start + self.heap_size)
                );
                assert_eq!(address % bytes, 0);
                free += bytes;
                // SAFETY: the retained backing and exclusive allocator borrow
                // preserve initialized headers within the validated free extent.
                let next = unsafe { (address as *const usize).read() };
                cursor = (next != 0).then_some(next);
            }
        }
        free
    }

    pub(super) fn allocate(&mut self, layout: Layout) -> *mut u8 {
        if self.backing.is_none() {
            return null_mut();
        }

        // アラインメント要求を満たすために、
        // size と align の両方を満たす最小のブロックを使用

        // 必要なサイズ: sizeとalignの大きい方（最低 MIN_BLOCK_SIZE）
        // Buddyアロケータでは、ブロックは常に2のべき乗サイズで、
        // 自身のサイズでアラインされているため、
        // align <= block_size を満たせばアラインメントも満たす
        let order = Self::layout_order(layout);

        if order > Self::MAX_ORDER {
            return null_mut();
        }

        // 要求オーダー以上の空きブロックを探す
        for current_order in order..=Self::MAX_ORDER {
            if let Some(block) = self.remove_from_free_list(current_order) {
                // 必要に応じて分割
                self.split_block(block, current_order, order);

                // Buddyブロックは自身のサイズでアラインされているため、
                // block_size >= align なら自動的にアラインメントを満たす
                return block as *mut u8;
            }
        }

        null_mut()
    }

    /// ブロックを目標オーダーまで分割
    fn split_block(&mut self, addr: usize, from_order: usize, to_order: usize) {
        let mut current_order = from_order;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while current_order > to_order {
            current_order -= 1;
            let buddy_addr = addr + Self::order_to_size(current_order);
            self.add_to_free_list(buddy_addr, current_order);
        }
    }

    /// Returns the capacity actually made reusable in this retained heap,
    /// including Buddy rounding. Invalid/non-admitted inputs publish no bytes.
    pub(super) fn deallocate(&mut self, ptr: *mut u8, layout: Layout) -> usize {
        if ptr.is_null() {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] deallocate: null or not init\n");
            return 0;
        }

        if self.backing.is_none() {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] deallocate: null or not init\n");
            return 0;
        }

        let order = Self::layout_order(layout);
        let addr = ptr as usize;

        if addr < self.heap_start || addr >= self.heap_start + self.heap_size {
            crate::io::log::early_print("[HEAP] ERROR: deallocate got invalid ptr!\n");
            return 0;
        }

        self.coalesce(addr, order);
        Self::order_to_size(order)
    }

    /// Buddyとの合体を反復的に試みる
    fn coalesce(&mut self, addr: usize, order: usize) {
        let mut current_addr = addr;
        let mut current_order = order;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while current_order < Self::MAX_ORDER {
            let buddy_addr = self.buddy_addr(current_addr, current_order);

            // Buddyがフリーリストにあるか確認
            if !self.remove_specific(buddy_addr, current_order) {
                break;
            }

            // 合体: 小さい方のアドレスを使用
            current_addr = current_addr.min(buddy_addr);
            current_order += 1;
        }

        self.add_to_free_list(current_addr, current_order);
    }

    /// Buddyのアドレスを計算
    #[inline]
    fn buddy_addr(&self, addr: usize, order: usize) -> usize {
        let block_size = Self::order_to_size(order);
        // Blocks are aligned to absolute addresses during admission, not to
        // the slab origin. XOR must use that same coordinate system.
        addr ^ block_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn buddy_coordinates_follow_absolute_alignment() {
        let allocator = BuddyHeapAllocator::new();
        assert_eq!(allocator.buddy_addr(0x14000, 6), 0x15000);
        assert_eq!(allocator.buddy_addr(0x15000, 6), 0x14000);
    }
}
