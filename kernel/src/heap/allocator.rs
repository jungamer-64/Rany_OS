//! Heap allocator implementation and bootstrap helpers.
#[path = "oom.rs"]
pub mod oom;

#[cfg(any(not(test), feature = "full_mm_tests"))]
#[path = "bootstrap.rs"]
mod bootstrap;
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub(crate) use bootstrap::{
    checked_store_usize, checked_volatile_write_usize, physical_memory_offset,
    set_physical_memory_offset,
};
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub use bootstrap::{
    ensure_global_heap_ready, free_memory_kb, heap_stats, init, is_initialized, total_memory_kb,
    used_memory_kb, verify_buddy_integrity,
};

use crate::sync::PoisonLock;
use alloc::vec::Vec;
use boot_proto::MemoryDescriptor;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::PhysAddr;

/// Test-mode volatile write stub (the real implementation is in ap_boot_reserve.rs).
#[cfg(all(test, not(feature = "full_mm_tests")))]
pub fn checked_volatile_write_usize(addr: usize, val: usize, _context: &str) {
    unsafe {
        core::ptr::write_volatile(addr as *mut usize, val);
    }
}

#[cfg(all(test, not(feature = "full_mm_tests")))]
pub fn checked_store_usize(addr: usize, val: usize, _context: &str) {
    unsafe {
        core::ptr::write_volatile(addr as *mut usize, val);
    }
}

#[cfg(feature = "qemu-test-export")]
static HEAP_DEALLOC_ENABLED: AtomicBool = AtomicBool::new(false);
#[cfg(not(feature = "qemu-test-export"))]
static HEAP_DEALLOC_ENABLED: AtomicBool = AtomicBool::new(true);

#[inline]
pub fn set_heap_deallocation_enabled(enabled: bool) {
    HEAP_DEALLOC_ENABLED.store(enabled, Ordering::Release);
}

#[inline]
fn heap_deallocation_enabled() -> bool {
    HEAP_DEALLOC_ENABLED.load(Ordering::Acquire)
}

const ALLOC_HEADER_MAGIC: u64 = 0x514f_5441_4d45_4d31;
const QUOTA_ALLOCATION_RACE_RETRY: usize = 3;
const ALLOC_OOM_RETRY: usize = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct AllocHeader {
    magic: u64,
    owner_domain: u64,
    charged_bytes: u64,
    raw_ptr: usize,
    raw_size: usize,
    raw_align: usize,
}

impl AllocHeader {
    const fn new(
        owner_domain: u64,
        charged_bytes: u64,
        raw_ptr: usize,
        raw_size: usize,
        raw_align: usize,
    ) -> Self {
        Self {
            magic: ALLOC_HEADER_MAGIC,
            owner_domain,
            charged_bytes,
            raw_ptr,
            raw_size,
            raw_align,
        }
    }

    fn matches_allocation(&self, header_addr: usize, min_user_offset: usize) -> bool {
        self.magic == ALLOC_HEADER_MAGIC
            && self.raw_ptr == header_addr
            && self.raw_size >= min_user_offset
            && self.raw_align != 0
            && self.raw_align.is_power_of_two()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotaChargeOutcome {
    Charged,
    Exceeded,
    Retry,
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
#[inline]
fn current_allocation_domain() -> crate::domain::DomainId {
    crate::domain::current_domain()
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
#[inline]
fn current_allocation_domain() -> crate::domain::DomainId {
    crate::domain::DomainId::KERNEL
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
#[inline]
fn quota_try_charge(domain: crate::domain::DomainId, bytes: u64) -> QuotaChargeOutcome {
    match crate::domain::quota::quota_manager().try_allocate_memory(domain, bytes) {
        Ok(()) => QuotaChargeOutcome::Charged,
        Err(crate::domain::quota::QuotaError::AllocationRace) => QuotaChargeOutcome::Retry,
        Err(_) => QuotaChargeOutcome::Exceeded,
    }
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
#[inline]
fn quota_try_charge(_domain: crate::domain::DomainId, _bytes: u64) -> QuotaChargeOutcome {
    QuotaChargeOutcome::Charged
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
#[inline]
fn quota_uncharge(domain: crate::domain::DomainId, bytes: u64) {
    crate::domain::quota::quota_manager().deallocate_memory(domain, bytes);
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
#[inline]
fn quota_uncharge(_domain: crate::domain::DomainId, _bytes: u64) {}

// ============================================================================
// Buddy-Based Kernel Heap Allocator
// 設計理念: O(log n)割り当てを保証し、<100ns per allocation を達成
// ============================================================================

/// カーネルヒープ用のBuddy Allocator
/// linked_list_allocator (O(n)) の代わりに使用
#[derive(Debug)]
struct BuddyHeapAllocator {
    /// ヒープの開始アドレス
    heap_start: usize,
    /// ヒープのサイズ
    heap_size: usize,
    /// 初期化済みフラグ
    initialized: bool,
    /// Buddy システム: 各オーダーの空きブロックリスト
    /// オーダー0 = 最小ブロック (MIN_BLOCK_SIZE)
    /// オーダーN = 2^N * MIN_BLOCK_SIZE
    free_lists: [Option<usize>; Self::MAX_ORDER + 1],
}

impl BuddyHeapAllocator {
    /// 最小ブロックサイズ（64バイト = キャッシュライン）
    const MIN_BLOCK_SIZE: usize = 64;
    /// 最大オーダー（64バイト * 2^20 = 64MB最大ブロック）
    const MAX_ORDER: usize = 20;

    const fn new() -> Self {
        Self {
            heap_start: 0,
            heap_size: 0,
            initialized: false,
            free_lists: [None; Self::MAX_ORDER + 1],
        }
    }

    /// Recover from metadata bit-flips where only `initialized` became false
    /// while heap geometry is already configured.
    #[inline]
    fn ensure_initialized(&mut self) -> bool {
        if self.initialized {
            return true;
        }
        if self.heap_start != 0 && self.heap_size != 0 {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] repaired initialized flag\n");
            self.initialized = true;
            return true;
        }
        false
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
    unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        crate::io::log::early_print("[BUD] init\n");
        self.heap_start = heap_start;
        self.heap_size = heap_size;
        self.initialized = true;

        crate::io::log::early_print("[BUD] clear\n");
        // 全てのフリーリストをクリア
        for list in self.free_lists.iter_mut() {
            *list = None;
        }

        crate::io::log::early_print("[BUD] loop\n");
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
                crate::io::log::early_print("[BUD] add\n");
                self.add_to_free_list(current, order);
                current += block_size;
            } else {
                break;
            }
        }
        crate::io::log::early_print("[BUD] done\n");
    }

    /// サイズから必要なオーダーを計算
    #[inline]
    fn size_to_order(size: usize) -> usize {
        let blocks = (size + Self::MIN_BLOCK_SIZE - 1) / Self::MIN_BLOCK_SIZE;
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

    /// フリーリストにブロックを追加
    fn add_to_free_list(&mut self, addr: usize, order: usize) {
        // Security check: Range validation
        if addr < self.heap_start || addr >= self.heap_start.saturating_add(HEAP_SIZE) {
            crate::io::log::early_print("[BUD] WARN: add_to_free_list invalid addr=");
            crate::io::log::early_print_hex(addr as u64);
            crate::io::log::early_print(" order=");
            crate::io::log::early_print_dec(order as u64);
            crate::io::log::early_print(" heap=");
            crate::io::log::early_print_hex(self.heap_start as u64);
            crate::io::log::early_print("-");
            crate::io::log::early_print_hex((self.heap_start + HEAP_SIZE) as u64);
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

        checked_volatile_write_usize(ptr_addr, old_head, "BUD add_to_free_list");
        self.free_lists[order] = Some(addr);
    }

    /// フリーリストからブロックを取得
    fn remove_from_free_list(&mut self, order: usize) -> Option<usize> {
        let addr = self.free_lists[order].take()?;

        let head_valid = addr >= self.heap_start
            && addr < self.heap_start.saturating_add(HEAP_SIZE)
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

        let next = crate::io::mmio::volatile_read::<usize>(addr);
        if next != 0 {
            let next_valid = next >= self.heap_start
                && next < self.heap_start.saturating_add(HEAP_SIZE)
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
                let next = crate::io::mmio::volatile_read::<usize>(next_ptr);
                let next_opt = if next == 0 { None } else { Some(next) };

                if let Some(prev_addr) = prev {
                    checked_volatile_write_usize(prev_addr, next, "BUD remove_specific prev->next");
                } else {
                    self.free_lists[order] = next_opt;
                }
                return true;
            }
            prev = current;
            let next_ptr = curr_addr as *const usize;
            let next = unsafe { *next_ptr };
            current = if next == 0 { None } else { Some(next) };
        }
        false
    }

    /// メモリを割り当て（O(log n)）
    fn allocate(&mut self, layout: Layout) -> *mut u8 {
        if !self.ensure_initialized() {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] allocate: not initialized\n");
            return null_mut();
        }

        // アラインメント要求を満たすために、
        // size と align の両方を満たす最小のブロックを使用
        let align = layout.align();
        let size = layout.size();

        // 必要なサイズ: sizeとalignの大きい方（最低 MIN_BLOCK_SIZE）
        // Buddyアロケータでは、ブロックは常に2のべき乗サイズで、
        // 自身のサイズでアラインされているため、
        // align <= block_size を満たせばアラインメントも満たす
        let alloc_size = size.max(align).max(Self::MIN_BLOCK_SIZE);
        let order = Self::size_to_order(alloc_size);

        if order > Self::MAX_ORDER {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] allocate: order too large\n");
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

        #[cfg(debug_assertions)]
        crate::io::log::early_print("[HEAP] allocate: out of memory\n");
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

    /// メモリを解放（O(log n)）
    fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] deallocate: null or not init\n");
            return;
        }

        // qemu full-boot export profiles keep deallocation disabled during the
        // earliest boot phase; runtime code re-enables it once heap metadata
        // stabilization is complete.
        if !heap_deallocation_enabled() {
            let _ = layout;
            return;
        }

        if !self.ensure_initialized() {
            #[cfg(debug_assertions)]
            crate::io::log::early_print("[HEAP] deallocate: null or not init\n");
            return;
        }

        let size = layout.size().max(layout.align()).max(Self::MIN_BLOCK_SIZE);
        let order = Self::size_to_order(size);
        let addr = ptr as usize;

        if addr < self.heap_start || addr >= self.heap_start + HEAP_SIZE {
            crate::io::log::early_print("[HEAP] ERROR: deallocate got invalid ptr!\n");
        }

        self.coalesce(addr, order);
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
        let offset = addr - self.heap_start;
        let block_size = Self::order_to_size(order);
        self.heap_start + (offset ^ block_size)
    }
}

/// スレッドセーフなグローバルアロケータラッパー
pub struct LockedBuddyHeap(PoisonLock<BuddyHeapAllocator>);

impl LockedBuddyHeap {
    pub const fn new() -> Self {
        Self(PoisonLock::new(BuddyHeapAllocator::new()))
    }

    /// Check if the heap allocator is initialized
    pub fn is_initialized(&self) -> Option<bool> {
        self.0.lock().ok().map(|g| g.initialized)
    }
}

unsafe impl GlobalAlloc for LockedBuddyHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let _align = layout.align();

        // Log suspicious allocations
        if size == 0 {
            crate::io::log::early_print("[ALLOC] WARNING: alloc called with size 0\n");
        }

        let owner = current_allocation_domain();
        let requested_bytes = layout.size() as u64;
        let needs_quota = owner != crate::domain::DomainId::KERNEL;

        let (header_plus_payload, user_offset) = match Layout::new::<AllocHeader>().extend(layout) {
            Ok((l, off)) => (l.pad_to_align(), off),
            Err(_) => return null_mut(),
        };

        let mut retry = 0usize;
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let mut charged = false;
            if needs_quota {
                let mut quota_result = QuotaChargeOutcome::Exceeded;
                for _ in 0..=QUOTA_ALLOCATION_RACE_RETRY {
                    quota_result = quota_try_charge(owner, requested_bytes);
                    if quota_result != QuotaChargeOutcome::Retry {
                        break;
                    }
                }
                if quota_result != QuotaChargeOutcome::Charged {
                    return null_mut();
                }
                charged = true;
            }

            let raw_ptr = match self.0.lock() {
                Ok(mut guard) => {
                    let p = guard.allocate(header_plus_payload);
                    if p.is_null() {
                        Self::dump_alloc_failure(&*guard, header_plus_payload, size);
                    }
                    p
                }
                Err(poisoned) => {
                    crate::io::log::early_print("[ALLOC] Poisoned lock\n");
                    Self::dump_poisoned_state(poisoned.get_ref());
                    if charged {
                        quota_uncharge(owner, requested_bytes);
                    }
                    return null_mut();
                }
            };

            if !raw_ptr.is_null() {
                let raw_addr = raw_ptr as usize;
                let header_ptr = raw_ptr as *mut AllocHeader;
                core::ptr::write(
                    header_ptr,
                    AllocHeader::new(
                        owner.as_u64(),
                        if needs_quota { requested_bytes } else { 0 },
                        raw_addr,
                        header_plus_payload.size(),
                        header_plus_payload.align(),
                    ),
                );
                crate::profiler::record_kernel_heap_allocation();
                return raw_ptr.add(user_offset);
            }

            if charged {
                quota_uncharge(owner, requested_bytes);
            }

            if retry >= ALLOC_OOM_RETRY || !crate::heap::oom::try_free_memory() {
                return null_mut();
            }
            retry = retry.saturating_add(1);
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        let user_offset = match Layout::new::<AllocHeader>().extend(layout) {
            Ok((_, off)) => off,
            Err(_) => {
                if let Ok(mut guard) = self.0.lock() {
                    guard.deallocate(ptr, layout);
                }
                return;
            }
        };

        if user_offset <= ptr as usize {
            let header_ptr = ptr.wrapping_sub(user_offset) as *const AllocHeader;
            let header_addr = header_ptr as usize;
            let header = core::ptr::read_unaligned(header_ptr);

            if header.matches_allocation(header_addr, user_offset) {
                if header.charged_bytes > 0 {
                    quota_uncharge(
                        crate::domain::DomainId::new(header.owner_domain),
                        header.charged_bytes,
                    );
                }

                if let Ok(raw_layout) = Layout::from_size_align(header.raw_size, header.raw_align) {
                    if let Ok(mut guard) = self.0.lock() {
                        guard.deallocate(header.raw_ptr as *mut u8, raw_layout);
                        return;
                    }
                }
            }
        }

        if let Ok(mut guard) = self.0.lock() {
            guard.deallocate(ptr, layout);
        }
    }
}

impl LockedBuddyHeap {
    fn dump_alloc_failure(guard: &BuddyHeapAllocator, layout: Layout, size: usize) {
        crate::io::log::early_print("[ALLOC] FAILED size=");
        let mut s = size;
        let mut buf = [0u8; 20];
        let mut i = 19;
        if s == 0 {
            buf[i] = b'0';
            i -= 1;
        } else {
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while s > 0 {
                buf[i] = b'0' + (s % 10) as u8;
                s /= 10;
                i -= 1;
            }
        }
        for k in (i + 1)..20 {
            crate::io::log::early_print_char(buf[k]);
        }

        crate::io::log::early_print(" align=");
        crate::io::log::early_print_dec(layout.align() as u64);
        crate::io::log::early_print("\n");

        crate::io::log::early_print("[ALLOC] guard.initialized=");
        crate::io::log::early_print_dec(if guard.initialized { 1 } else { 0 });
        crate::io::log::early_print("\n");

        crate::io::log::early_print("[ALLOC] Dumping free_lists:\n");
        for i in 0..=BuddyHeapAllocator::MAX_ORDER {
            crate::io::log::early_print("[ALLOC] free_lists[");
            crate::io::log::early_print_dec(i as u64);
            crate::io::log::early_print("] = ");
            let head = guard.free_lists[i].unwrap_or(0);
            crate::io::log::early_print_hex(head as u64);
            crate::io::log::early_print("\n");
        }

        crate::io::log::early_print("[ALLOC] Backtrace:\n");
        let bt = crate::unwind::Backtrace::capture();
        for entry in bt.iter() {
            crate::io::log::early_print("[ALLOC][BT] IP=");
            crate::io::log::early_print_hex(entry.frame.instruction_pointer as u64);
            crate::io::log::early_print("\n");
        }
    }

    fn dump_poisoned_state(guard_ref: &crate::sync::PoisonLockGuard<BuddyHeapAllocator>) {
        crate::io::log::early_print("[ALLOC] Dumping buddy free_lists (poisoned)\n");
        let alloc_ref: &BuddyHeapAllocator = &*guard_ref;
        for i in 0..=BuddyHeapAllocator::MAX_ORDER {
            crate::io::log::early_print("[ALLOC] free_lists[");
            crate::io::log::early_print_dec(i as u64);
            crate::io::log::early_print("] = ");
            let head = alloc_ref.free_lists[i].unwrap_or(0);
            crate::io::log::early_print_hex(head as u64);
            crate::io::log::early_print("\n");
        }
    }
}

/// グローバルヒープアロケータ（Buddy Allocatorベース）
/// 設計理念: O(log n)割り当てで <100ns を達成
#[cfg(any(
    not(feature = "full_mm_tests"),
    all(feature = "full_mm_tests", not(test))
))]
pub static ALLOCATOR: LockedBuddyHeap = LockedBuddyHeap::new();

#[cfg(all(feature = "full_mm_tests", test))]
pub use crate::ALLOCATOR;

/// ヒープのサイズ
///
/// PF passthrough with VT-d now builds substantially larger IOMMU metadata and
/// firmware-page working sets than the original single-driver boot path.
pub const HEAP_SIZE: usize = 256 * 1024 * 1024; // 256 MiB

/// Exchange Heap のサイズ
/// NOTE: ネットワーク Mempool (1024 × 4KB = 4MiB) + RRef IPC + その他のため
/// 十分な容量を確保する
pub const EXCHANGE_HEAP_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
const EFI_PAGE_SIZE: u64 = 4096;
const EFI_MEMORY_TYPE_BOOT_SERVICES_CODE: u32 = 3;
const EFI_MEMORY_TYPE_BOOT_SERVICES_DATA: u32 = 4;
const EFI_MEMORY_TYPE_CONVENTIONAL: u32 = 7;
const MIN_USABLE_PHYS_ADDR: u64 = 0x100_0000; // 16 MiB

/// ヒープの開始アドレスを計算（ランタイム）
/// 物理メモリ16MBをPhysical Memory Offsetでマップした仮想アドレス
#[inline]
fn heap_start() -> u64 {
    physical_memory_offset() + 0x100_0000
}

/// Exchange Heap の開始アドレスを計算（ランタイム）
///
/// NOTE: place the Exchange Heap after the global heap to avoid overlap
/// with the main kernel heap (see bugfix for overlapping regions).
#[inline]
pub(crate) fn exchange_heap_start() -> u64 {
    // heap_start() + HEAP_SIZE (no overlap)
    heap_start().saturating_add(HEAP_SIZE as u64)
}

/// メモリサブシステム初期化フラグ
static MEMORY_INITIALIZED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

fn is_usable_efi_memory_type(ty: u32) -> bool {
    ty == EFI_MEMORY_TYPE_CONVENTIONAL
        || ty == EFI_MEMORY_TYPE_BOOT_SERVICES_CODE
        || ty == EFI_MEMORY_TYPE_BOOT_SERVICES_DATA
}

/// Validate a memory descriptor and return (clamped_start, end) if usable.
fn validate_usable_descriptor(desc: &MemoryDescriptor, min_addr: u64) -> Option<(u64, u64)> {
    if desc.page_count == 0 {
        return None;
    }
    let size = desc.page_count.checked_mul(EFI_PAGE_SIZE)?;
    let start = desc.phys_start;
    let end = start.checked_add(size)?;
    let start = start.max(min_addr);
    if end <= start {
        return None;
    }
    Some((start, end))
}

fn get_boot_memory_regions(memory_map: &[MemoryDescriptor]) -> Vec<(PhysAddr, u64)> {
    let mut regions = Vec::new();
    if memory_map.is_empty() {
        return regions;
    }

    for desc in memory_map {
        if !is_usable_efi_memory_type(desc.r#type) {
            continue;
        }
        if let Some((start, end)) = validate_usable_descriptor(desc, MIN_USABLE_PHYS_ADDR) {
            regions.push((PhysAddr::new(start), end - start));
        }
    }

    regions
}

fn subtract_from_region(
    start: u64,
    end: u64,
    reserved_start: u64,
    reserved_end: u64,
    filtered: &mut Vec<(PhysAddr, u64)>,
) {
    if reserved_end <= start || reserved_start >= end {
        filtered.push((PhysAddr::new(start), end - start));
        return;
    }
    if start < reserved_start {
        filtered.push((PhysAddr::new(start), reserved_start - start));
    }
    if end > reserved_end {
        filtered.push((PhysAddr::new(reserved_end), end - reserved_end));
    }
}

fn subtract_reserved_range(
    regions: Vec<(PhysAddr, u64)>,
    reserved_start: u64,
    reserved_size: u64,
) -> Vec<(PhysAddr, u64)> {
    if reserved_size == 0 {
        return regions;
    }
    let reserved_end = reserved_start.saturating_add(reserved_size);
    let mut filtered = Vec::with_capacity(regions.len());

    for (addr, size) in regions {
        let start = addr.as_u64();
        let end = start.saturating_add(size);
        subtract_from_region(start, end, reserved_start, reserved_end, &mut filtered);
    }

    filtered
}

fn reserve_bootstrap_heaps(regions: Vec<(PhysAddr, u64)>) -> Vec<(PhysAddr, u64)> {
    let hhdm = physical_memory_offset();
    let heap_phys = heap_start().saturating_sub(hhdm);
    let exchange_phys = exchange_heap_start().saturating_sub(hhdm);

    // Reserve and remove bootstrap heap regions (global heap and exchange heap)
    let regions = subtract_reserved_range(regions, heap_phys, HEAP_SIZE as u64);
    let mut regions = subtract_reserved_range(regions, exchange_phys, EXCHANGE_HEAP_SIZE as u64);

    // Reserve kernel image (.text/.rodata/.data/.bss) so PMM never hands out
    // frames that back static kernel state (e.g. global allocator metadata).
    if let Some((kernel_start, kernel_end)) = kernel_phys_range() {
        let kernel_size = kernel_end.saturating_sub(kernel_start);
        regions = subtract_reserved_range(regions, kernel_start, kernel_size);
    }

    regions
}

#[cfg(not(test))]
fn kernel_phys_range() -> Option<(u64, u64)> {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }

    let (kernel_start_virt, kernel_end_virt) = unsafe {
        (
            crate::mm::virt::higher_half::VirtAddr::new(&__kernel_start as *const u8 as u64),
            crate::mm::virt::higher_half::VirtAddr::new(&__kernel_end as *const u8 as u64),
        )
    };
    if kernel_end_virt.as_u64() <= kernel_start_virt.as_u64() {
        return None;
    }

    let kernel_start_phys = crate::mm::virt::higher_half::global_translate(kernel_start_virt)
        .map(|p| p.as_u64())
        .or_else(|| addr_to_phys(kernel_start_virt.as_u64()))?;

    let kernel_last_virt =
        crate::mm::virt::higher_half::VirtAddr::new(kernel_end_virt.as_u64().saturating_sub(1));
    let kernel_last_phys = crate::mm::virt::higher_half::global_translate(kernel_last_virt)
        .map(|p| p.as_u64())
        .or_else(|| addr_to_phys(kernel_last_virt.as_u64()))?;
    let kernel_end_phys = kernel_last_phys.saturating_add(1);

    if kernel_end_phys <= kernel_start_phys {
        return None;
    }

    Some((kernel_start_phys, kernel_end_phys))
}

#[cfg(test)]
fn kernel_phys_range() -> Option<(u64, u64)> {
    None
}

fn hhdm_ptr_to_phys(ptr: u64) -> Option<u64> {
    if ptr == 0 {
        return None;
    }
    let hhdm = physical_memory_offset();
    if ptr < hhdm {
        return None;
    }
    Some(ptr - hhdm)
}

fn addr_to_phys(addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let hhdm = physical_memory_offset();
    if addr >= hhdm {
        Some(addr - hhdm)
    } else {
        Some(addr)
    }
}

/// Subtract a reserved range if address is valid and size is non-zero.
fn subtract_if_valid(
    regions: Vec<(PhysAddr, u64)>,
    phys: Option<u64>,
    size: u64,
) -> Vec<(PhysAddr, u64)> {
    match phys {
        Some(p) if size > 0 => subtract_reserved_range(regions, p, size),
        _ => regions,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
