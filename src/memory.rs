// ============================================================================
// src/memory.rs - SAS Memory Management with Linear Mapping
// ============================================================================
use x86_64::{PhysAddr, VirtAddr};
use linked_list_allocator::LockedHeap;

/// 設計書 1.3: Higher Half Kernel Base (SAS)
pub const PHYSICAL_MEMORY_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// グローバルヒープアロケータ
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// ヒープの開始アドレスとサイズ
pub const HEAP_START: u64 = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

/// メモリサブシステムの初期化
pub fn init() {
    // ヒープの初期化
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
}

/// 物理アドレス -> 仮想アドレスへの変換 (O(1))
#[inline(always)]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + PHYSICAL_MEMORY_OFFSET)
}

/// 仮想アドレス -> 物理アドレスへの変換 (O(1))
#[inline(always)]
pub fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    PhysAddr::new(virt.as_u64() - PHYSICAL_MEMORY_OFFSET)
}
