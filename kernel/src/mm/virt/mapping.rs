// ============================================================================
// src/mm/mapping.rs - SAS/SPL Linear Memory Mapping
// ============================================================================
#![allow(dead_code)]

use x86_64::{PhysAddr, VirtAddr};

/// 設計書 1.3: Higher Half Kernel Base (SAS)
/// すべての物理メモリはこのオフセット以降にリニアマッピングされる
#[inline(always)]
pub fn physical_memory_offset() -> u64 {
    crate::mm::virt::higher_half::physical_memory_offset()
}

/// 物理アドレス -> 仮想アドレスへの変換 (O(1))
/// 設計書 5.1: ページテーブルウォークを排除した高速変換
#[inline(always)]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + physical_memory_offset())
}

/// 仮想アドレス -> 物理アドレスへの変換 (O(1))
#[inline(always)]
pub fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    PhysAddr::new(virt.as_u64() - physical_memory_offset())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_address_conversion() {
        crate::mm::virt::higher_half::init(0xFFFF_8000_0000_0000);
        let phys = PhysAddr::new(0x1000);
        let virt = phys_to_virt(phys);
        let phys2 = virt_to_phys(virt);
        assert_eq!(phys, phys2);
    }
}
