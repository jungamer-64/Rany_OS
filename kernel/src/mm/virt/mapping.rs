// ============================================================================
// src/mm/mapping.rs - SAS/SPL Linear Memory Mapping
// ============================================================================
use x86_64::{PhysAddr, VirtAddr};

/// Retains a device aperture already installed in the permanent direct map.
///
/// # Safety
/// The platform resource owner must reserve the physical range for this device
/// (never allocator RAM), establish the device's effective cache attributes,
/// and exclude conflicting register ownership. The direct-map entries must not
/// be unmapped or repurposed during the returned capability's lifetime.
///
/// # Errors
/// Rejects empty/overflowing ranges and any page not translated to the expected
/// physical page. This operation does not modify page tables or access hardware.
pub(crate) unsafe fn retain_device_registers(
    physical: PhysAddr,
    length: usize,
) -> Result<hal::MappedMmio, super::higher_half::MapError> {
    use super::higher_half::{MapError, VirtAddr as PageVirtAddr, global_translate};

    if length == 0 || length > isize::MAX as usize {
        return Err(MapError::InvalidAddress);
    }
    let length_u64 = u64::try_from(length).map_err(|_| MapError::InvalidAddress)?;
    let physical_start = physical.as_u64();
    let last_physical = physical_start
        .checked_add(length_u64 - 1)
        .ok_or(MapError::InvalidAddress)?;
    PhysAddr::try_new(last_physical).map_err(|_| MapError::InvalidAddress)?;
    let offset = physical_memory_offset();
    let virtual_start = physical_start
        .checked_add(offset)
        .ok_or(MapError::InvalidAddress)?;
    let virtual_last = last_physical
        .checked_add(offset)
        .ok_or(MapError::InvalidAddress)?;
    VirtAddr::try_new(virtual_start).map_err(|_| MapError::InvalidAddress)?;
    VirtAddr::try_new(virtual_last).map_err(|_| MapError::InvalidAddress)?;
    let first_page = physical_start & !4095;
    let last_page = last_physical & !4095;
    let page_count = (last_page - first_page) / 4096 + 1;
    for page in 0..page_count {
        let expected = first_page + page * 4096;
        let virtual_page = expected
            .checked_add(offset)
            .ok_or(MapError::InvalidAddress)?;
        let translated =
            global_translate(PageVirtAddr::new(virtual_page)).ok_or(MapError::NotMapped)?;
        if translated.as_u64() != expected {
            return Err(MapError::InvalidAddress);
        }
    }
    let base = usize::try_from(virtual_start).map_err(|_| MapError::InvalidAddress)?;
    // SAFETY: all pages were checked above. The caller reserves the device
    // resource and guarantees permanent direct-map lifetime/cache semantics.
    // This mapping has no per-handle unmap: the kernel page-table owner retains
    // it beyond every capability, including when the final Arc is dropped.
    unsafe { hal::MappedMmio::from_raw_parts(alloc::sync::Arc::new(()), base, length) }
        .map_err(|_| MapError::InvalidAddress)
}

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
