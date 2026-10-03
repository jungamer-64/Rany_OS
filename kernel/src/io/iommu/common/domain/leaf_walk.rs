//! Leaf-size-aware traversal and metadata admission bounds. These operations
//! borrow table storage without releasing RAM or publishing a translation.
use crate::io::iommu::common::tables::{PT_ENTRIES, SlPte, phys_to_virt_usize};
use crate::io::iommu::types::{IommuError, PteFormat};

use crate::io::iommu::common::dma::page_table_pool::inc_ref;
use crate::io::iommu::common::tables::PageTableScope;
use crate::io::iommu::vendors::amd::tables::AmdPte;
use alloc::vec::Vec;

/// Fully admitted leaf writes. Its scopes keep attached intermediate RAM
/// quarantinable until metadata admission succeeds. No leaf contains a DMA data
/// address until this value is consumed by commit under the paging lock.
pub(super) struct PreparedDmaRange<'a> {
    pub(super) leaves: Vec<PreparedLeaf>,
    pub(super) scopes: Vec<PageTableScope<'a>>,
}
pub(super) struct PreparedLeaf {
    pub(super) table: *mut SlPte,
    pub(super) table_phys: u64,
    pub(super) index: usize,
    pub(super) count: usize,
    pub(super) level: u8,
    pub(super) phys: u64,
}
impl PreparedDmaRange<'_> {
    /// # Safety
    /// The caller holds the same paging lock as preparation. Metadata admission
    /// succeeded, and all table owners and conflict checks remain unchanged.
    pub(super) unsafe fn commit(self, format: PteFormat, read: bool, write: bool) {
        for scope in self.scopes {
            scope.commit();
        }
        for leaf in self.leaves {
            for offset in 0..leaf.count {
                let phys = leaf.phys + offset as u64 * 4096;
                let entry = match format {
                    PteFormat::Amd => SlPte(AmdPte::mapping(phys, read, write, 0).0),
                    PteFormat::Intel => match leaf.level {
                        3 => SlPte::super_page_1gb(phys, read, write),
                        2 => SlPte::super_page_2mb(phys, read, write),
                        _ => SlPte::mapping(phys, read, write),
                    },
                };
                // SAFETY: preparation retained and conflict-checked this entire leaf run.
                unsafe { leaf.table.add(leaf.index + offset).write(entry) };
                inc_ref(leaf.table_phys);
            }
        }
    }
}

/// Observe one complete leaf run without mutation.
/// # Safety
/// The caller retains every table reachable from `root` through the walk and
/// excludes concurrent hierarchy mutation. `levels` describes that root, and
/// the remaining range is nonzero, page-aligned and address-width validated.
pub(super) unsafe fn unmap_leaf_run(
    root: *const SlPte,
    levels: u8,
    format: PteFormat,
    iova: u64,
    remaining: u64,
) -> Result<(u64, u8), IommuError> {
    let mut table = root;
    let mut level = levels;
    // LOOP_PROOF: mode=condition; reason=Each table descent reduces level and a present leaf or an error returns before level can reach zero.;
    while level > 0 {
        let index = ((iova >> (12 + 9 * (level - 1))) & 511) as usize;
        // SAFETY: the paging lock retains this live table and index is below PT_ENTRIES.
        let entry = unsafe { *table.add(index) };
        if !entry.is_present() {
            return Err(IommuError::NotMapped);
        }
        if (2..=3).contains(&level) && entry.is_super_page(format) {
            let bytes = 1u64 << (12 + 9 * (level - 1));
            if iova % bytes != 0 || remaining < bytes {
                return Err(IommuError::InvalidAlignment);
            }
            return Ok((bytes, level));
        }
        if level == 1 {
            let pages = core::cmp::min(remaining / 4096, (PT_ENTRIES - index) as u64) as usize;
            for offset in 0..pages {
                // SAFETY: the retained table contains PT_ENTRIES entries.
                if !unsafe { *table.add(index + offset) }.is_present() {
                    return Err(IommuError::NotMapped);
                }
            }
            return Ok((pages as u64 * 4096, 1));
        }
        table = phys_to_virt_usize(entry.phys_addr()) as *const SlPte;
        level -= 1;
    }
    Err(IommuError::HardwareError)
}

/// Counts every non-root table window touched by a validated half-open range.
/// Four extra slots admit a failed path construction whose scoped rollback may
/// detach ancestors before the already mapped prefix is removed.
pub(super) fn retirement_table_bound(
    iova: u64,
    size: u64,
    levels: u8,
) -> Result<usize, IommuError> {
    if size == 0 || (iova | size) & 4095 != 0 {
        return Err(IommuError::InvalidAlignment);
    }
    if !(2..=5).contains(&levels) {
        return Err(IommuError::InvalidAddress);
    }
    let last = iova
        .checked_add(size)
        .and_then(|end| end.checked_sub(1))
        .ok_or(IommuError::InvalidAddress)?;
    let mut count = 4usize;
    for level in 1..levels {
        let shift = 12 + 9 * level;
        let windows = (last >> shift) - (iova >> shift) + 1;
        count = count
            .checked_add(usize::try_from(windows).map_err(|_| IommuError::InvalidAddress)?)
            .ok_or(IommuError::InvalidAddress)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[repr(C, align(4096))]
    struct Table([SlPte; PT_ENTRIES]);

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn prepared_commit_publishes_mixed_leaf_sizes_without_allocation() {
        use crate::io::iommu::common::dma::page_table_pool::{PageTablePool, get_ref_count};
        let pool = PageTablePool::new(1, 3);
        for format in [PteFormat::Intel, PteFormat::Amd] {
            let pt = pool.acquire(Some(0)).unwrap();
            let pd = pool.acquire(Some(0)).unwrap();
            let pdpt = pool.acquire(Some(0)).unwrap();
            let prepared = PreparedDmaRange {
                leaves: alloc::vec![
                    PreparedLeaf {
                        table: pt.ptr().as_ptr(),
                        table_phys: pt.phys(),
                        index: 510,
                        count: 2,
                        level: 1,
                        phys: 0x1000
                    },
                    PreparedLeaf {
                        table: pd.ptr().as_ptr(),
                        table_phys: pd.phys(),
                        index: 3,
                        count: 1,
                        level: 2,
                        phys: 0x200000
                    },
                    PreparedLeaf {
                        table: pdpt.ptr().as_ptr(),
                        table_phys: pdpt.phys(),
                        index: 4,
                        count: 1,
                        level: 3,
                        phys: 0x40000000
                    },
                ],
                scopes: Vec::new(),
            };
            // SAFETY: these retained, unpublished fixtures are exclusively
            // borrowed and every prepared index/run is within its table.
            unsafe {
                assert_eq!((*pt.ptr().as_ptr().add(510)).0, 0);
                assert_eq!((*pd.ptr().as_ptr().add(3)).0, 0);
                prepared.commit(format, true, false);
                assert_eq!((*pt.ptr().as_ptr().add(510)).phys_addr(), 0x1000);
                assert_eq!((*pt.ptr().as_ptr().add(511)).phys_addr(), 0x2000);
                assert_eq!((*pd.ptr().as_ptr().add(3)).phys_addr(), 0x200000);
                assert_eq!((*pdpt.ptr().as_ptr().add(4)).phys_addr(), 0x40000000);
                assert!((*pd.ptr().as_ptr().add(3)).is_super_page(format));
                let leaf = (*pt.ptr().as_ptr().add(510)).0;
                match format {
                    PteFormat::Intel => {
                        assert_eq!(leaf & (SlPte::READ | SlPte::WRITE), SlPte::READ)
                    }
                    PteFormat::Amd => {
                        assert_eq!(leaf & (AmdPte::READ | AmdPte::WRITE), AmdPte::READ)
                    }
                }
            }
            assert_eq!(get_ref_count(pt.phys()), 2);
            assert_eq!(get_ref_count(pd.phys()), 1);
            assert_eq!(get_ref_count(pdpt.phys()), 1);
            // No hardware context ever acquired these fixture roots.
            drop((pt, pd, pdpt));
        }
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn leaf_walk_rejects_partial_huge_pages_and_preserves_entries() {
        for format in [PteFormat::Intel, PteFormat::Amd] {
            let mut root = alloc::boxed::Box::new(Table([SlPte::new(); PT_ENTRIES]));
            root.0[0] = match format {
                PteFormat::Intel => SlPte::super_page_2mb(0x200000, true, true),
                PteFormat::Amd => SlPte(
                    crate::io::iommu::vendors::amd::tables::AmdPte::mapping(
                        0x200000, true, true, 0,
                    )
                    .0,
                ),
            };
            let original = root.0[0].0;
            // SAFETY: this private fixture retains a full aligned root and no
            // hardware or concurrent writer can observe its entries.
            unsafe {
                assert_eq!(
                    unmap_leaf_run(root.0.as_ptr(), 2, format, 0, 4096),
                    Err(IommuError::InvalidAlignment)
                );
                assert_eq!(
                    unmap_leaf_run(root.0.as_ptr(), 2, format, 4096, 1 << 21),
                    Err(IommuError::InvalidAlignment)
                );
                assert_eq!(
                    unmap_leaf_run(root.0.as_ptr(), 2, format, 0, 1 << 21),
                    Ok((1 << 21, 2))
                );
            }
            assert_eq!(root.0[0].0, original);
            root.0[0] = SlPte::super_page_1gb(0, true, true);
            if format == PteFormat::Amd {
                root.0[0] = SlPte(
                    crate::io::iommu::vendors::amd::tables::AmdPte::mapping(0, true, true, 0).0,
                );
            }
            // SAFETY: the same exclusively retained fixture now describes a level-3 root.
            unsafe {
                assert_eq!(
                    unmap_leaf_run(root.0.as_ptr(), 3, format, 0, 1 << 21),
                    Err(IommuError::InvalidAlignment)
                );
                assert_eq!(
                    unmap_leaf_run(root.0.as_ptr(), 3, format, 0, 1 << 30),
                    Ok((1 << 30, 3))
                );
            }
        }
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn leaf_run_checks_the_whole_4k_prefix_before_mutation() {
        let mut leaf = Table([SlPte::new(); PT_ENTRIES]);
        leaf.0[510] = SlPte::mapping(0x1000, true, false);
        // SAFETY: a retained leaf-only fixture with a nonzero aligned range;
        // this observer cannot mutate any table or return allocation ownership.
        unsafe {
            assert_eq!(
                unmap_leaf_run(leaf.0.as_ptr(), 1, PteFormat::Intel, 510 * 4096, 8192),
                Err(IommuError::NotMapped)
            );
            assert_eq!(
                unmap_leaf_run(leaf.0.as_ptr(), 1, PteFormat::Intel, 510 * 4096, 4096),
                Ok((4096, 1))
            );
        }
        assert!(leaf.0[510].is_present());
        leaf.0[511] = SlPte::mapping(0x2000, true, false);
        // SAFETY: the fixture owns both observed leaves through this call.
        unsafe {
            assert_eq!(
                unmap_leaf_run(leaf.0.as_ptr(), 1, PteFormat::Intel, 510 * 4096, 12288),
                Ok((8192, 1))
            );
        }
    }
    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn retirement_capacity_counts_table_windows_at_boundaries() {
        assert_eq!(retirement_table_bound(0, 1 << 30, 4), Ok(518));
        assert_eq!(retirement_table_bound((1 << 30) - 4096, 8192, 4), Ok(9));
        assert_eq!(retirement_table_bound(0, 4096, 5), Ok(8));
        assert_eq!(
            retirement_table_bound(1, 4096, 4),
            Err(IommuError::InvalidAlignment)
        );
        assert_eq!(
            retirement_table_bound(u64::MAX - 4095, 4096, 4),
            Err(IommuError::InvalidAddress)
        );
    }
}
