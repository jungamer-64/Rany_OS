use super::*;

impl ProcessAddressSpace {
    /// Internal unsafe helper for promotion
    pub(crate) unsafe fn perform_promotion(
        &self,
        pt_root: u64,
        indices: [usize; 4],
        huge_phys_x64: X64PhysAddr,
        protection: Protection,
    ) -> bool {
        use crate::mm::virt::higher_half::{
            PAGE_TABLE_MANAGER, PageFlags, PageTable, PageTableEntry,
        };

        // 脆弱性修正: プロモーション処理全体を PAGE_TABLE_MANAGER ロックで保護。
        // これにより、別の CPU が同時に同じ範囲をマップ/アンマップしたり、別の
        // プロモーションを実行したりすることによる不整合を防止する。
        let mut _guard = match PAGE_TABLE_MANAGER.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };

        // Convert x86_64::PhysAddr to higher_half::PhysAddr for PT operations
        let huge_phys = PhysAddr::new(huge_phys_x64.as_u64());

        // Level 4 (PML4)
        let pml4_phys = PhysAddr::new(pt_root);
        let pml4 = &*crate::mm::virt::higher_half::phys_to_virt(pml4_phys).as_ptr::<PageTable>();
        let pml4e = pml4.entry(indices[0]);
        if !pml4e.is_present() {
            return false;
        }

        // Level 3 (PDPT)
        let pdpt_phys = pml4e.phys_addr();
        let pdpt = &*crate::mm::virt::higher_half::phys_to_virt(pdpt_phys).as_ptr::<PageTable>();
        let pdpte = pdpt.entry(indices[1]);
        if !pdpte.is_present() {
            return false;
        }
        if pdpte.is_huge() {
            return false;
        }

        // Level 2 (PD) - This is where we modify
        let pd_phys = pdpte.phys_addr();
        let pd =
            &mut *crate::mm::virt::higher_half::phys_to_virt(pd_phys).as_mut_ptr::<PageTable>();
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() {
            return false;
        }
        if pde.is_huge() {
            return false;
        } // Already huge

        // Level 1 (PT) - The table we are replacing
        let pt_phys = pde.phys_addr();
        let pt = &*crate::mm::virt::higher_half::phys_to_virt(pt_phys).as_ptr::<PageTable>();

        let huge_base_virt = crate::mm::virt::mapping::phys_to_virt(huge_phys_x64);

        let frames_to_free = Self::copy_pt_entries_to_huge(pt, huge_base_virt);

        // Update PDE to point to Huge Page
        let mut flags = protection.to_page_flags();
        flags = flags.set(PageFlags::PRESENT | PageFlags::HUGE_PAGE);
        if protection.write {
            flags = flags.set(PageFlags::DIRTY);
        }

        let new_pde = PageTableEntry::huge(huge_phys, flags);

        *pde = new_pde;

        // TLB Flush and free old frames
        Self::finalize_promotion_cleanup(&indices, frames_to_free, pt_phys);

        true
    }

    /// Copy all present PT entries to a huge page frame, returning frames to free
    unsafe fn copy_pt_entries_to_huge(
        pt: &crate::mm::virt::higher_half::PageTable,
        huge_base_virt: x86_64::VirtAddr,
    ) -> Vec<crate::mm::virt::higher_half::PhysAddr> {
        let mut frames_to_free = Vec::new();
        for i in 0..512 {
            let pte = pt.entry(i);
            if pte.is_present() {
                let src_phys_hh = pte.phys_addr();
                let src_phys_x64 = X64PhysAddr::new(src_phys_hh.as_u64());
                let src_virt = crate::mm::virt::mapping::phys_to_virt(src_phys_x64);
                let dst_virt = huge_base_virt + (i as u64 * 4096);
                core::ptr::copy_nonoverlapping(
                    src_virt.as_ptr::<u8>(),
                    dst_virt.as_mut_ptr::<u8>(),
                    4096,
                );
                frames_to_free.push(src_phys_hh);
            }
        }
        frames_to_free
    }

    /// TLB flush and free old 4K frames + PT frame
    unsafe fn finalize_promotion_cleanup(
        indices: &[usize; 4],
        frames_to_free: Vec<crate::mm::virt::higher_half::PhysAddr>,
        pt_phys: crate::mm::virt::higher_half::PhysAddr,
    ) {
        let vaddr_raw =
            (indices[0] as u64) << 39 | (indices[1] as u64) << 30 | (indices[2] as u64) << 21;
        let vaddr = VirtAddr::new(vaddr_raw);

        // 脆弱性修正: ローカルな invlpg から、マルチコア対応のシュートダウンへ
        crate::mm::virt::higher_half::invalidate_page(vaddr);

        for frame in frames_to_free {
            let frame_addr = X64PhysAddr::new(frame.as_u64());
            let phys_frame: PhysFrame<Size4KiB> =
                PhysFrame::from_start_address(frame_addr).unwrap();
            buddy_dealloc_frame(phys_frame);
        }
        let pt_frame_addr = X64PhysAddr::new(pt_phys.as_u64());
        let pt_frame: PhysFrame<Size4KiB> = PhysFrame::from_start_address(pt_frame_addr).unwrap();
        buddy_dealloc_frame(pt_frame);
    }
}
