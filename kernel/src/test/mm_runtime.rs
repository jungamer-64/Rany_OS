//! Runtime checks use live allocator owners and synchronized global mappings.
//! Failed cases retain backing rather than returning possibly published RAM.
use super::runtime_dispatch::RuntimeTestResult;
use crate::mm::phys::frame_allocator::{self as pmm, PhysicalAllocation};
use crate::mm::types::NumaNodeId;
use crate::mm::virt::higher_half::{
    self as vm, MapError, PageFlags, PhysAddr, TlbSyncState, VirtAddr,
};
use core::alloc::Layout;

fn outcome(result: Result<(), &'static str>) -> RuntimeTestResult {
    match result {
        Ok(()) => RuntimeTestResult::pass(),
        Err(reason) => RuntimeTestResult::fail(reason),
    }
}

pub(super) fn owned_frames(_: Option<&str>) -> RuntimeTestResult {
    outcome((|| {
        let mut owners: [Option<PhysicalAllocation>; 80] = [const { None }; 80];
        for index in 0..owners.len() {
            let owner = pmm::alloc_frame().map_err(|_| "4KiB allocation failed")?;
            if owners
                .iter()
                .flatten()
                .any(|live| live.as_u64() == owner.as_u64())
            {
                return Err("simultaneous physical owners overlap");
            }
            owners[index] = Some(owner);
        }
        for owner in owners.into_iter().flatten() {
            pmm::dealloc_frame(owner);
        }
        crate::heap::reclaim_local_caches();
        for index in 0..crate::mm::numa::topology::num_nodes() {
            let node = NumaNodeId::new(index as u8);
            let frame = match pmm::alloc_frame_on_numa_node(node) {
                Ok(frame) => frame,
                Err(pmm::FrameAllocError::Exhausted) => continue, // valid CPU-only node
                Err(_) => return Err("published NUMA node was not admitted"),
            };
            if frame.node() != node {
                return Err("explicit node allocation fell back");
            }
            // Dirty several pages so each speculative zeroed refill slot,
            // including the cached hits after its demand page, is observed.
            let mut dirty: [Option<PhysicalAllocation>; 16] = [const { None }; 16];
            dirty[0] = Some(frame);
            for slot in &mut dirty[1..] {
                *slot = Some(
                    pmm::alloc_frame_on_numa_node(node)
                        .map_err(|_| "dirty frame preparation failed")?,
                );
            }
            for frame in dirty.into_iter().flatten() {
                // SAFETY: this unique unmapped owner retains writable HHDM RAM.
                unsafe {
                    crate::mm::virt::mapping::phys_to_virt(frame.start_address())
                        .as_mut_ptr::<u8>()
                        .write_bytes(0xa5, 4096);
                }
                frame.release();
            }
            let mut zeros: [Option<PhysicalAllocation>; 16] = [const { None }; 16];
            for index in 0..zeros.len() {
                let zero = pmm::alloc_zeroed_frame(node).map_err(|_| "zeroed allocation failed")?;
                if zero.node() != node
                    || zeros
                        .iter()
                        .flatten()
                        .any(|live| live.as_u64() == zero.as_u64())
                {
                    return Err("zeroed owners overlap or changed explicit node");
                }
                // SAFETY: zeroing completed before this exclusive page escaped.
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        crate::mm::virt::mapping::phys_to_virt(zero.start_address()).as_ptr::<u8>(),
                        4096,
                    )
                };
                if bytes.iter().any(|&byte| byte != 0) {
                    return Err("zeroed refill or cached hit contains stale bytes");
                }
                zeros[index] = Some(zero);
            }
            for zero in zeros.into_iter().flatten() {
                zero.release();
            }

            // A 513-page exclusive loan always has a non-2MiB-aligned 512-page
            // subextent. Size alone must never admit it as a huge-cache hit.
            let loan = pmm::alloc_contiguous_frames_aligned_on_node(node, 513, 4096)
                .map_err(|_| "huge cache geometry preparation failed")?;
            let (partial, unaligned) = if loan.as_u64() % 0x200000 == 0 {
                loan.split(1).map_err(|_| "huge loan split failed")?
            } else {
                let (unaligned, partial) = loan.split(512).map_err(|_| "huge loan split failed")?;
                (partial, unaligned)
            };
            if unaligned.as_u64() % 0x200000 == 0 || unaligned.page_count() != 512 {
                return Err("huge cache geometry fixture is invalid");
            }
            pmm::dealloc_frame_2m(unaligned);
            partial.release();
            let huge =
                pmm::alloc_frame_2m_on_numa_node(node).map_err(|_| "huge allocation failed")?;
            if huge.node() != node || huge.as_u64() % 0x200000 != 0 || huge.page_count() != 512 {
                return Err("huge cache returned invalid geometry or node");
            }
            pmm::dealloc_frame_2m(huge);
        }
        crate::heap::reclaim_local_caches();
        Ok(())
    })())
}

pub(super) fn heap_layouts(_: Option<&str>) -> RuntimeTestResult {
    outcome((|| {
        for bytes in [1, 64, 127, 256, 512, 1024, 1984, 2048, 4096, 65536] {
            for align in [1, 8, 64, 128, 4096, 65536] {
                let layout =
                    Layout::from_size_align(bytes, align).map_err(|_| "invalid heap Layout")?;
                // SAFETY: this valid nonzero Layout is retained for the unique return.
                let pointer = unsafe { alloc::alloc::alloc(layout) };
                if pointer.is_null() {
                    return Err("heap allocation failed");
                }
                if pointer.addr() % align != 0 {
                    return Err("heap alignment failed");
                }
                // SAFETY: live exclusive GlobalAlloc pointer covers this payload;
                // the original Layout is consumed once after the last access.
                unsafe {
                    pointer.write_bytes(0x5a, bytes);
                    alloc::alloc::dealloc(pointer, layout)
                };
            }
        }
        crate::heap::reclaim_local_caches();
        crate::heap::reclaim_shared_pools();
        Ok(())
    })())
}

pub(super) fn mapping_ranges(_: Option<&str>) -> RuntimeTestResult {
    outcome((|| {
        let start = vm::allocate_kernel_virt(1536);
        let ram = pmm::alloc_contiguous_frames(2).map_err(|_| "range backing failed")?;
        let conflict = pmm::alloc_frame().map_err(|_| "conflicting backing failed")?;
        let flags = PageFlags::kernel_data().set(PageFlags::GLOBAL);
        // SAFETY: reserved virtual range and both owners exclude independent mappings/users.
        unsafe { vm::global_map_page(start + 4096, PhysAddr::new(conflict.as_u64()), flags) }
            .map_err(|_| "conflicting mapping setup failed")?;
        // SAFETY: same reserved range, retained RAM, no payload borrower or DMA.
        let error = match unsafe {
            vm::global_map_range(start, PhysAddr::new(ram.as_u64()), 8192, flags)
        } {
            Err(error) => error,
            Ok(()) => return Err("overlapping second leaf was accepted"),
        };
        if error.cause != MapError::AlreadyMapped
            || error.modified_size != 4096
            || error.tlb_sync != TlbSyncState::Complete
        {
            return Err("partial range failure lost progress or TLB completion");
        }
        // SAFETY: this private mapping is retained and inaccessible to other payload borrowers.
        unsafe {
            vm::global_update_flags_range(
                start,
                4096,
                PageFlags::kernel_code().set(PageFlags::GLOBAL),
            )
        }
        .map_err(|_| "range permission update failed")?;
        let entry = vm::get_current_pte(start).ok_or("updated leaf disappeared")?;
        if entry.flags().contains(PageFlags::WRITABLE) {
            return Err("writable permission survived update");
        }
        // SAFETY: no payload/DMA users remain; successful return includes remote TLB completion.
        unsafe { vm::global_unmap_range(start, 8192) }
            .map_err(|_| "partial range cleanup failed")?;
        ram.release();
        conflict.release();

        let huge_address =
            VirtAddr::new((start.as_u64() + 8192 + (1 << 21) - 1) & !((1 << 21) - 1));
        let huge = pmm::alloc_frame_2m().map_err(|_| "huge backing failed")?;
        // SAFETY: the aligned 2MiB mapping fits wholly within the reserved 6MiB extent.
        unsafe { vm::global_map_range(huge_address, PhysAddr::new(huge.as_u64()), 1 << 21, flags) }
            .map_err(|_| "huge mapping failed")?;
        // SAFETY: ownership is unchanged, and the partial request must fail without mutation.
        let error = match unsafe { vm::global_unmap_range(huge_address + 4096, 4096) } {
            Err(error) => error,
            Ok(()) => return Err("partial huge leaf was accepted"),
        };
        if error.cause != MapError::AlignmentError
            || error.modified_size != 0
            || error.tlb_sync != TlbSyncState::Complete
        {
            return Err("partial huge request removed neighbouring mappings");
        }
        // SAFETY: whole owned leaf with no payload/DMA borrower; completion precedes RAM reuse.
        unsafe { vm::global_unmap_range(huge_address, 1 << 21) }
            .map_err(|_| "huge cleanup failed")?;
        huge.release();
        Ok(())
    })())
}
