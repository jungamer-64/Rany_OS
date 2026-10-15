//! Runtime checks use live allocator owners and synchronized global mappings.
//! Failed cases retain backing rather than returning possibly published RAM.
use super::runtime_dispatch::RuntimeTestResult;
use crate::mm::phys::frame_allocator::{self as pmm, PhysicalAllocation};
use crate::mm::types::NumaNodeId;
use crate::mm::virt::higher_half::{
    self as vm, MapError, PageFlags, PageSize, PageTable, PageTableEntry, PageTableManager,
    PhysAddr, TlbSyncState, VirtAddr,
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
            let mapped = crate::mm::virt::mapping::phys_to_virt(owner.start_address());
            if crate::mm::virt::mapping::virt_to_phys(mapped) != owner.start_address()
                || vm::global_translate(VirtAddr::new(mapped.as_u64()))
                    != Some(PhysAddr::new(owner.as_u64()))
            {
                return Err("direct-map conversion disagrees with the live page tables");
            }
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
        if vm::global_translate(start) != Some(PhysAddr::new(ram.as_u64()))
            || vm::global_translate(start + 4096) != Some(PhysAddr::new(conflict.as_u64()))
        {
            return Err("partial mapping changed its existing neighbour");
        }
        // SAFETY: all three virtual pages are reserved here and the first two
        // retain RAM owners. The absent third leaf must stop the update.
        let error = match unsafe {
            vm::global_update_flags_range(
                start,
                3 * 4096,
                PageFlags::kernel_code().set(PageFlags::GLOBAL),
            )
        } {
            Err(error) => error,
            Ok(()) => return Err("permission update accepted an absent leaf"),
        };
        if error.cause != MapError::NotMapped
            || error.modified_size != 8192
            || error.tlb_sync != TlbSyncState::Complete
        {
            return Err("permission failure lost its synchronized prefix");
        }
        let entry = vm::get_current_pte(start).ok_or("updated leaf disappeared")?;
        let neighbour = vm::get_current_pte(start + 4096).ok_or("updated neighbour disappeared")?;
        if entry.flags().contains(PageFlags::WRITABLE)
            || neighbour.flags().contains(PageFlags::WRITABLE)
        {
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
        // SAFETY: this aligned ordinary-RAM mapping fits wholly within the
        // reserved 6MiB extent and uses the same cache type as its HHDM view.
        unsafe { vm::global_map_range(huge_address, PhysAddr::new(huge.as_u64()), 1 << 21, flags) }
            .map_err(|_| "huge mapping failed")?;
        if vm::global_translate(huge_address + 0x1234)
            != Some(PhysAddr::new(huge.as_u64() + 0x1234))
        {
            return Err("huge leaf changed its physical offset");
        }
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
        // SAFETY: this whole owned leaf has no payload/DMA borrower and both
        // the original and updated permissions retain its RAM cache type.
        unsafe {
            vm::global_update_flags_range(
                huge_address,
                1 << 21,
                PageFlags::kernel_code().set(PageFlags::GLOBAL),
            )
        }
        .map_err(|_| "huge permission update failed")?;
        let entry = vm::get_current_pte(huge_address).ok_or("updated huge leaf disappeared")?;
        if entry.as_u64() & PageFlags::PAT_LARGE != 0
            || entry.flags().contains(PageFlags::WRITABLE)
            || vm::global_translate(huge_address) != Some(PhysAddr::new(huge.as_u64()))
        {
            return Err("huge permission update retained PAT or changed backing");
        }
        // SAFETY: the interior address selects this uniquely owned whole leaf;
        // successful return synchronizes its full extent before RAM reuse.
        let removed = unsafe { vm::global_unmap_page(huge_address + 4096) }
            .map_err(|_| "huge cleanup failed")?;
        if removed.size != PageSize::Size2MiB
            || removed.virtual_start != huge_address
            || removed.physical != PhysAddr::new(huge.as_u64())
            || vm::global_translate(huge_address).is_some()
        {
            return Err("interior huge unmap lost the actual retired extent");
        }
        huge.release();
        Ok(())
    })())
}

pub(super) fn huge_mapping_flags(_: Option<&str>) -> RuntimeTestResult {
    outcome((|| {
        let tables = pmm::alloc_contiguous_frames(3).map_err(|_| "private table RAM failed")?;
        let data = pmm::alloc_frame_2m().map_err(|_| "private huge backing failed")?;
        let root = crate::mm::virt::mapping::phys_to_virt(tables.start_address())
            .as_mut_ptr::<PageTable>();
        let parent_flags = PageFlags::new(PageFlags::PRESENT | PageFlags::WRITABLE);
        // SAFETY: the retained 3-page owner exclusively covers these aligned
        // tables. This complete hierarchy is never installed in any CR3, so
        // its PAT encodings cannot introduce a hardware alias of HHDM RAM.
        unsafe {
            root.write_bytes(0, 3);
            *(*root).entry_mut(0) =
                PageTableEntry::new(PhysAddr::new(tables.as_u64() + 4096), parent_flags);
            *(*root.add(1)).entry_mut(0) =
                PageTableEntry::new(PhysAddr::new(tables.as_u64() + 8192), parent_flags);
        }
        {
            // SAFETY: all three paging levels and the leaf data retain their unique
            // owners throughout mutation; no hardware or concurrent CPU uses them.
            let mut manager = unsafe {
                PageTableManager::new(
                    PhysAddr::new(tables.as_u64()),
                    crate::heap::physical_memory_offset(),
                )
            };
            let address = VirtAddr::new(1 << 21);
            // SAFETY: the existing parent links cover this whole aligned data owner;
            // publication affects only the retained, hardware-inaccessible root.
            unsafe {
                manager.map_2mb_page(
                    address,
                    PhysAddr::new(data.as_u64()),
                    PageFlags::write_combining(),
                )
            }
            .map_err(|_| "private huge mapping failed")?;
            // SAFETY: the exclusive table owner covers PD entry 1 and no writer is active.
            let encoded = unsafe { (*root.add(2)).entry(1).as_u64() };
            if encoded & (1 << 12) == 0
                || manager.translate(address + 0x1234)
                    != Some(PhysAddr::new(data.as_u64() + 0x1234))
            {
                return Err("huge PAT encoding lost its architectural bit or backing");
            }
            // SAFETY: the full private leaf retains backing and has no hardware readers.
            unsafe { manager.update_flags_range(address, 1 << 21, PageFlags::kernel_code()) }
                .map_err(|_| "private huge permission update failed")?;
            // SAFETY: mutation ended; the same retained PD entry remains exclusively owned.
            let updated = unsafe { *(*root.add(2)).entry(1) };
            if updated.as_u64() & (1 << 12) != 0
                || updated.flags().contains(PageFlags::WRITABLE)
                || manager.translate(address) != Some(PhysAddr::new(data.as_u64()))
            {
                return Err("huge permission update retained PAT or changed backing");
            }
            // SAFETY: the entire hierarchy is private, and the leaf is removed
            // before releasing either its data owner or any table backing.
            let removed = unsafe { manager.unmap_page(address + 4096) }
                .map_err(|_| "private huge unmap failed")?;
            if removed.virtual_start != address
                || removed.size != PageSize::Size2MiB
                || removed.physical != PhysAddr::new(data.as_u64())
                || manager.translate(address).is_some()
            {
                return Err("private huge unmap returned the wrong retired extent");
            }
        }
        data.release();
        tables.release();
        Ok(())
    })())
}

pub(super) fn owned_mapping_replacement(_: Option<&str>) -> RuntimeTestResult {
    outcome((|| {
        let address = vm::allocate_kernel_virt(1);
        let source = pmm::alloc_frame().map_err(|_| "replacement source RAM failed")?;
        let destination = pmm::alloc_frame().map_err(|_| "replacement destination RAM failed")?;
        let unrelated = pmm::alloc_frame().map_err(|_| "unrelated source RAM failed")?;
        let source_physical = source.as_u64();
        let unrelated_physical = unrelated.as_u64();
        // SAFETY: these distinct unpublished owners retain exclusive writable
        // HHDM RAM; neither has a payload borrower or device publication.
        unsafe {
            crate::mm::virt::mapping::phys_to_virt(source.start_address())
                .as_mut_ptr::<u64>()
                .write(0x1122_3344_5566_7788);
            crate::mm::virt::mapping::phys_to_virt(destination.start_address())
                .as_mut_ptr::<u64>()
                .write(0x8877_6655_4433_2211);
        }
        let flags = PageFlags::kernel_data().set(PageFlags::GLOBAL);
        // SAFETY: this reserved address has one non-HHDM mapping and source
        // retains backing until replacement completes or cleanup removes it.
        unsafe { vm::global_map_page(address, PhysAddr::new(source_physical), flags) }
            .map_err(|_| "replacement mapping setup failed")?;
        // SAFETY: the source owner retains this mapped word. Reading it also
        // populates the CPU translation cache before replacement.
        if unsafe { address.as_ptr::<u64>().read_volatile() } != 0x1122_3344_5566_7788 {
            return Err("source mapping does not address its retained RAM");
        }
        let retained_flags = vm::get_current_pte(address)
            .ok_or("source leaf disappeared")?
            .flags();
        // SAFETY: both comparison owners are retained and this case excludes
        // competing payload, DMA and mapping mutations throughout the call.
        let unrelated =
            match unsafe { vm::global_replace_owned_page(address, unrelated, &destination) } {
                Err((MapError::MappingChanged, owner)) => owner,
                _ => return Err("stale source replacement did not return its owner"),
            };
        if unrelated.as_u64() != unrelated_physical
            || vm::global_translate(address) != Some(PhysAddr::new(source_physical))
        {
            return Err("rejected replacement changed an owner or translation");
        }
        // SAFETY: the exact mapped source is transferred once; destination
        // remains owned here through publication, TLB completion and cleanup.
        unsafe { vm::global_replace_owned_page(address, source, &destination) }
            .map_err(|_| "owned mapping replacement failed")?;
        let entry = vm::get_current_pte(address).ok_or("replaced leaf disappeared")?;
        if vm::global_translate(address) != Some(PhysAddr::new(destination.as_u64()))
            || entry.flags().as_u64() != retained_flags.as_u64()
        {
            return Err("replacement lost backing or leaf permissions");
        }
        // SAFETY: completed replacement retains destination here and must
        // retire the previously populated source translation before this read.
        if unsafe { address.as_ptr::<u64>().read_volatile() } != 0x8877_6655_4433_2211 {
            return Err("replacement returned before translation invalidation");
        }
        // SAFETY: the reserved mapping still has no competing CPU/DMA users;
        // unmap completes translation retirement before either owner is freed.
        unsafe { vm::global_unmap_range(address, 4096) }
            .map_err(|_| "replacement cleanup failed")?;
        destination.release();
        unrelated.release();
        Ok(())
    })())
}
