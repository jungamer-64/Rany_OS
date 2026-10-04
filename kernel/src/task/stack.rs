//! Guarded task stacks in a fixed, reusable virtual arena.

use crate::mm::phys::frame_allocator::{self, FrameAllocError, PhysicalAllocation};
use crate::mm::virt::higher_half::{
    MapError, PhysAddr, VirtAddr, global_map_guarded_scatter, global_unmap_scatter,
};
use crate::sync::PoisonLock;

use super::config::SCHEDULER_CONFIG;

const PAGE_BYTES: usize = 4096;
const STACK_PAGES: usize = SCHEDULER_CONFIG.stack_bytes / PAGE_BYTES;
const SLOT_BYTES: u64 = (SCHEDULER_CONFIG.stack_bytes + PAGE_BYTES) as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StackError {
    SlotsExhausted,
    PhysicalMemoryExhausted,
    Mapping(MapError),
}

static STACK_SLOTS: PoisonLock<[bool; SCHEDULER_CONFIG.max_tasks]> =
    PoisonLock::new([false; SCHEDULER_CONFIG.max_tasks]);

/// Owns every physical frame backing a task stack. The low page of each slot
/// remains unmapped. The arena slot is returned only after unmap completes its
/// cross-CPU TLB invalidation, so a new task cannot observe an old translation.
pub(super) struct TaskStack {
    slot: usize,
    frames: [Option<PhysicalAllocation>; STACK_PAGES],
}

impl TaskStack {
    pub(super) fn allocate() -> Result<Self, StackError> {
        let slot = {
            let mut slots = STACK_SLOTS
                .lock()
                .unwrap_or_else(|_| panic!("task stack arena ownership is poisoned"));
            let slot = slots
                .iter()
                .position(|&used| !used)
                .ok_or(StackError::SlotsExhausted)?;
            slots[slot] = true;
            slot
        };

        let mut frames: [Option<PhysicalAllocation>; STACK_PAGES] = [const { None }; STACK_PAGES];
        let mut physical = [PhysAddr::zero(); STACK_PAGES];
        for (index, frame) in frames.iter_mut().enumerate() {
            let allocated = match frame_allocator::alloc_frame() {
                Ok(allocated) => allocated,
                Err(cause) => {
                    for owned in frames.into_iter().flatten() {
                        frame_allocator::dealloc_frame(owned);
                    }
                    release_slot(slot);
                    return Err(classify_mapping_failure(MapError::FrameAllocation(cause)));
                }
            };
            physical[index] = PhysAddr::new(allocated.start_address().as_u64());
            *frame = Some(allocated);
        }

        // SAFETY: this owner retains every frame until it has removed the
        // mapping and completed the synchronous TLB invalidation in Drop. The
        // reserved arena slot exclusively owns its low guard and mapped run.
        if let Err(error) = unsafe { global_map_guarded_scatter(guard_page(slot), &physical) } {
            for owned in frames.into_iter().flatten() {
                frame_allocator::dealloc_frame(owned);
            }
            release_slot(slot);
            return Err(classify_mapping_failure(error));
        }

        Ok(Self { slot, frames })
    }

    pub(super) fn top(&self) -> u64 {
        mapped_base(self.slot).as_u64() + SCHEDULER_CONFIG.stack_bytes as u64
    }

    pub(super) fn bounds(&self) -> core::ops::Range<u64> {
        mapped_base(self.slot).as_u64()..self.top()
    }

    pub(super) fn slot(&self) -> usize {
        self.slot
    }
}

impl Drop for TaskStack {
    fn drop(&mut self) {
        let physical = core::array::from_fn::<_, STACK_PAGES, _>(|index| {
            PhysAddr::new(
                self.frames[index]
                    .as_ref()
                    .expect("mapped stack frame owner")
                    .as_u64(),
            )
        });
        // SAFETY: the stack is no longer executing; its owner drops only
        // after the scheduler has observed poll completion.
        unsafe { global_unmap_scatter(mapped_base(self.slot), &physical) }
            .unwrap_or_else(|error| panic!("task stack unmap failed: {error:?}"));
        for frame in &mut self.frames {
            frame_allocator::dealloc_frame(frame.take().expect("unmapped stack frame owner"));
        }
        release_slot(self.slot);
    }
}

fn mapped_base(slot: usize) -> VirtAddr {
    guard_page(slot).offset(PAGE_BYTES as u64)
}

fn guard_page(slot: usize) -> VirtAddr {
    VirtAddr::new(VirtAddr::KERNEL_STACK_BASE + slot as u64 * SLOT_BYTES)
}

fn classify_mapping_failure(error: MapError) -> StackError {
    match error {
        MapError::FrameAllocation(
            FrameAllocError::Exhausted | FrameAllocError::MetadataAllocation,
        )
        | MapError::MetadataAllocation => StackError::PhysicalMemoryExhausted,
        other => StackError::Mapping(other),
    }
}

fn release_slot(slot: usize) {
    let mut slots = STACK_SLOTS
        .lock()
        .unwrap_or_else(|_| panic!("task stack arena ownership is poisoned"));
    assert!(slots[slot], "task stack slot released twice");
    slots[slot] = false;
}

#[cfg(test)]
mod allocation_failure_tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn page_table_allocation_failure_is_memory_exhaustion() {
        assert_eq!(
            classify_mapping_failure(MapError::FrameAllocation(FrameAllocError::Exhausted)),
            StackError::PhysicalMemoryExhausted
        );
        assert_eq!(
            classify_mapping_failure(MapError::ParentPermissionDenied),
            StackError::Mapping(MapError::ParentPermissionDenied)
        );
    }
}
