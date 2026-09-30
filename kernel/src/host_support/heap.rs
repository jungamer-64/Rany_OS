//! Hosted allocation boundary for pure kernel components; no boot RAM admission
//! or allocator reinitialization authority is available in this configuration.
use boot_proto::ExoBootInfoView;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicU64, Ordering};

static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);

pub struct LockedBuddyHeap;

impl LockedBuddyHeap {
    pub const fn new() -> Self {
        Self
    }

    pub fn is_initialized(&self) -> Option<bool> {
        Some(true)
    }
}

unsafe impl GlobalAlloc for LockedBuddyHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(any(feature = "std", all(test, target_os = "linux")))]
        {
            return unsafe { std::alloc::System.alloc(layout) };
        }
        #[cfg(not(any(feature = "std", all(test, target_os = "linux"))))]
        {
            let _ = layout;
            core::ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(any(feature = "std", all(test, target_os = "linux")))]
        {
            unsafe {
                std::alloc::System.dealloc(ptr, layout);
            }
        }
        #[cfg(not(any(feature = "std", all(test, target_os = "linux"))))]
        {
            let _ = (ptr, layout);
        }
    }
}

pub static ALLOCATOR: LockedBuddyHeap = LockedBuddyHeap::new();

pub mod oom {
    #[derive(Debug, Clone, Default)]
    pub struct OomStats {
        pub total_domains: usize,
        pub kill_count: u64,
        pub freed_memory: u64,
        pub in_progress: bool,
    }

    pub fn try_free_memory() -> bool {
        false
    }

    pub fn stats() -> OomStats {
        OomStats::default()
    }
}

pub fn verify_buddy_integrity() {}

pub fn is_initialized() -> bool {
    true
}

pub fn heap_stats() -> (usize, usize) {
    (0, 0)
}

pub fn total_memory_kb() -> u64 {
    1024 * 1024
}

pub fn free_memory_kb() -> u64 {
    512 * 1024
}

pub fn used_memory_kb() -> u64 {
    total_memory_kb().saturating_sub(free_memory_kb())
}

pub(crate) fn print_memory_stats() {}

pub(crate) fn reclaim_acpi_reclaimable(_boot_info: &ExoBootInfoView<'_>) {}

pub(crate) fn physical_memory_offset() -> u64 {
    PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed)
}

pub(crate) fn set_physical_memory_offset(offset: u64) {
    PHYSICAL_MEMORY_OFFSET.store(offset, Ordering::Relaxed);
}
