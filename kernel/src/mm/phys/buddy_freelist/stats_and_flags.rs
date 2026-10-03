use super::*;

#[derive(Debug, Clone, Copy)]
pub struct FreeListBuddyStats {
    pub total_frames: usize,
    pub free_frames: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    pub fallback_count: u64,
    pub order_stats: [(usize, usize); MAX_ORDER + 1],
    pub migrate_stats: [u64; MigrateType::COUNT],
}

#[cfg(feature = "qemu-test-export")]
#[path = "qemu_tests.rs"]
pub mod qemu_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
