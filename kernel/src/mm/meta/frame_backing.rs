// ============================================================================
// src/mm/frame_backing.rs - Frame -> File Backing Mapping
// ============================================================================
//!
//! This module maintains a lightweight mapping from physical frames (FrameIndex)
//! to the backing file page (inode number, page number). It is used by the
//! page reclaim path to perform targeted per-frame writeback instead of a
//! coarse global sync.
// ============================================================================

use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use core::fmt;

use crate::fs::InodeNum;
use crate::mm::types::FrameIndex;

/// Information describing the backing of a frame
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameBackingInfo {
    /// Inode number
    pub ino: InodeNum,
    /// Page number within the file (offset / PAGE_SIZE)
    pub page_num: u64,
}

impl fmt::Display for FrameBackingInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ino={} page_num={}", self.ino, self.page_num)
    }
}

/// Tracker structure
pub struct FrameBackingTracker {
    mapping: PoisonRwLock<BTreeMap<FrameIndex, FrameBackingInfo>>,
}

impl FrameBackingTracker {
    pub const fn new() -> Self {
        Self {
            mapping: PoisonRwLock::new(BTreeMap::new()),
        }
    }

    /// Track a frame's backing
    pub fn track(&self, frame: FrameIndex, ino: InodeNum, page_num: u64) {
        let mut m = self.mapping.write().unwrap_or_else(|e| e.into_inner());
        m.insert(frame, FrameBackingInfo { ino, page_num });
    }

    /// Untrack a frame and return its backing info (if any)
    pub fn untrack(&self, frame: FrameIndex) -> Option<FrameBackingInfo> {
        let mut m = self.mapping.write().unwrap_or_else(|e| e.into_inner());
        m.remove(&frame)
    }

    /// Get backing info for a frame
    pub fn get(&self, frame: FrameIndex) -> Option<FrameBackingInfo> {
        let m = self.mapping.read().unwrap_or_else(|e| e.into_inner());
        m.get(&frame).copied()
    }
}

static FRAME_BACKING_TRACKER: FrameBackingTracker = FrameBackingTracker::new();

/// Track a frame's backing (public wrapper)
pub fn track_frame_backing(frame: FrameIndex, ino: InodeNum, page_num: u64) {
    FRAME_BACKING_TRACKER.track(frame, ino, page_num);
}

/// Untrack a frame's backing
pub fn untrack_frame_backing(frame: FrameIndex) -> Option<FrameBackingInfo> {
    FRAME_BACKING_TRACKER.untrack(frame)
}

/// Get a frame's backing info
pub fn get_frame_backing(frame: FrameIndex) -> Option<FrameBackingInfo> {
    FRAME_BACKING_TRACKER.get(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::types::FrameIndex;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_track_and_get_untrack() {
        let f = FrameIndex::new(12345);
        assert!(get_frame_backing(f).is_none());

        track_frame_backing(f, 42, 7);
        let info = get_frame_backing(f).expect("expected backing");
        assert_eq!(info.ino, 42);
        assert_eq!(info.page_num, 7);

        let removed = untrack_frame_backing(f).expect("expected removed");
        assert_eq!(removed.ino, 42);
        assert!(get_frame_backing(f).is_none());
    }
}
