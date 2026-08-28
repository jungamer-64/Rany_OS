//! Per-frame metadata flag definitions.
//!
//! Storage and mutation authority belong to the physical-memory inventory that
//! admits the frames. This module intentionally does not expose ambient lookup
//! or mutation functions.

/// Atomic software metadata flags associated with a managed physical frame.
///
/// These flags are distinct from page-table entry flags in
/// `crate::mm::virt::higher_half`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageMetaFlags {
    /// Page is currently queued for swapout.
    SwapPending = 1 << 0,
    /// Page is currently under writeback.
    Writeback = 1 << 1,
    /// Page is dirty according to software tracking.
    Dirty = 1 << 2,
    /// Page cannot currently be reclaimed.
    Locked = 1 << 3,
    /// Page was referenced according to software tracking.
    Referenced = 1 << 4,
    /// Page is the head of a compound allocation.
    CompoundHead = 1 << 5,
    /// Page is a tail of a compound allocation.
    CompoundTail = 1 << 6,
}

impl PageMetaFlags {
    /// Returns the bit representing this flag.
    #[inline]
    pub const fn bits(self) -> u8 {
        self as u8
    }
}
