// ============================================================================
// src/mm/folio.rs - Folio (Compound Page) Abstraction
// ============================================================================
//! Folio is a group of physically contiguous pages treated as a single unit.
//! This is similar to Linux's struct folio, used to manage large pages
//! efficiently without carrying the overhead of per-page tracking for every
//! 4KB constituent page.

use crate::mm::types::FrameIndex;
use crate::mm::page_flags::{self, PageMetaFlags};

/// A Folio represents a physically contiguous set of pages.
/// A Folio is always aligned to its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Folio(FrameIndex);

impl Folio {
    /// Create a Folio from a head page frame index.
    /// 
    /// # Safety
    /// The frame must be the head of a valid compound page or a single order-0 page.
    pub const fn new(frame: FrameIndex) -> Self {
        Self(frame)
    }

    /// Get the frame index of the head page.
    pub fn frame(&self) -> FrameIndex {
        self.0
    }

    /// Check if this frame is marked as a compound head.
    pub fn is_head(&self) -> bool {
        page_flags::test_flag(self.0, PageMetaFlags::CompoundHead)
    }

    /// Try to create a Folio from an arbitrary frame.
    /// If the frame is a tail page, returns the Folio for the head page.
    /// If the frame is a head page or order-0, returns the Folio for it.
    /// 
    /// Note: Currently we don't strictly track "Head pointer in Tail" in software
    /// without extra overhead. For now, this assumes we are given a head.
    /// A robust implementation would store the head PFN in the metadata of tail pages.
    pub fn from_frame(frame: FrameIndex) -> Self {
        // TODO: Look up head pointer from tail page metadata if it's a tail.
        // For now, assume we are handling valid heads or single pages.
        Self(frame)
    }

    /// Get the order of the folio (power of 2 size in 4KB pages).
    pub fn order(&self) -> u8 {
        page_flags::get_order(self.0)
    }

    /// Get the size of the folio in bytes.
    pub fn size(&self) -> usize {
        4096 << self.order()
    }
}
