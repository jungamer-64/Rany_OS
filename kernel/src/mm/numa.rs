// ============================================================================
// src/mm/numa.rs - NUMA helper wrappers
// ============================================================================
//! Lightweight NUMA helper APIs used by kernel subsystems.
//!
//! This module provides small wrappers around the existing NUMA topology
//! detection (see `task::work_stealing_advanced::NumaTopology`) and exposes
//! allocation helpers that accept a NUMA node hint. Currently the allocator
//! helpers are fallbacks to the global allocator; they act as a stable API for
//! future NUMA-aware allocation implementations.
#![allow(dead_code)]

use alloc::alloc::Layout;
use core::ptr::NonNull;

/// Return the number of NUMA nodes in the system (1 for single-node)
pub fn num_nodes() -> usize {
    super::super::task::work_stealing_advanced::NumaTopology::get().num_nodes()
}

/// Return the NUMA node for the current CPU if available
pub fn current_node() -> usize {
    if let Some(cpu) = crate::mm::per_cpu::try_current_cpu_id() {
        super::super::task::work_stealing_advanced::NumaTopology::get()
            .get_numa_node(cpu as u32)
    } else {
        0
    }
}

/// Allocate a zeroed block with an optional NUMA node hint.
///
/// Note: This is currently a thin wrapper around `crate::util::allocate_zeroed`.
/// When a proper NUMA-aware allocator is available, this function will be
/// updated to allocate from the specified node.
pub fn allocate_zeroed_on_node(layout: Layout, _node: Option<usize>) -> Option<NonNull<u8>> {
    crate::util::allocate_zeroed(layout)
}

/// Deallocate a block previously returned by `allocate_zeroed_on_node`.
pub fn deallocate_on_node(ptr: NonNull<u8>, layout: Layout, _node: Option<usize>) {
    unsafe { alloc::alloc::dealloc(ptr.as_ptr(), layout) }
}
