// ============================================================================
// kernel/src/io/iommu/controller/mod.rs
// ============================================================================

//! IOMMU Controller Types and Submodules
//!
//! Core types for the IOMMU controller. The actual `IommuController` struct
//! and its impl blocks remain in the parent `iommu.rs` module for now.
//!
//! # Submodules (Placeholders for future extraction)
//!
//! - `init` - Controller initialization and capability detection
//! - `dma` - Domain and DMA mapping management
//! - `qi_ops` - Queued Invalidation operations
//!
//! These submodules are currently stubs documenting the intended split.
//! The actual implementation will be incrementally moved here.

pub mod cpu_cache;
pub mod dma;
pub mod fault;
pub mod init;
pub mod init_global;
pub mod iova;
pub mod ir;
pub mod perfmon;
pub mod pi;
pub mod pri;
pub mod qi_init;
pub mod qi_ops;
pub mod utils;

use alloc::vec::Vec;

use super::tables::HardwareTable;
use super::{ContextEntry, RootEntry};

// ============================================================================
// Hardware Context
// ============================================================================

/// Hardware Tables (Root Table and Context Tables)
///
/// Uses the type-safe `HardwareTable<T>` abstraction which provides:
/// - Physical contiguity (1 page per table)
/// - Zero initialization
/// - NUMA-aware allocation
/// - RAII-based deallocation
///
/// # Safety
///
/// The controller must ensure that hardware is not using these tables
/// before they are dropped (i.e., translation must be disabled first).
pub struct HardwareContext {
    /// Root Table: 256 entries (16 bytes each = 4KB)
    pub root_table: Option<HardwareTable<RootEntry>>,
    /// Context Tables: 256 tables, each with 256 entries (16 bytes each = 4KB)
    pub context_tables: Vec<HardwareTable<ContextEntry>>,
}

impl Default for HardwareContext {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareContext {
    /// Create an empty HardwareContext (tables will be allocated during init)
    pub fn new() -> Self {
        Self {
            root_table: None,
            context_tables: Vec::new(),
        }
    }

    /// Check if hardware tables are initialized
    pub fn is_initialized(&self) -> bool {
        self.root_table.is_some() && !self.context_tables.is_empty()
    }
}

// SAFETY: HardwareContext is Send because:
// - All inner types (HardwareTable) implement Send
// - Access is controlled via external locks (IommuController::hardware)
unsafe impl Send for HardwareContext {}

// ============================================================================
// IOMMU Capabilities
// ============================================================================

/// IOMMU capability summary
#[derive(Debug, Clone)]
pub struct IommuCapabilities {
    pub queued_invalidation: bool,
    pub interrupt_remapping: bool,
    pub super_page_2mb: bool,
    pub super_page_1gb: bool,
    pub page_walk_coherency: bool,
    pub snoop_control: bool,
    pub posted_interrupts: bool,
    pub scalable_mode: bool,
    pub performance_monitoring: bool,
}
