//! Storage durability utilities.
//!
//! - `wal`: write-ahead logging primitives
//! - `pmem`: persistent memory flush/order helpers

pub mod pmem;
pub mod wal;

/// Initialize storage durability subsystems.
pub fn init() {
    pmem::init_default_region();
    wal::init_global_wal();
}
