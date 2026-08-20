//! Durability utilities (formerly `storage/`).
//!
//! This module provides data durability guarantees for persistent storage:
//! - `wal`: write-ahead logging primitives
//! - `pmem`: persistent memory flush/order helpers

pub mod pmem;
pub mod wal;

/// Initialize storage durability subsystems.
pub fn init() {
    if let Err(error) = pmem::init_from_nfit() {
        log::warn!("PMEM discovery unavailable: {error:?}");
    }
    wal::init_global_wal();
}
