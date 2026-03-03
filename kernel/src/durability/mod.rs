//! Durability utilities (formerly `storage/`).
//!
//! This module provides data durability guarantees for persistent storage:
//! - `wal`: write-ahead logging primitives
//! - `pmem`: persistent memory flush/order helpers

pub mod pmem;
pub mod wal;

/// Initialize storage durability subsystems.
pub fn init() {
    let _ = pmem::init_from_nfit();
    wal::init_global_wal();
}
