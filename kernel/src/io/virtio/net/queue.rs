//! Transitional queue module.
//!
//! `NetVirtQueue` and related queue internals are currently defined in
//! `net/mod.rs`; this module provides a stable namespace for call sites while
//! the implementation is being split.

pub use super::{IommuMapping, NetVirtQueue, NetVirtQueueInner};
