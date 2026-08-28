//! NVMe device implementation boundary.
//!
//! The former raw-pointer queue, ambient MMIO, and independently reclaiming
//! DMA implementation has been removed. Production components are rebuilt on
//! mapping and registry capabilities before this crate is made operational.

#![no_std]
