#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::doc_markdown)]
// hal/src/lib.rs - Minimal Hardware Abstraction Layer for MMIO/Port I/O
#![cfg_attr(not(feature = "std"), no_std)]

// re-export modules
pub mod mmio;
pub mod port_io;

// selectively re-export only the symbols actually used outside the submodules
pub use mmio::{
    MmioReg, mmio_read_u8, mmio_read_u16, mmio_read_u32, mmio_read_u64, mmio_write_u8,
    mmio_write_u16, mmio_write_u32, mmio_write_u64, volatile_read, volatile_write,
};

pub use port_io::{IoPort, PortU8, PortU16, PortU32, inb, inl, inp, inw, out, outb, outl, outw};
