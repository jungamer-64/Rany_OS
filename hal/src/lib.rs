// hal/src/lib.rs - Minimal Hardware Abstraction Layer for MMIO/Port I/O
#![cfg_attr(not(feature = "std"), no_std)]

// re-export modules
pub mod mmio;
pub mod port_io;

pub use mmio::*;
pub use port_io::*;
