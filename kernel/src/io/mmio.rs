// Re-export mmio functions from the shared hal crate. This maintains the
// old module path `crate::io::mmio` while delegating the implementation to
// the `hal` crate which centralizes MMIO operations across kernel and
// drivers.
pub use hal::mmio::*;
