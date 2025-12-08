// Re-export port I/O functions from the shared hal crate. This keeps the same
// module path (`crate::io::port_io`) while delegating the unsafe hardware I/O
// operations to the `hal` crate which is the canonical location for these
// wrappers across the workspace.
pub use hal::port_io::*;
