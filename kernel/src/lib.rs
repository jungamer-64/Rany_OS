// When not running tests or benches, compile as `no_std`. For benches we
// enable the standard library so benchmark harnesses (Criterion) and
// alloc-dependent graphics helpers can build and run under the host test
// runner.
#![cfg_attr(not(any(test, feature = "std")), no_std)]

// For unit testing we expose a small set of modules via the library entry
// point. This keeps most of the kernel as a binary-only crate while still
// allowing targeted library-style tests (e.g. security/capability) to run
// under `cargo test --lib` without pulling the entire binary test harness.
#[cfg(test)]
pub mod security;

// Expose additional modules when building tests so unit tests inside those
// modules can be executed via `cargo test --lib`.
// Also expose the `graphics` module when compiling benches via the
// `bench` feature so Criterion benches can access framebuffer types and
// helpers. This keeps the default binary layout unchanged while allowing
// convenient benching during development.
#[cfg(any(test, feature = "bench"))]
pub mod graphics;

#[cfg(any(test, feature = "bench"))]
pub use hal;

// Some graphics modules depend on the `alloc` crate and other internal
// modules (e.g. unwind). When compiling benches we need to make these
// available so the bench harness can build the same code paths we
// exercise at runtime.
#[cfg(any(test, feature = "bench"))]
extern crate alloc;

#[cfg(test)]
pub mod unwind;

#[cfg(any(test, feature = "bench"))]
pub mod util;

// Remove lib.rs as we're using a binary-only structure
