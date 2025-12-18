// Minimal I/O module for bench builds: only expose `log.rs` so benches can
// exercise the logging paths (per-core/global) without compiling the whole
// I/O subsystem which pulls in many heavy dependencies and platform code.

#[path = "log.rs"]
pub mod log;