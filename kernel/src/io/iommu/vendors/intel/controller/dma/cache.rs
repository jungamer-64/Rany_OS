// ============================================================================
// Deprecated shim for old location of the context cache.
// Originally lived under `intel/controller/dma/cache.rs`, but the cache
// actually stores *context entries* (device‑ID → context table entry mapping)
// and is not part of the DMA/IOVA translation path.  The real implementation
// has been moved to `intel/controller/context_cache.rs`.
//
// Keeping this stub around allows existing `use` paths to continue working
// while emitting a deprecation warning.
// ============================================================================

#![allow(deprecated)]

#[deprecated(
    note = "context cache moved to `crate::io::iommu::vendors::intel::controller::context_cache`"
)]
pub use crate::io::iommu::vendors::intel::controller::context_cache::*;

