// ============================================================================
// kernel/src/io/iommu/backends/common/mod.rs
// ============================================================================

pub mod pasid;
#[allow(unused_imports)]
pub use self::pasid::*;

pub mod ats;
#[allow(unused_imports)]
pub use self::ats::*;

pub mod posted_interrupt;
pub use self::posted_interrupt::*;
