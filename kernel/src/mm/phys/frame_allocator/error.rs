//! Physical admission failures are independent of the RAM provider. Native
//! PMM and host storage use the same reason classes at their ownership boundary.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAllocError {
    Uninitialized,
    Exhausted,
    InvalidRange,
    Alignment,
    MetadataAllocation,
    AlreadyInitialized,
    InvalidNode,
}
