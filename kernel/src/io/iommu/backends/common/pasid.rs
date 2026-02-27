// ============================================================================
// kernel/src/io/iommu/common/pasid.rs
// ============================================================================
//! PASID (Process Address Space ID) Support for Scalable Mode
//!
//! Canonical PASID table types live in `crate::io::iommu::backends::intel::tables`:
//!   - `PasidDirEntry`   (8-byte directory entry)
//!   - `PasidTableEntry` (64-byte leaf entry)
//!   - `PasidTable`      (directory + leaf + bitmap allocator)
