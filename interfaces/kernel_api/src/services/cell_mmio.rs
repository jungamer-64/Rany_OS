//! Imports only a grant delivered by the kernel's successful acquisition call.
#![deny(unsafe_code)]

use crate::abi::driver::{AbiMmioGrant, KERNEL_API_ABI_VERSION, KernelApiV4};
use crate::mmio::{MmioAcquireError, MmioAperture, PciMmioRequest};
use alloc::sync::Arc;

struct CellMappingOwner {
    identity: u64,
}

impl Drop for CellMappingOwner {
    #[expect(
        unsafe_code,
        reason = "The private importer owns exactly one kernel grant; the final HAL owner releases it once."
    )]
    fn drop(&mut self) {
        // SAFETY: this identity was transferred by a successful acquire, has
        // never been copied into another owner, and has no live register handle.
        unsafe { (super::abi().mmio_release)(self.identity) };
    }
}

#[expect(
    unsafe_code,
    reason = "Importing a kernel-owned mapping is the trusted ABI boundary; callers cannot import numerical metadata."
)]
pub(super) fn acquire(request: PciMmioRequest) -> Result<hal::MappedMmio, MmioAcquireError> {
    let api = super::abi();
    if api.abi_version != KERNEL_API_ABI_VERSION
        || (api.abi_size as usize) < core::mem::size_of::<KernelApiV4>()
    {
        return Err(MmioAcquireError::Unavailable);
    }
    let (kind, offset, length) = match request.aperture() {
        MmioAperture::WholeBar => (0, 0, 0),
        MmioAperture::Bytes(range) => (1, range.offset(), range.byte_count()),
    };
    let mut grant = AbiMmioGrant::default();
    // SAFETY: the request was validated, the table has the complete ABI, and
    // out points to exclusive aligned storage for this synchronous operation.
    let status = unsafe {
        (api.mmio_acquire)(
            request.device().raw(),
            request.bar_index(),
            kind,
            offset,
            length,
            &mut grant,
        )
    };
    if status != 0 {
        return Err(MmioAcquireError::from_abi(status));
    }
    if grant.identity == 0 {
        return Err(MmioAcquireError::MappingFailed);
    }
    let owner = Arc::new(CellMappingOwner {
        identity: grant.identity,
    });
    // SAFETY: success transfers a resource-pinned, cache-correct installed
    // aperture. Owner drop releases it after the final HAL-derived register.
    unsafe { hal::MappedMmio::from_raw_parts(owner, grant.base, grant.length) }
        .map_err(|_| MmioAcquireError::MappingFailed)
}
