//! Scalar accesses to live descriptor RAM. Allocation references never cross
//! this boundary; the registry serializes CPU operations and reclamation.

use super::RRefDmaBytes;
use kernel_api::dma::{DmaAccessWidth, DmaLeaseError};

impl RRefDmaBytes {
    fn shared_scalar_ptr(
        &self,
        offset: usize,
        width: DmaAccessWidth,
    ) -> Result<*mut u8, DmaLeaseError> {
        let end = offset
            .checked_add(width.bytes())
            .ok_or(DmaLeaseError::InvalidRange)?;
        if end > self.len {
            return Err(DmaLeaseError::InvalidRange);
        }
        let allocation = self
            .buffer
            .handle
            .rref
            .as_ref()
            .ok_or(DmaLeaseError::InvalidState)?;
        let base = allocation.allocation_ptr().cast::<u8>();
        // SAFETY: the checked logical range is contained in the retained RRef
        // allocation. Pointer arithmetic preserves that allocation's provenance.
        let pointer = unsafe { base.as_ptr().add(offset) };
        if !pointer.addr().is_multiple_of(width.bytes()) {
            return Err(DmaLeaseError::InvalidAlignment);
        }
        Ok(pointer)
    }

    /// Read a scalar from shared coherent RAM without a pointee reference.
    ///
    /// # Safety
    /// The registry must serialize this access against all CPU writes and
    /// reclamation. No ordinary Rust reference to these bytes may be live.
    /// The mapping must use the x86 coherent DMA cache policy.
    ///
    /// # Errors
    /// Rejects bounds/alignment errors before touching the allocation.
    pub(crate) unsafe fn read_shared_word(
        &self,
        offset: usize,
        width: DmaAccessWidth,
    ) -> Result<u64, DmaLeaseError> {
        let pointer = self.shared_scalar_ptr(offset, width)?;
        let value = match width {
            DmaAccessWidth::Byte => {
                // SAFETY: range and alignment checked; caller serializes CPU
                // access and retains the allocation. Every u8 pattern is valid.
                u64::from(unsafe { pointer.read_volatile() })
            }
            DmaAccessWidth::Word => {
                // SAFETY: the validated range covers an aligned u16. The caller
                // retains the backing and excludes competing CPU accesses.
                u64::from(unsafe { pointer.cast::<u16>().read_volatile() })
            }
            DmaAccessWidth::Dword => {
                // SAFETY: the validated range covers an aligned u32. The caller
                // retains the backing and excludes competing CPU accesses.
                u64::from(unsafe { pointer.cast::<u32>().read_volatile() })
            }
            DmaAccessWidth::Qword => {
                // SAFETY: the validated range covers an aligned u64. The caller
                // retains the backing and excludes competing CPU accesses.
                unsafe { pointer.cast::<u64>().read_volatile() }
            }
        };
        // Coherent x86 RAM needs ordering, not cache-line invalidation. The
        // acquire fence keeps descriptor reads after its ownership/phase read.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        Ok(value)
    }

    /// Write one scalar to shared coherent RAM without a pointee reference.
    ///
    /// # Safety
    /// The registry must serialize all CPU access and reclamation, and exclude
    /// ordinary Rust references to these bytes. The driver must publish fields
    /// according to the device's ownership protocol. Mapping cache policy must
    /// be x86 DMA-coherent.
    ///
    /// # Errors
    /// Rejects value, bounds, and alignment errors before the device-visible write.
    pub(crate) unsafe fn write_shared_word(
        &self,
        offset: usize,
        width: DmaAccessWidth,
        value: u64,
    ) -> Result<(), DmaLeaseError> {
        if !width.contains(value) {
            return Err(DmaLeaseError::InvalidRange);
        }
        let pointer = self.shared_scalar_ptr(offset, width)?;
        // Publish prior descriptor writes before the final ownership word.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        match width {
            DmaAccessWidth::Byte => {
                // SAFETY: validated aligned live allocation, exclusive CPU
                // access, and a value representable by the selected width.
                unsafe { pointer.write_volatile(value as u8) };
            }
            DmaAccessWidth::Word => {
                // SAFETY: range/alignment/value checked above; caller holds
                // allocation ownership and excludes concurrent CPU references.
                unsafe { pointer.cast::<u16>().write_volatile(value as u16) };
            }
            DmaAccessWidth::Dword => {
                // SAFETY: range/alignment/value checked above; caller holds
                // allocation ownership and excludes concurrent CPU references.
                unsafe { pointer.cast::<u32>().write_volatile(value as u32) };
            }
            DmaAccessWidth::Qword => {
                // SAFETY: range/alignment checked above; caller holds allocation
                // ownership and excludes concurrent CPU references.
                unsafe { pointer.cast::<u64>().write_volatile(value) };
            }
        }
        // Orders coherent RAM publication before a subsequent device doorbell.
        super::sfence();
        Ok(())
    }
}
