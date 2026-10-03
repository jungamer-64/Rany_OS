//! Byte-range access is confined to the framework transfer registry. The
//! mapping retains a padded allocation, while CPU access is bounded by the
//! caller's logical length. Hardware-active access uses scalars without Rust
//! references; ordinary references require the registry's CPU-owned state.

use super::{DmaDirection, DmaHandle, MapError, MapErrorKind, UnmapErrorKind};
use crate::io::iommu::types::DeviceId;
use crate::ipc::RRef;
use kernel_api::dma::{DmaAccessWidth, DmaLeaseError};

pub(crate) struct DmaBytes {
    handle: DmaHandle<[u8]>,
    len: usize,
}

pub(crate) struct DmaBytesUnmapError {
    pub(crate) buffer: DmaBytes,
    pub(crate) kind: UnmapErrorKind,
}

impl DmaBytes {
    pub(crate) fn map(
        backing: RRef<[u8]>,
        len: usize,
        device: &DeviceId,
        direction: DmaDirection,
    ) -> Result<Self, MapError<[u8]>> {
        if len == 0 || len > backing.len() {
            return Err(MapError::unmapped(backing, MapErrorKind::InvalidSize));
        }
        DmaHandle::map_rref_slice_for_device(backing, device, direction)
            .map(|handle| Self { handle, len })
    }

    pub(crate) fn iova(&self) -> u64 {
        self.handle.iova()
    }

    fn backing_ptr(&self) -> Option<*mut u8> {
        self.handle
            .rref
            .as_ref()
            .map(|backing| backing.allocation_ptr().as_ptr().cast::<u8>())
    }

    /// # Safety
    /// The registry must hold CPU ownership of the entire allocation, exclude
    /// device access and competing CPU mutation, and retain that state for the
    /// returned borrow. A prepared or retiring mapping is not CPU ownership.
    pub(crate) unsafe fn cpu_bytes(&self) -> Option<&[u8]> {
        self.handle.rref.as_deref()?.get(..self.len)
    }

    /// # Safety
    /// The registry must retain exclusive CPU ownership, excluding device and
    /// other CPU accesses for the entire borrow; no hardware publication or
    /// retirement may occur during this visit.
    pub(crate) unsafe fn cpu_bytes_mut(&mut self) -> Option<&mut [u8]> {
        self.handle.rref.as_deref_mut()?.get_mut(..self.len)
    }

    /// Cache operations observe raw backing without forming a Rust reference
    /// while a device may still be updating coherent RAM.
    pub(crate) fn flush_for_device(&self) -> Result<(), DmaLeaseError> {
        let pointer = self.backing_ptr().ok_or(DmaLeaseError::InvalidState)?;
        crate::io::dma::flush_cache_range(pointer, self.len);
        Ok(())
    }

    pub(crate) fn invalidate_for_cpu(&self) -> Result<(), DmaLeaseError> {
        let pointer = self.backing_ptr().ok_or(DmaLeaseError::InvalidState)?;
        crate::io::dma::invalidate_cache_range(pointer, self.len);
        Ok(())
    }

    pub(crate) fn try_unmap(self) -> Result<RRef<[u8]>, DmaBytesUnmapError> {
        let Self { handle, len } = self;
        handle.unmap().map_err(|error| DmaBytesUnmapError {
            buffer: Self {
                handle: error.handle,
                len,
            },
            kind: error.kind,
        })
    }

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
        let base = self.backing_ptr().ok_or(DmaLeaseError::InvalidState)?;
        // SAFETY: the checked range lies within the retained initialized backing.
        let pointer = unsafe { base.add(offset) };
        if !pointer.addr().is_multiple_of(width.bytes()) {
            return Err(DmaLeaseError::InvalidAlignment);
        }
        Ok(pointer)
    }

    /// # Safety
    /// The registry must serialize CPU access and reclamation, retain the
    /// coherent mapping, and exclude ordinary Rust references to this RAM.
    /// The driver's descriptor protocol must authorize the selected word.
    pub(crate) unsafe fn read_shared_word(
        &self,
        offset: usize,
        width: DmaAccessWidth,
    ) -> Result<u64, DmaLeaseError> {
        let pointer = self.shared_scalar_ptr(offset, width)?;
        let value = match width {
            // SAFETY: validated live ranges/alignment, every unsigned integer
            // pattern is valid, and the caller serializes CPU access.
            DmaAccessWidth::Byte => u64::from(unsafe { pointer.read_volatile() }),
            // SAFETY: same checked range and CPU exclusion contract for a u16.
            DmaAccessWidth::Word => u64::from(unsafe { pointer.cast::<u16>().read_volatile() }),
            // SAFETY: same checked range and CPU exclusion contract for a u32.
            DmaAccessWidth::Dword => u64::from(unsafe { pointer.cast::<u32>().read_volatile() }),
            // SAFETY: same checked range and CPU exclusion contract for a u64.
            DmaAccessWidth::Qword => unsafe { pointer.cast::<u64>().read_volatile() },
        };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        Ok(value)
    }

    /// # Safety
    /// The registry must retain the coherent allocation, serialize all CPU
    /// access and reclamation, and exclude ordinary references. The driver
    /// must obey the descriptor ownership and publication protocol.
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
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        match width {
            // SAFETY: retained live range/alignment and representable value;
            // the caller excludes competing CPU access and references.
            DmaAccessWidth::Byte => unsafe { pointer.write_volatile(value as u8) },
            // SAFETY: same validated scalar access contract for a u16.
            DmaAccessWidth::Word => unsafe { pointer.cast::<u16>().write_volatile(value as u16) },
            // SAFETY: same validated scalar access contract for a u32.
            DmaAccessWidth::Dword => unsafe { pointer.cast::<u32>().write_volatile(value as u32) },
            // SAFETY: same validated scalar access contract for a u64.
            DmaAccessWidth::Qword => unsafe { pointer.cast::<u64>().write_volatile(value) },
        }
        crate::io::dma::sfence();
        Ok(())
    }
}
