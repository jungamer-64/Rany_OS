//! Device-shared descriptor RAM uses the same registry allocation and close
//! protocol as transfer DMA, but never lends Rust references while active.

use super::*;

/// An indivisible CPU access width supported for device-shared RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DmaAccessWidth {
    Byte,
    Word,
    Dword,
    Qword,
}

impl DmaAccessWidth {
    /// Number of bytes transferred by one scalar access.
    pub const fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
            Self::Qword => 8,
        }
    }

    /// Validate the complete scalar before any device-visible write occurs.
    pub const fn contains(self, value: u64) -> bool {
        match self {
            Self::Byte => value <= u8::MAX as u64,
            Self::Word => value <= u16::MAX as u64,
            Self::Dword => value <= u32::MAX as u64,
            Self::Qword => true,
        }
    }

    /// Decode the exact scalar width carried by the stable ABI.
    pub const fn from_abi(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Byte),
            1 => Some(Self::Word),
            2 => Some(Self::Dword),
            3 => Some(Self::Qword),
            _ => None,
        }
    }

    /// Encode the exact scalar width for the stable ABI.
    pub const fn into_abi(self) -> u8 {
        self as u8
    }
}

impl CpuDmaLease {
    /// Prepare this allocation for a long-lived shared descriptor/ring role.
    ///
    /// # Errors
    /// Returns the unchanged CPU owner if queue validation or preparation fails.
    pub fn prepare_shared(
        mut self,
        queue: DmaQueueIdentity,
    ) -> Result<PreparedSharedDmaLease, DmaTransitionError<Self>> {
        if let Err(cause) = self.authority().prepare_shared(queue) {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(PreparedSharedDmaLease::from_core(self.take_core()))
    }
}

impl PreparedSharedDmaLease {
    /// Mapping metadata borrowed until publication or pre-publication abort.
    ///
    /// # Errors
    /// Returns the registry failure without changing the prepared owner.
    pub fn descriptor(&self) -> Result<DmaDescriptor<'_>, DmaLeaseError> {
        let authority = self.authority();
        Ok(DmaDescriptor {
            lease_id: authority.lease_id(),
            device_address: authority.device_address(),
            byte_count: authority.byte_count(),
            queue: authority.prepared_queue()?,
            _lease: PhantomData,
        })
    }

    /// Cancel preparation before any hardware publication.
    ///
    /// # Errors
    /// Returns the unchanged prepared owner if the registry rejects the transition.
    pub fn abort(mut self) -> Result<CpuDmaLease, DmaTransitionError<Self>> {
        if let Err(cause) = self.authority().abort_prepared() {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(CpuDmaLease::from_core(self.take_core()))
    }

    /// Disable CPU references before programming the device with this region.
    ///
    /// The caller must perform this transition before publication. Once active,
    /// even a failed initialization retains the allocation until queue quiescence
    /// or reset is established. A software error is not proof of non-acceptance.
    ///
    /// # Errors
    /// Returns the unchanged prepared owner; no hardware publication occurs here.
    pub fn activate(mut self) -> Result<SharedDmaLease, DmaTransitionError<Self>> {
        if let Err(cause) = self.authority().activate_shared() {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(SharedDmaLease::from_core(self.take_core()))
    }
}

/// Non-cloneable proof that a queue no longer accesses one shared allocation.
#[derive(Debug)]
pub struct DmaQuiesceWitness {
    queue: DmaQueueIdentity,
    lease: DmaLeaseId,
}

impl DmaQuiesceWitness {
    /// Queue observed in its stopped state.
    pub const fn queue(&self) -> DmaQueueIdentity {
        self.queue
    }

    /// Shared allocation no longer reachable by that queue.
    pub const fn lease_id(&self) -> DmaLeaseId {
        self.lease
    }

    /// Bind an observed queue stop to its shared allocation.
    ///
    /// # Safety
    /// The driver must observe the hardware-defined stopped/idle state, drain
    /// outstanding accesses to `lease`, and ensure no other queue can access it.
    /// This witness may be created only once for that stop and allocation.
    pub unsafe fn after_queue_quiesced(queue: DmaQueueIdentity, lease: DmaLeaseId) -> Self {
        Self { queue, lease }
    }
}

impl SharedDmaLease {
    /// Borrow a bounded window for scalar volatile access, without RAM references.
    ///
    /// # Errors
    /// Rejects empty, overflowing, or out-of-allocation ranges.
    pub fn window(
        &mut self,
        offset: usize,
        byte_count: usize,
    ) -> Result<DmaSharedWindow<'_>, DmaLeaseError> {
        let byte_count = DmaByteCount::new(byte_count).ok_or(DmaLeaseError::InvalidRange)?;
        let end = offset
            .checked_add(byte_count.get())
            .ok_or(DmaLeaseError::InvalidRange)?;
        if end > self.byte_count().get() {
            return Err(DmaLeaseError::InvalidRange);
        }
        Ok(DmaSharedWindow {
            authority: self.authority(),
            offset,
            byte_count,
            _exclusive: PhantomData,
        })
    }

    /// Recover CPU ownership after all hardware access to this region has stopped.
    ///
    /// # Errors
    /// A mismatched lease or queue generation returns the unchanged shared owner.
    pub fn quiesce(
        mut self,
        witness: DmaQuiesceWitness,
    ) -> Result<CpuDmaLease, DmaTransitionError<Self>> {
        if let Err(cause) = self.authority().quiesce_shared(witness) {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(CpuDmaLease::from_core(self.take_core()))
    }

    /// Revoke access to this shared region after a device reset.
    ///
    /// # Errors
    /// A wrong device or stale reset generation returns the unchanged shared owner.
    pub fn revoke_after_reset(
        mut self,
        witness: DmaResetWitness,
    ) -> Result<RevokedAfterResetDmaLease, DmaTransitionError<Self>> {
        if let Err(cause) = self.authority().revoke_after_reset(witness) {
            return Err(DmaTransitionError::new(self, cause));
        }
        Ok(RevokedAfterResetDmaLease::from_core(self.take_core()))
    }
}

/// Exclusive CPU window into a live, device-shared allocation.
///
/// Scalar accesses preserve the requested width and validate bounds/alignment.
/// They do not establish a coherent snapshot of an entire descriptor: the
/// driver must observe its ownership/phase field and apply the device protocol.
pub struct DmaSharedWindow<'lease> {
    authority: &'lease dyn DmaLeaseAuthority,
    offset: usize,
    byte_count: DmaByteCount,
    _exclusive: PhantomData<&'lease mut SharedDmaLease>,
}

impl fmt::Debug for DmaSharedWindow<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DmaSharedWindow")
            .field("lease", &self.authority.lease_id())
            .field("offset", &self.offset)
            .field("byte_count", &self.byte_count)
            .finish()
    }
}

impl DmaSharedWindow<'_> {
    /// Length of this checked window.
    pub const fn byte_count(&self) -> DmaByteCount {
        self.byte_count
    }

    fn scalar_offset(
        &self,
        relative: usize,
        width: DmaAccessWidth,
    ) -> Result<usize, DmaLeaseError> {
        let end = relative
            .checked_add(width.bytes())
            .ok_or(DmaLeaseError::InvalidRange)?;
        if end > self.byte_count.get() {
            return Err(DmaLeaseError::InvalidRange);
        }
        let offset = self
            .offset
            .checked_add(relative)
            .ok_or(DmaLeaseError::InvalidRange)?;
        if !offset.is_multiple_of(width.bytes()) {
            return Err(DmaLeaseError::InvalidAlignment);
        }
        Ok(offset)
    }

    fn read(&self, relative: usize, width: DmaAccessWidth) -> Result<u64, DmaLeaseError> {
        let offset = self.scalar_offset(relative, width)?;
        self.authority.read_shared_word(offset, width)
    }

    fn write(
        &mut self,
        relative: usize,
        width: DmaAccessWidth,
        value: u64,
    ) -> Result<(), DmaLeaseError> {
        let offset = self.scalar_offset(relative, width)?;
        self.authority.write_shared_word(offset, width, value)
    }
}

macro_rules! scalar_access {
    ($read:ident, $write:ident, $ty:ty, $width:ident) => {
        impl DmaSharedWindow<'_> {
            /// Read one native-endian scalar with acquire-side DMA ordering.
            ///
            /// # Errors
            /// Rejects out-of-window or misaligned access and revoked leases.
            pub fn $read(&self, offset: usize) -> Result<$ty, DmaLeaseError> {
                self.read(offset, DmaAccessWidth::$width)
                    .map(|value| value as $ty)
            }

            /// Write one native-endian scalar with release-side DMA ordering.
            ///
            /// # Errors
            /// Rejects out-of-window or misaligned access and revoked leases
            /// before writing any bytes.
            pub fn $write(&mut self, offset: usize, value: $ty) -> Result<(), DmaLeaseError> {
                self.write(offset, DmaAccessWidth::$width, value as u64)
            }
        }
    };
}

scalar_access!(read_u8, write_u8, u8, Byte);
scalar_access!(read_u16, write_u16, u16, Word);
scalar_access!(read_u32, write_u32, u32, Dword);
scalar_access!(read_u64, write_u64, u64, Qword);
