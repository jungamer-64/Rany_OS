//! Linear RAM ownership for descriptor queues. Initialization can fail at any
//! region; the queue keeps the actual prepared/active prefix until finalization.

#![deny(unsafe_code)]

use crate::error::{Mlx5Error, Mlx5Result};
use kernel_api::dma::{
    CpuDmaLease, DmaDeviceAddress, DmaDirection, DmaLeaseError, DmaQueueIdentity,
    DmaQuiesceWitness, PreparedSharedDmaLease, SharedDmaLease, UnmapFailedDmaLease,
};

enum Region {
    Cpu(CpuDmaLease),
    Prepared(PreparedSharedDmaLease),
    Shared {
        lease: SharedDmaLease,
        address: DmaDeviceAddress,
    },
    UnmapFailed(UnmapFailedDmaLease, DmaLeaseError),
    Released,
}

/// RAM activation and firmware acceptance are independent transitions.
/// Unknown acceptance retains RAM and prevents another creation attempt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum QueueGrant {
    Unpublished,
    CreationSubmitted,
    Live(u32),
    DestroySubmitted(u32),
    Quiesced,
}

pub(crate) enum QueueRetireAction {
    Destroy(u32),
    CloseRam,
}

impl QueueGrant {
    pub(crate) fn number(&self) -> Option<u32> {
        match self {
            Self::Live(number) => Some(*number),
            _ => None,
        }
    }

    pub(crate) fn begin_creation(&mut self) -> Mlx5Result<()> {
        if !matches!(self, Self::Unpublished) {
            return Err(Mlx5Error::DeviceNotReady);
        }
        *self = Self::CreationSubmitted;
        Ok(())
    }

    /// A command that was not published, or an acknowledged rejection, did
    /// not acquire a queue. Unknown acceptance prohibits RAM retirement.
    pub(crate) fn finish_creation(
        &mut self,
        result: Result<u32, crate::error::CommandFailure>,
    ) -> Mlx5Result<u32> {
        assert!(matches!(self, Self::CreationSubmitted));
        match result {
            Ok(number) => {
                *self = Self::Live(number);
                Ok(number)
            }
            Err(cause) => {
                if matches!(
                    cause,
                    crate::error::CommandFailure::Rejected(_)
                        | crate::error::CommandFailure::NotPublished(_)
                ) {
                    *self = Self::Unpublished;
                }
                Err(cause.cause())
            }
        }
    }

    pub(crate) fn begin_retirement(&mut self) -> Mlx5Result<QueueRetireAction> {
        match *self {
            Self::Live(number) => {
                *self = Self::DestroySubmitted(number);
                Ok(QueueRetireAction::Destroy(number))
            }
            Self::Unpublished | Self::Quiesced => {
                *self = Self::Quiesced;
                Ok(QueueRetireAction::CloseRam)
            }
            Self::CreationSubmitted | Self::DestroySubmitted(_) => Err(Mlx5Error::DeviceNotReady),
        }
    }

    /// Successful destruction is recorded before RAM close. Failed unmap then
    /// cannot cause a second DESTROY command against a reused firmware number.
    pub(crate) fn finish_destruction(
        &mut self,
        result: Result<(), crate::error::CommandFailure>,
    ) -> Mlx5Result<()> {
        let Self::DestroySubmitted(number) = *self else {
            unreachable!("retirement owns the outstanding destroy command")
        };
        match result {
            Ok(()) => {
                *self = Self::Quiesced;
                Ok(())
            }
            Err(cause) => {
                if matches!(
                    cause,
                    crate::error::CommandFailure::Rejected(_)
                        | crate::error::CommandFailure::NotPublished(_)
                ) {
                    *self = Self::Live(number);
                }
                Err(cause.cause())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_creation_keeps_retirement_blocked() {
        let mut grant = QueueGrant::Unpublished;
        grant.begin_creation().unwrap();
        assert_eq!(
            grant.finish_creation(Err(crate::error::CommandFailure::OutcomeUnknown(
                Mlx5Error::CommandTimeout
            ))),
            Err(Mlx5Error::CommandTimeout)
        );
        assert!(grant.begin_retirement().is_err());
        assert!(grant.number().is_none());
        assert_eq!(grant, QueueGrant::CreationSubmitted);
    }

    #[test]
    fn firmware_rejection_preserves_the_original_live_grant() {
        let mut grant = QueueGrant::Live(0);
        assert!(matches!(
            grant.begin_retirement().unwrap(),
            QueueRetireAction::Destroy(0)
        ));
        grant
            .finish_destruction(Err(crate::error::CommandFailure::Rejected(4)))
            .unwrap_err();
        assert_eq!(grant.number(), Some(0));
        assert!(matches!(
            grant.begin_retirement().unwrap(),
            QueueRetireAction::Destroy(0)
        ));
    }

    #[test]
    fn completed_destruction_never_repeats_before_ram_release() {
        let mut grant = QueueGrant::Live(17);
        assert!(matches!(
            grant.begin_retirement().unwrap(),
            QueueRetireAction::Destroy(17)
        ));
        grant.finish_destruction(Ok(())).unwrap();
        assert!(matches!(
            grant.begin_retirement().unwrap(),
            QueueRetireAction::CloseRam
        ));
        assert!(matches!(
            grant.begin_retirement().unwrap(),
            QueueRetireAction::CloseRam
        ));
        assert!(grant.number().is_none());
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RegionLayout {
    pub(crate) bytes: usize,
    pub(crate) direction: DmaDirection,
    pub(crate) alignment: usize,
}

pub(crate) struct QueueMemory<const N: usize> {
    identity: DmaQueueIdentity,
    regions: [Region; N],
}

impl<const N: usize> QueueMemory<N> {
    pub(crate) fn new(identity: DmaQueueIdentity, leases: [CpuDmaLease; N]) -> Self {
        Self {
            identity,
            regions: leases.map(Region::Cpu),
        }
    }

    /// The initializer sees exclusively CPU-owned RAM, before any descriptor
    /// is available for device publication. Every failure keeps its owner.
    pub(crate) fn prepare(
        &mut self,
        layouts: [RegionLayout; N],
        mut initialize: impl FnMut(usize, &mut [u8]),
    ) -> Mlx5Result<()> {
        for (index, (region, layout)) in self.regions.iter_mut().zip(layouts).enumerate() {
            let Region::Cpu(cpu) = region else {
                return Err(Mlx5Error::DeviceNotReady);
            };
            if cpu.byte_count().get() < layout.bytes || cpu.direction() != layout.direction {
                return Err(Mlx5Error::InvalidParameter);
            }
            cpu.write(|bytes| initialize(index, bytes))
                .map_err(Mlx5Error::DmaLease)?;
            let Region::Cpu(cpu) = core::mem::replace(region, Region::Released) else {
                unreachable!()
            };
            match cpu.prepare_shared(self.identity) {
                Ok(prepared) => *region = Region::Prepared(prepared),
                Err(error) => {
                    let (cause, cpu) = error.into_parts();
                    *region = Region::Cpu(cpu);
                    return Err(Mlx5Error::DmaLease(cause));
                }
            }
            let Region::Prepared(prepared) = region else {
                unreachable!()
            };
            let descriptor = prepared.descriptor().map_err(Mlx5Error::DmaLease)?;
            let address = descriptor.device_address();
            if layout.alignment == 0
                || address.get() == 0
                || !address.get().is_multiple_of(layout.alignment as u64)
                || address
                    .checked_add(descriptor.byte_count().get() - 1)
                    .is_none()
            {
                return Err(Mlx5Error::InvalidParameter);
            }
        }
        for region in &mut self.regions {
            let Region::Prepared(prepared) = core::mem::replace(region, Region::Released) else {
                unreachable!()
            };
            let address = match prepared.descriptor() {
                Ok(descriptor) => descriptor.device_address(),
                Err(cause) => {
                    *region = Region::Prepared(prepared);
                    return Err(Mlx5Error::DmaLease(cause));
                }
            };
            match prepared.activate() {
                Ok(lease) => *region = Region::Shared { lease, address },
                Err(error) => {
                    let (cause, prepared) = error.into_parts();
                    *region = Region::Prepared(prepared);
                    return Err(Mlx5Error::DmaLease(cause));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn address(&self, index: usize) -> Mlx5Result<DmaDeviceAddress> {
        match &self.regions[index] {
            Region::Shared { address, .. } => Ok(*address),
            _ => Err(Mlx5Error::DeviceNotReady),
        }
    }

    fn shared(&mut self, index: usize) -> Mlx5Result<&mut SharedDmaLease> {
        match &mut self.regions[index] {
            Region::Shared { lease, .. } => Ok(lease),
            _ => Err(Mlx5Error::DeviceNotReady),
        }
    }

    pub(crate) fn read_byte(&mut self, index: usize, offset: usize) -> Mlx5Result<u8> {
        self.shared(index)?
            .window(offset, 1)
            .and_then(|window| window.read_u8(0))
            .map_err(Mlx5Error::DmaLease)
    }

    pub(crate) fn read<const BYTES: usize>(
        &mut self,
        index: usize,
        offset: usize,
    ) -> Mlx5Result<[u8; BYTES]> {
        let window = self
            .shared(index)?
            .window(offset, BYTES)
            .map_err(Mlx5Error::DmaLease)?;
        let mut bytes = [0; BYTES];
        for (index, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            chunk.copy_from_slice(
                &window
                    .read_u64(index * 8)
                    .map_err(Mlx5Error::DmaLease)?
                    .to_ne_bytes(),
            );
        }
        for (relative, byte) in bytes.iter_mut().enumerate().skip(BYTES / 8 * 8) {
            *byte = window.read_u8(relative).map_err(Mlx5Error::DmaLease)?;
        }
        Ok(bytes)
    }

    pub(crate) fn write_be32(&mut self, index: usize, offset: usize, value: u32) -> Mlx5Result<()> {
        self.shared(index)?
            .window(offset, 4)
            .and_then(|mut window| window.write_u32(0, value.to_be()))
            .map_err(Mlx5Error::DmaLease)
    }

    /// Scalar descriptor stores expose no Rust reference to shared RAM. The
    /// queue owner publishes its doorbell only after the whole descriptor.
    pub(crate) fn write(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Mlx5Result<()> {
        let mut window = self
            .shared(index)?
            .window(offset, bytes.len())
            .map_err(Mlx5Error::DmaLease)?;
        for (index, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let word = u64::from_ne_bytes(*chunk);
            window
                .write_u64(index * 8, word)
                .map_err(Mlx5Error::DmaLease)?;
        }
        for (relative, &byte) in bytes.iter().enumerate().skip(bytes.len() / 8 * 8) {
            window
                .write_u8(relative, byte)
                .map_err(Mlx5Error::DmaLease)?;
        }
        Ok(())
    }

    /// # Safety
    /// No firmware consumer was published, or a completed queue destruction
    /// has stopped and drained every hardware consumer of these allocations.
    /// The caller records that fact before this fallible close, so retry never
    /// repeats a destruction after an unmap failure.
    #[expect(
        unsafe_code,
        reason = "queue protocol owner supplies the hardware quiescence proof"
    )]
    pub(crate) unsafe fn close_quiesced(&mut self) -> Mlx5Result<()> {
        for region in &mut self.regions {
            let owned = core::mem::replace(region, Region::Released);
            let cpu = match owned {
                Region::Cpu(cpu) => cpu,
                Region::Prepared(prepared) => match prepared.abort() {
                    Ok(cpu) => cpu,
                    Err(error) => {
                        let (cause, prepared) = error.into_parts();
                        *region = Region::Prepared(prepared);
                        return Err(Mlx5Error::DmaLease(cause));
                    }
                },
                Region::Shared { lease, address } => {
                    // SAFETY: the caller established queue quiescence before
                    // entering finalization and retained this exact generation.
                    let witness = unsafe {
                        DmaQuiesceWitness::after_queue_quiesced(self.identity, lease.lease_id())
                    };
                    match lease.quiesce(witness) {
                        Ok(cpu) => cpu,
                        Err(error) => {
                            let (cause, lease) = error.into_parts();
                            *region = Region::Shared { lease, address };
                            return Err(Mlx5Error::DmaLease(cause));
                        }
                    }
                }
                Region::UnmapFailed(lease, cause) => {
                    *region = Region::UnmapFailed(lease, cause);
                    return Err(Mlx5Error::DmaLease(cause));
                }
                Region::Released => continue,
            };
            if let Err(error) = cpu.close() {
                let (cause, failed) = error.into_parts();
                *region = Region::UnmapFailed(failed, cause);
                return Err(Mlx5Error::DmaLease(cause));
            }
        }
        Ok(())
    }
}
