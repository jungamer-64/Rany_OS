//! The command interface owns its three linear RAM capabilities. Failed
//! preparation and failed finalization keep the exact capability state here.

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

pub(super) struct CommandMemory {
    identity: DmaQueueIdentity,
    regions: [Region; 3],
}

impl CommandMemory {
    pub(super) fn new(identity: DmaQueueIdentity, leases: [CpuDmaLease; 3]) -> Self {
        Self {
            identity,
            regions: leases.map(Region::Cpu),
        }
    }

    /// All geometry is checked while prepared; activation precedes the first
    /// command-address register write. No CPU address leaves the registry.
    pub(super) fn prepare(&mut self, queue_bytes: usize) -> Mlx5Result<()> {
        for (index, region) in self.regions.iter_mut().enumerate() {
            let Region::Cpu(cpu) = region else {
                return Err(Mlx5Error::DeviceNotReady);
            };
            let minimum = if index == 0 {
                queue_bytes
            } else {
                crate::defs::MLX5_CMD_MBOX_BACKING_SIZE
            };
            if cpu.byte_count().get() < minimum || cpu.direction() != DmaDirection::Bidirectional {
                return Err(Mlx5Error::InvalidParameter);
            }
            cpu.write(|bytes| bytes.fill(0))
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
            let alignment = if index == 0 {
                crate::defs::MLX5_PAGE_SIZE
            } else {
                crate::defs::MLX5_CMD_PROT_BLOCK_ALIGN
            };
            if address.get() == 0
                || !address.get().is_multiple_of(alignment as u64)
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

    pub(super) fn address(&self, index: usize) -> Mlx5Result<DmaDeviceAddress> {
        match &self.regions[index] {
            Region::Shared { address, .. } => Ok(*address),
            _ => Err(Mlx5Error::DeviceNotReady),
        }
    }

    pub(super) fn read_byte(&mut self, index: usize, offset: usize) -> Mlx5Result<u8> {
        let Region::Shared { lease, .. } = &mut self.regions[index] else {
            return Err(Mlx5Error::DeviceNotReady);
        };
        lease
            .window(offset, 1)
            .and_then(|window| window.read_u8(0))
            .map_err(Mlx5Error::DmaLease)
    }

    pub(super) fn write_byte(&mut self, index: usize, offset: usize, value: u8) -> Mlx5Result<()> {
        let Region::Shared { lease, .. } = &mut self.regions[index] else {
            return Err(Mlx5Error::DeviceNotReady);
        };
        lease
            .window(offset, 1)
            .and_then(|mut window| window.write_u8(0, value))
            .map_err(Mlx5Error::DmaLease)
    }

    pub(super) fn read<const N: usize>(
        &mut self,
        index: usize,
        offset: usize,
    ) -> Mlx5Result<[u8; N]> {
        let Region::Shared { lease, .. } = &mut self.regions[index] else {
            return Err(Mlx5Error::DeviceNotReady);
        };
        let window = lease.window(offset, N).map_err(Mlx5Error::DmaLease)?;
        let mut bytes = [0; N];
        for (chunk_index, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            chunk.copy_from_slice(
                &window
                    .read_u64(chunk_index * 8)
                    .map_err(Mlx5Error::DmaLease)?
                    .to_ne_bytes(),
            );
        }
        for (relative, byte) in bytes.iter_mut().enumerate().skip(N / 8 * 8) {
            *byte = window.read_u8(relative).map_err(Mlx5Error::DmaLease)?;
        }
        Ok(bytes)
    }

    pub(super) fn write(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Mlx5Result<()> {
        let Region::Shared { lease, .. } = &mut self.regions[index] else {
            return Err(Mlx5Error::DeviceNotReady);
        };
        let mut window = lease
            .window(offset, bytes.len())
            .map_err(Mlx5Error::DmaLease)?;
        for (chunk_index, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let value = u64::from_ne_bytes(*chunk);
            window
                .write_u64(chunk_index * 8, value)
                .map_err(Mlx5Error::DmaLease)?;
        }
        for (relative, &value) in bytes.iter().enumerate().skip(bytes.len() / 8 * 8) {
            window
                .write_u8(relative, value)
                .map_err(Mlx5Error::DmaLease)?;
        }
        Ok(())
    }

    /// # Safety
    /// The command address has never been written to the device. No other
    /// protocol owner has received any of these three descriptors.
    #[expect(
        unsafe_code,
        reason = "proves absence of hardware publication at the command construction boundary"
    )]
    pub(super) unsafe fn close_unpublished(&mut self) -> Mlx5Result<()> {
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
                    // SAFETY: neither CMDQ nor its mailbox coordinates were
                    // published; this fresh identity has no hardware consumer.
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
