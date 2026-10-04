//! Modern MMIO register owner. Selector-dependent work is one guarded operation.
use hal::mmio::OwnedMmioRegister;

use alloc::sync::Arc;
use exorust_sync::Mutex;
use hal::{MappedMmio, ReadOnly, ReadWrite, WriteOnly};
use kernel_api::abi::driver::PackedPciLocation;

use super::*;
use crate::queue_memory::{QueueConfigureCause, QueueDoorbell, QueueInterrupt};

struct Registers {
    features: OwnedMmioRegister<u32, ReadOnly>,
    feature_select: OwnedMmioRegister<u32, ReadWrite>,
    driver_features: OwnedMmioRegister<u32, WriteOnly>,
    driver_feature_select: OwnedMmioRegister<u32, ReadWrite>,
    queue_select: OwnedMmioRegister<u32, ReadWrite>,
    queue_capacity: OwnedMmioRegister<u32, ReadOnly>,
    queue_size: OwnedMmioRegister<u32, WriteOnly>,
    queue_ready: OwnedMmioRegister<u32, ReadWrite>,
    descriptor_low: OwnedMmioRegister<u32, WriteOnly>,
    descriptor_high: OwnedMmioRegister<u32, WriteOnly>,
    available_low: OwnedMmioRegister<u32, WriteOnly>,
    available_high: OwnedMmioRegister<u32, WriteOnly>,
    used_low: OwnedMmioRegister<u32, WriteOnly>,
    used_high: OwnedMmioRegister<u32, WriteOnly>,
    status: OwnedMmioRegister<u32, ReadWrite>,
    interrupt_status: OwnedMmioRegister<u32, ReadOnly>,
    interrupt_ack: OwnedMmioRegister<u32, WriteOnly>,
    config_generation: OwnedMmioRegister<u32, ReadOnly>,
}

/// Retains a complete modern MMIO aperture and its device-scoped DMA identity.
pub struct VirtioMmioTransport {
    device: PackedPciLocation,
    device_type: VirtioDeviceType,
    mapping: Arc<MappedMmio>,
    registers: Mutex<Registers>,
}

impl core::fmt::Debug for VirtioMmioTransport {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VirtioMmioTransport")
            .field("device", &self.device)
            .field("device_type", &self.device_type)
            .finish_non_exhaustive()
    }
}

impl VirtioMmioTransport {
    /// Check register geometry, magic and the modern MMIO version before setup.
    ///
    /// # Errors
    /// Returns the original retained aperture for invalid geometry, magic,
    /// unsupported version or a device reporting no device type.
    pub fn new(
        mapping: Arc<MappedMmio>,
        device: PackedPciLocation,
    ) -> Result<Self, TransportAcquireError<Arc<MappedMmio>>> {
        let validate = || -> TransportResult<(VirtioDeviceType, Registers)> {
            if device.is_null() {
                return Err(TransportError::DeviceNotFound);
            }
            let region = mapping.region();
            if region.read_only::<u32>(0)?.read() != 0x7472_6976 {
                return Err(TransportError::InvalidMagic);
            }
            if region.read_only::<u32>(4)?.read() != 2 {
                return Err(TransportError::UnsupportedVersion);
            }
            let device_type = VirtioDeviceType::from(region.read_only::<u32>(8)?.read());
            if device_type == VirtioDeviceType::Unknown {
                return Err(TransportError::DeviceNotFound);
            }
            let registers = Registers {
                features: mapping.owned_read_only(0x010)?,
                feature_select: mapping.owned_read_write(0x014)?,
                driver_features: mapping.owned_write_only(0x020)?,
                driver_feature_select: mapping.owned_read_write(0x024)?,
                queue_select: mapping.owned_read_write(0x030)?,
                queue_capacity: mapping.owned_read_only(0x034)?,
                queue_size: mapping.owned_write_only(0x038)?,
                queue_ready: mapping.owned_read_write(0x044)?,
                descriptor_low: mapping.owned_write_only(0x080)?,
                descriptor_high: mapping.owned_write_only(0x084)?,
                available_low: mapping.owned_write_only(0x090)?,
                available_high: mapping.owned_write_only(0x094)?,
                used_low: mapping.owned_write_only(0x0a0)?,
                used_high: mapping.owned_write_only(0x0a4)?,
                status: mapping.owned_read_write(0x070)?,
                interrupt_status: mapping.owned_read_only(0x060)?,
                interrupt_ack: mapping.owned_write_only(0x064)?,
                config_generation: mapping.owned_read_only(0x0fc)?,
            };
            // The notify register is delegated only at queue configuration.
            mapping.region().write_only::<u32>(0x050)?;
            Ok((device_type, registers))
        };
        match validate() {
            Ok((device_type, registers)) => Ok(Self {
                device,
                device_type,
                mapping,
                registers: Mutex::new(registers),
            }),
            Err(cause) => Err(TransportAcquireError {
                cause,
                owner: mapping,
            }),
        }
    }

    fn config_offset(&self, offset: usize) -> TransportResult<usize> {
        offset
            .checked_add(0x100)
            .ok_or(TransportError::ConfigAccessFailed)
    }
}

impl super::sealed::Transport for VirtioMmioTransport {}

impl VirtioTransport for VirtioMmioTransport {
    fn device_type(&self) -> VirtioDeviceType {
        self.device_type
    }
    fn transport_type(&self) -> TransportType {
        TransportType::Mmio
    }
    fn status(&self) -> u8 {
        self.registers.lock().status.read() as u8
    }
    fn request_reset(&self) {
        self.registers.lock().status.write(0);
    }
    fn add_status(&self, bits: u8) {
        let mut registers = self.registers.lock();
        let current = registers.status.read();
        registers.status.write(current | u32::from(bits));
    }
    fn device_features(&self) -> u64 {
        let mut registers = self.registers.lock();
        registers.feature_select.write(0);
        let low = registers.features.read();
        registers.feature_select.write(1);
        u64::from(low) | (u64::from(registers.features.read()) << 32)
    }
    fn set_driver_features(&self, features: u64) {
        let mut registers = self.registers.lock();
        registers.driver_feature_select.write(0);
        registers.driver_features.write(features as u32);
        registers.driver_feature_select.write(1);
        registers.driver_features.write((features >> 32) as u32);
    }
    fn config_generation(&self) -> u32 {
        self.registers.lock().config_generation.read()
    }
    fn queue_count(&self) -> Option<u16> {
        None
    }
    fn queue_capacity(&self, index: u16) -> TransportResult<u16> {
        let mut registers = self.registers.lock();
        registers.queue_select.write(u32::from(index));
        u16::try_from(registers.queue_capacity.read()).map_err(|_| TransportError::QueueSetupFailed)
    }

    fn configure_queue(
        &self,
        configuration: QueueConfiguration,
    ) -> Result<ConfiguredQueueMemory, QueueConfigureError> {
        let mut registers = self.registers.lock();
        let validate = || -> TransportResult<()> {
            if matches!(configuration.interrupt(), QueueInterrupt::Msix(_)) {
                return Err(TransportError::UnsupportedInterruptVector);
            }
            if configuration.identity().device() != self.device {
                return Err(TransportError::InvalidQueueIndex);
            }
            Ok(())
        };
        if let Err(cause) = validate() {
            return Err(QueueConfigureError {
                cause: QueueConfigureCause::Transport(cause),
                configuration,
            });
        }
        registers
            .queue_select
            .write(u32::from(configuration.identity().index()));
        let validate = || -> TransportResult<QueueDoorbell> {
            if registers.queue_ready.read() != 0 {
                return Err(TransportError::QueueAlreadyEnabled);
            }
            let maximum = registers.queue_capacity.read();
            if u32::from(configuration.layout().size()) > maximum || maximum == 0 {
                return Err(TransportError::QueueSetupFailed);
            }
            Ok(QueueDoorbell::Mmio {
                index: configuration.identity().index(),
                register: self.mapping.owned_write_only(0x050)?,
            })
        };
        let doorbell = match validate() {
            Ok(doorbell) => doorbell,
            Err(cause) => {
                return Err(QueueConfigureError {
                    cause: QueueConfigureCause::Transport(cause),
                    configuration,
                });
            }
        };
        let size = configuration.layout().size();
        let descriptor = configuration.descriptor_address().get();
        let available = configuration.available_address().get();
        let used = configuration.used_address().get();
        let memory = configuration.activate(doorbell)?;
        registers.queue_size.write(u32::from(size));
        registers.descriptor_low.write(descriptor as u32);
        registers.descriptor_high.write((descriptor >> 32) as u32);
        registers.available_low.write(available as u32);
        registers.available_high.write((available >> 32) as u32);
        registers.used_low.write(used as u32);
        registers.used_high.write((used >> 32) as u32);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        registers.queue_ready.write(1);
        Ok(memory)
    }

    fn acknowledge_interrupt(&self) -> u32 {
        let mut registers = self.registers.lock();
        let status = registers.interrupt_status.read();
        registers.interrupt_ack.write(status);
        status
    }
    fn read_config_u8(&self, offset: usize) -> TransportResult<u8> {
        Ok(self
            .mapping
            .region()
            .read_only::<u8>(self.config_offset(offset)?)?
            .read())
    }
    fn read_config_u16(&self, offset: usize) -> TransportResult<u16> {
        Ok(self
            .mapping
            .region()
            .read_only::<u16>(self.config_offset(offset)?)?
            .read())
    }
    fn read_config_u32(&self, offset: usize) -> TransportResult<u32> {
        Ok(self
            .mapping
            .region()
            .read_only::<u32>(self.config_offset(offset)?)?
            .read())
    }
    fn read_config_u64(&self, offset: usize) -> TransportResult<u64> {
        let registers = self.registers.lock();
        let start = registers.config_generation.read();
        let low = self.read_config_u32(offset)?;
        let high = self.read_config_u32(
            offset
                .checked_add(4)
                .ok_or(TransportError::ConfigAccessFailed)?,
        )?;
        if start != registers.config_generation.read() {
            return Err(TransportError::ConfigurationChanged);
        }
        Ok(u64::from(low) | (u64::from(high) << 32))
    }
    fn write_config_u8(&self, offset: usize, value: u8) -> TransportResult<()> {
        self.mapping
            .region()
            .write_only::<u8>(self.config_offset(offset)?)?
            .write(value);
        Ok(())
    }
    fn write_config_u16(&self, offset: usize, value: u16) -> TransportResult<()> {
        self.mapping
            .region()
            .write_only::<u16>(self.config_offset(offset)?)?
            .write(value);
        Ok(())
    }
    fn write_config_u32(&self, offset: usize, value: u32) -> TransportResult<()> {
        self.mapping
            .region()
            .write_only::<u32>(self.config_offset(offset)?)?
            .write(value);
        Ok(())
    }
}
