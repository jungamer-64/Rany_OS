//! Modern PCI register owner. Doorbells retain only their notification aperture.
use hal::mmio::OwnedMmioRegister;

use alloc::sync::Arc;
use exorust_sync::Mutex;
use hal::{MappedMmio, ReadOnly, ReadWrite, WriteOnly};
use kernel_api::abi::driver::PackedPciLocation;

use super::*;
use crate::queue_memory::{QueueConfigureCause, QueueDoorbell, QueueInterrupt};

/// Capability byte windows acquired and retained by the PCI function host.
/// A capability's BAR-relative offset is resolved before constructing these
/// windows; these values do not authorize arbitrary physical address mapping.
#[derive(Debug)]
pub struct PciTransportApertures {
    pub common: Arc<MappedMmio>,
    pub notification: Arc<MappedMmio>,
    pub interrupt_status: Arc<MappedMmio>,
    pub device_configuration: Option<Arc<MappedMmio>>,
    pub notification_multiplier: u32,
}

struct Registers {
    feature_select: OwnedMmioRegister<u32, ReadWrite>,
    features: OwnedMmioRegister<u32, ReadOnly>,
    driver_feature_select: OwnedMmioRegister<u32, ReadWrite>,
    driver_features: OwnedMmioRegister<u32, WriteOnly>,
    queues: OwnedMmioRegister<u16, ReadOnly>,
    status: OwnedMmioRegister<u8, ReadWrite>,
    generation: OwnedMmioRegister<u8, ReadOnly>,
    queue_select: OwnedMmioRegister<u16, ReadWrite>,
    queue_size: OwnedMmioRegister<u16, ReadWrite>,
    queue_vector: OwnedMmioRegister<u16, ReadWrite>,
    queue_enable: OwnedMmioRegister<u16, ReadWrite>,
    queue_notify_offset: OwnedMmioRegister<u16, ReadOnly>,
    descriptor_low: OwnedMmioRegister<u32, WriteOnly>,
    descriptor_high: OwnedMmioRegister<u32, WriteOnly>,
    available_low: OwnedMmioRegister<u32, WriteOnly>,
    available_high: OwnedMmioRegister<u32, WriteOnly>,
    used_low: OwnedMmioRegister<u32, WriteOnly>,
    used_high: OwnedMmioRegister<u32, WriteOnly>,
    interrupt_status: OwnedMmioRegister<u8, ReadOnly>,
}

/// PCI transport bound to a function's retained capability windows.
pub struct VirtioPciTransport {
    device: PackedPciLocation,
    device_type: VirtioDeviceType,
    registers: Mutex<Registers>,
    notification: Arc<MappedMmio>,
    notification_multiplier: u32,
    device_configuration: Option<Arc<MappedMmio>>,
}

impl core::fmt::Debug for VirtioPciTransport {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VirtioPciTransport")
            .field("device", &self.device)
            .field("device_type", &self.device_type)
            .finish_non_exhaustive()
    }
}

impl VirtioPciTransport {
    /// Validate every fixed register before a queue can publish device addresses.
    ///
    /// # Errors
    /// Returns all input apertures when a function/type is absent, a fixed
    /// register escapes a window, or its required access width is misaligned.
    pub fn new(
        device: PackedPciLocation,
        device_type: VirtioDeviceType,
        apertures: PciTransportApertures,
    ) -> Result<Self, TransportAcquireError<PciTransportApertures>> {
        let validate = || -> TransportResult<Registers> {
            if device.is_null() || device_type == VirtioDeviceType::Unknown {
                return Err(TransportError::DeviceNotFound);
            }
            notification_offset(0, apertures.notification_multiplier)?;
            apertures.notification.region().write_only::<u16>(0)?;
            let mapping = &apertures.common;
            Ok(Registers {
                feature_select: mapping.owned_read_write(0x00)?,
                features: mapping.owned_read_only(0x04)?,
                driver_feature_select: mapping.owned_read_write(0x08)?,
                driver_features: mapping.owned_write_only(0x0c)?,
                queues: mapping.owned_read_only(0x12)?,
                status: mapping.owned_read_write(0x14)?,
                generation: mapping.owned_read_only(0x15)?,
                queue_select: mapping.owned_read_write(0x16)?,
                queue_size: mapping.owned_read_write(0x18)?,
                queue_vector: mapping.owned_read_write(0x1a)?,
                queue_enable: mapping.owned_read_write(0x1c)?,
                queue_notify_offset: mapping.owned_read_only(0x1e)?,
                descriptor_low: mapping.owned_write_only(0x20)?,
                descriptor_high: mapping.owned_write_only(0x24)?,
                available_low: mapping.owned_write_only(0x28)?,
                available_high: mapping.owned_write_only(0x2c)?,
                used_low: mapping.owned_write_only(0x30)?,
                used_high: mapping.owned_write_only(0x34)?,
                interrupt_status: apertures.interrupt_status.owned_read_only(0)?,
            })
        };
        match validate() {
            Ok(registers) => Ok(Self {
                device,
                device_type,
                registers: Mutex::new(registers),
                notification: apertures.notification,
                notification_multiplier: apertures.notification_multiplier,
                device_configuration: apertures.device_configuration,
            }),
            Err(cause) => Err(TransportAcquireError {
                cause,
                owner: apertures,
            }),
        }
    }

    fn configuration(&self) -> TransportResult<&MappedMmio> {
        self.device_configuration
            .as_deref()
            .ok_or(TransportError::ConfigAccessFailed)
    }
}

impl super::sealed::Transport for VirtioPciTransport {}

impl VirtioTransport for VirtioPciTransport {
    fn device_type(&self) -> VirtioDeviceType {
        self.device_type
    }
    fn transport_type(&self) -> TransportType {
        TransportType::PciModern
    }
    fn status(&self) -> u8 {
        self.registers.lock().status.read()
    }
    fn request_reset(&self) {
        self.registers.lock().status.write(0);
    }
    fn add_status(&self, bits: u8) {
        let mut registers = self.registers.lock();
        let current = registers.status.read();
        registers.status.write(current | bits);
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
        u32::from(self.registers.lock().generation.read())
    }
    fn queue_count(&self) -> Option<u16> {
        Some(self.registers.lock().queues.read())
    }
    fn queue_capacity(&self, index: u16) -> TransportResult<u16> {
        let mut registers = self.registers.lock();
        if index >= registers.queues.read() {
            return Err(TransportError::InvalidQueueIndex);
        }
        registers.queue_select.write(index);
        Ok(registers.queue_size.read())
    }

    fn configure_queue(
        &self,
        configuration: QueueConfiguration,
    ) -> Result<ConfiguredQueueMemory, QueueConfigureError> {
        let mut registers = self.registers.lock();
        let validate = |registers: &mut Registers| -> TransportResult<QueueDoorbell> {
            let identity = configuration.identity();
            if identity.device() != self.device || identity.index() >= registers.queues.read() {
                return Err(TransportError::InvalidQueueIndex);
            }
            registers.queue_select.write(identity.index());
            if registers.queue_enable.read() != 0 {
                return Err(TransportError::QueueAlreadyEnabled);
            }
            let maximum = registers.queue_size.read();
            if configuration.layout().size() > maximum || maximum == 0 {
                return Err(TransportError::QueueSetupFailed);
            }
            let offset = notification_offset(
                registers.queue_notify_offset.read(),
                self.notification_multiplier,
            )?;
            let register = self.notification.owned_write_only(offset)?;
            let vector = match configuration.interrupt() {
                QueueInterrupt::Polled | QueueInterrupt::Platform => u16::MAX,
                QueueInterrupt::Msix(vector) if vector != u16::MAX => vector,
                QueueInterrupt::Msix(_) => return Err(TransportError::UnsupportedInterruptVector),
            };
            registers.queue_vector.write(vector);
            if registers.queue_vector.read() != vector {
                return Err(TransportError::ConfigAccessFailed);
            }
            Ok(QueueDoorbell::Pci {
                index: identity.index(),
                register,
            })
        };
        let doorbell = match validate(&mut registers) {
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
        registers.queue_size.write(size);
        registers.descriptor_low.write(descriptor as u32);
        registers.descriptor_high.write((descriptor >> 32) as u32);
        registers.available_low.write(available as u32);
        registers.available_high.write((available >> 32) as u32);
        registers.used_low.write(used as u32);
        registers.used_high.write((used >> 32) as u32);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        registers.queue_enable.write(1);
        Ok(memory)
    }

    fn acknowledge_interrupt(&self) -> u32 {
        u32::from(self.registers.lock().interrupt_status.read())
    }
    fn read_config_u8(&self, offset: usize) -> TransportResult<u8> {
        Ok(self
            .configuration()?
            .region()
            .read_only::<u8>(offset)?
            .read())
    }
    fn read_config_u16(&self, offset: usize) -> TransportResult<u16> {
        Ok(self
            .configuration()?
            .region()
            .read_only::<u16>(offset)?
            .read())
    }
    fn read_config_u32(&self, offset: usize) -> TransportResult<u32> {
        Ok(self
            .configuration()?
            .region()
            .read_only::<u32>(offset)?
            .read())
    }
    fn read_config_u64(&self, offset: usize) -> TransportResult<u64> {
        let registers = self.registers.lock();
        let start = registers.generation.read();
        let low = self.read_config_u32(offset)?;
        let high = self.read_config_u32(
            offset
                .checked_add(4)
                .ok_or(TransportError::ConfigAccessFailed)?,
        )?;
        if start != registers.generation.read() {
            return Err(TransportError::ConfigurationChanged);
        }
        Ok(u64::from(low) | (u64::from(high) << 32))
    }
    fn write_config_u8(&self, offset: usize, value: u8) -> TransportResult<()> {
        self.configuration()?
            .region()
            .write_only::<u8>(offset)?
            .write(value);
        Ok(())
    }
    fn write_config_u16(&self, offset: usize, value: u16) -> TransportResult<()> {
        self.configuration()?
            .region()
            .write_only::<u16>(offset)?
            .write(value);
        Ok(())
    }
    fn write_config_u32(&self, offset: usize, value: u32) -> TransportResult<()> {
        self.configuration()?
            .region()
            .write_only::<u32>(offset)?
            .write(value);
        Ok(())
    }
}

pub(super) fn notification_offset(queue_offset: u16, multiplier: u32) -> TransportResult<usize> {
    if multiplier != 0 && (multiplier < 2 || !multiplier.is_power_of_two()) {
        return Err(TransportError::ConfigAccessFailed);
    }
    usize::from(queue_offset)
        .checked_mul(usize::try_from(multiplier).map_err(|_| TransportError::ConfigAccessFailed)?)
        .ok_or(TransportError::ConfigAccessFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pci_notification_coordinate_is_capability_relative() {
        assert_eq!(notification_offset(7, 4), Ok(28));
        assert_eq!(notification_offset(32767, 0), Ok(0));
        for multiplier in [1, 3, 6, u32::MAX] {
            assert_eq!(
                notification_offset(0, multiplier),
                Err(TransportError::ConfigAccessFailed)
            );
        }
        assert_eq!(
            notification_offset(65535, 0x8000_0000),
            usize::try_from(140735340871680u64).map_err(|_| TransportError::ConfigAccessFailed)
        );
    }
}
