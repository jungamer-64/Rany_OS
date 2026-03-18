use alloc::vec::Vec;
use kernel_api::service::platform::{
    self as kplatform, Bar, BdfAddress, ClassCode, DeviceId, PciDeviceInfo, PciServices, VendorId,
};

struct BuiltinPciProvider;

static BUILTIN_PCI_PROVIDER: BuiltinPciProvider = BuiltinPciProvider;

fn convert_bar(bar: crate::drivers::pci::Bar) -> Bar {
    match bar {
        crate::drivers::pci::Bar::Memory32 {
            base,
            size,
            prefetchable,
        } => Bar::Memory32 {
            base,
            size,
            prefetchable,
        },
        crate::drivers::pci::Bar::Memory64 {
            base,
            size,
            prefetchable,
        } => Bar::Memory64 {
            base,
            size,
            prefetchable,
        },
        crate::drivers::pci::Bar::Io { base, size } => Bar::Io { base, size },
    }
}

fn convert_bar_to_native(bar: Bar) -> crate::drivers::pci::Bar {
    match bar {
        Bar::Memory32 {
            base,
            size,
            prefetchable,
        } => crate::drivers::pci::Bar::Memory32 {
            base,
            size,
            prefetchable,
        },
        Bar::Memory64 {
            base,
            size,
            prefetchable,
        } => crate::drivers::pci::Bar::Memory64 {
            base,
            size,
            prefetchable,
        },
        Bar::Io { base, size } => crate::drivers::pci::Bar::Io { base, size },
    }
}

pub fn from_native_device(dev: crate::drivers::pci::PciDeviceInfo) -> PciDeviceInfo {
    PciDeviceInfo {
        segment: dev.segment,
        bdf: BdfAddress::new(dev.bdf.bus(), dev.bdf.device(), dev.bdf.function()),
        vendor_id: VendorId(dev.vendor_id.0),
        device_id: DeviceId(dev.device_id.0),
        revision_id: dev.revision_id,
        class_code: ClassCode::new(
            dev.class_code.class,
            dev.class_code.subclass,
            dev.class_code.prog_if,
        ),
        header_type: dev.header_type,
        subsystem_vendor_id: dev.subsystem_vendor_id,
        subsystem_id: dev.subsystem_id,
        interrupt_line: dev.interrupt_line,
        interrupt_pin: dev.interrupt_pin,
        bars: dev.bars.map(|bar| bar.map(convert_bar)),
        capabilities: dev
            .capabilities
            .into_iter()
            .map(|(cap, offset)| (cap as u8, offset))
            .collect(),
        msi_cap_offset: dev.msi_cap_offset,
        msix_cap_offset: dev.msix_cap_offset,
        pcie_cap_offset: dev.pcie_cap_offset,
        iommu_domain_id: dev.iommu_domain_id,
    }
}

pub fn to_native_device(dev: &PciDeviceInfo) -> crate::drivers::pci::PciDeviceInfo {
    crate::drivers::pci::PciDeviceInfo {
        segment: dev.segment,
        bdf: crate::drivers::pci::BdfAddress::new(
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
        ),
        vendor_id: crate::drivers::pci::VendorId(dev.vendor_id.0),
        device_id: crate::drivers::pci::DeviceId(dev.device_id.0),
        revision_id: dev.revision_id,
        class_code: crate::drivers::pci::ClassCode::new(
            dev.class_code.class,
            dev.class_code.subclass,
            dev.class_code.prog_if,
        ),
        header_type: dev.header_type,
        subsystem_vendor_id: dev.subsystem_vendor_id,
        subsystem_id: dev.subsystem_id,
        interrupt_line: dev.interrupt_line,
        interrupt_pin: dev.interrupt_pin,
        bars: dev.bars.map(|bar| bar.map(convert_bar_to_native)),
        capabilities: dev
            .capabilities
            .iter()
            .filter_map(|(cap, offset)| {
                crate::drivers::pci::bus::CapabilityId::from_u8(*cap)
                    .map(|cap_id| (cap_id, *offset))
            })
            .collect(),
        msi_cap_offset: dev.msi_cap_offset,
        msix_cap_offset: dev.msix_cap_offset,
        pcie_cap_offset: dev.pcie_cap_offset,
        iommu_domain_id: dev.iommu_domain_id,
    }
}

fn update_command_bit(bdf: BdfAddress, bit: u16, enabled: bool) {
    let cmd =
        crate::drivers::pci::legacy::pci_read16(bdf.bus(), bdf.device(), bdf.function(), 0x04);
    let new_value = if enabled { cmd | bit } else { cmd & !bit };
    crate::drivers::pci::legacy::pci_write(
        bdf.bus(),
        bdf.device(),
        bdf.function(),
        0x04,
        new_value as u32,
    );
}

impl PciServices for BuiltinPciProvider {
    fn scan_all_devices(&self) -> Vec<PciDeviceInfo> {
        crate::drivers::pci::scan_all_devices()
            .into_iter()
            .map(from_native_device)
            .collect()
    }

    fn find_by_class(&self, class: u8, subclass: u8) -> Vec<PciDeviceInfo> {
        crate::drivers::pci::find_by_class(class, subclass)
            .into_iter()
            .map(from_native_device)
            .collect()
    }

    fn find_virtio_devices(&self) -> Vec<PciDeviceInfo> {
        crate::drivers::pci::find_virtio_devices()
            .into_iter()
            .map(from_native_device)
            .collect()
    }

    fn set_bus_master(&self, bdf: BdfAddress, enabled: bool) -> kernel_api::KapiResult<()> {
        update_command_bit(bdf, crate::drivers::pci::command_bits::BUS_MASTER, enabled);
        Ok(())
    }

    fn set_memory_space(&self, bdf: BdfAddress, enabled: bool) -> kernel_api::KapiResult<()> {
        update_command_bit(bdf, crate::drivers::pci::command_bits::MEMORY_SPACE, enabled);
        Ok(())
    }

    fn set_io_space(&self, bdf: BdfAddress, enabled: bool) -> kernel_api::KapiResult<()> {
        update_command_bit(bdf, crate::drivers::pci::command_bits::IO_SPACE, enabled);
        Ok(())
    }

    fn disable_intx(&self, bdf: BdfAddress) -> kernel_api::KapiResult<()> {
        update_command_bit(bdf, crate::drivers::pci::command_bits::INTERRUPT_DISABLE, true);
        Ok(())
    }
}

pub fn register_builtin_service() {
    crate::provider_registry::provider_registry().register_builtin_pci(&BUILTIN_PCI_PROVIDER);
}

pub fn init() {
    if kplatform::try_pci().is_none() {
        crate::drivers::pci::init();
    }
}

pub fn scan_all_devices() -> Vec<PciDeviceInfo> {
    kplatform::try_pci()
        .map(PciServices::scan_all_devices)
        .unwrap_or_else(|| BUILTIN_PCI_PROVIDER.scan_all_devices())
}

pub fn find_by_class(class: u8, subclass: u8) -> Vec<PciDeviceInfo> {
    kplatform::try_pci()
        .map(|svc| svc.find_by_class(class, subclass))
        .unwrap_or_else(|| BUILTIN_PCI_PROVIDER.find_by_class(class, subclass))
}

pub fn find_virtio_devices() -> Vec<PciDeviceInfo> {
    kplatform::try_pci()
        .map(PciServices::find_virtio_devices)
        .unwrap_or_else(|| BUILTIN_PCI_PROVIDER.find_virtio_devices())
}

pub fn disable_intx(device: &PciDeviceInfo) -> kernel_api::KapiResult<()> {
    if let Some(pci) = kplatform::try_pci() {
        return pci.disable_intx(device.bdf);
    }

    BUILTIN_PCI_PROVIDER.disable_intx(device.bdf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn to_native_device_preserves_bar_base_addresses() {
        let dev = PciDeviceInfo {
            segment: 0,
            bdf: BdfAddress::new(0, 1, 0),
            vendor_id: VendorId(0x8086),
            device_id: DeviceId(0x2668),
            revision_id: 0,
            class_code: ClassCode::new(0x04, 0x03, 0x00),
            header_type: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            interrupt_line: 10,
            interrupt_pin: 1,
            bars: [
                Some(Bar::Memory64 {
                    base: 0x1234_5000,
                    size: 0x1000,
                    prefetchable: false,
                }),
                Some(Bar::Io {
                    base: 0x3f8,
                    size: 0x8,
                }),
                None,
                None,
                None,
                None,
            ],
            capabilities: alloc::vec![(0x05, 0x50)],
            msi_cap_offset: Some(0x50),
            msix_cap_offset: None,
            pcie_cap_offset: None,
            iommu_domain_id: Some(7),
        };

        let native = to_native_device(&dev);

        assert_eq!(native.bars[0].map(|bar| bar.base()), Some(0x1234_5000));
        assert_eq!(native.bars[1].map(|bar| bar.base()), Some(0x3f8));
        assert_eq!(native.iommu_domain_id, Some(7));
    }
}
