use alloc::vec::Vec;
use kernel_api::service::platform::{
    self as kplatform, Bar, BdfAddress, ClassCode, DeviceId, PciDeviceInfo, PciServices, VendorId,
};

struct BuiltinPciProvider;

static BUILTIN_PCI_PROVIDER: BuiltinPciProvider = BuiltinPciProvider;

fn convert_bar(bar: crate::io::pci::Bar) -> Bar {
    match bar {
        crate::io::pci::Bar::Memory32 {
            base,
            size,
            prefetchable,
        } => Bar::Memory32 {
            base,
            size,
            prefetchable,
        },
        crate::io::pci::Bar::Memory64 {
            base,
            size,
            prefetchable,
        } => Bar::Memory64 {
            base,
            size,
            prefetchable,
        },
        crate::io::pci::Bar::Io { base, size } => Bar::Io { base, size },
    }
}

fn convert_device(dev: crate::io::pci::PciDeviceInfo) -> PciDeviceInfo {
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

fn update_command_bit(bdf: BdfAddress, bit: u16, enabled: bool) {
    let cmd = crate::io::pci::pci_read16(bdf.bus(), bdf.device(), bdf.function(), 0x04);
    let new_value = if enabled { cmd | bit } else { cmd & !bit };
    crate::io::pci::pci_write(
        bdf.bus(),
        bdf.device(),
        bdf.function(),
        0x04,
        new_value as u32,
    );
}

impl PciServices for BuiltinPciProvider {
    fn scan_all_devices(&self) -> Vec<PciDeviceInfo> {
        crate::io::pci::scan_all_devices()
            .into_iter()
            .map(convert_device)
            .collect()
    }

    fn find_by_class(&self, class: u8, subclass: u8) -> Vec<PciDeviceInfo> {
        crate::io::pci::find_by_class(class, subclass)
            .into_iter()
            .map(convert_device)
            .collect()
    }

    fn find_virtio_devices(&self) -> Vec<PciDeviceInfo> {
        crate::io::pci::find_virtio_devices()
            .into_iter()
            .map(convert_device)
            .collect()
    }

    fn set_bus_master(&self, bdf: BdfAddress, enabled: bool) -> kernel_api::KapiResult<()> {
        update_command_bit(bdf, crate::io::pci::command_bits::BUS_MASTER, enabled);
        Ok(())
    }

    fn set_memory_space(&self, bdf: BdfAddress, enabled: bool) -> kernel_api::KapiResult<()> {
        update_command_bit(bdf, crate::io::pci::command_bits::MEMORY_SPACE, enabled);
        Ok(())
    }

    fn set_io_space(&self, bdf: BdfAddress, enabled: bool) -> kernel_api::KapiResult<()> {
        update_command_bit(bdf, crate::io::pci::command_bits::IO_SPACE, enabled);
        Ok(())
    }

    fn disable_intx(&self, bdf: BdfAddress) -> kernel_api::KapiResult<()> {
        update_command_bit(bdf, crate::io::pci::command_bits::INTERRUPT_DISABLE, true);
        Ok(())
    }
}

pub fn register_builtin_service() {
    crate::provider_registry::provider_registry().register_builtin_pci(&BUILTIN_PCI_PROVIDER);
}

pub fn init() {
    if kplatform::try_pci().is_none() {
        crate::io::pci::init();
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
