use super::*;
use kernel_api::service::platform::PciDeviceInfo;

mod global_init;
pub use self::global_init::*;
mod virtio_gpu_init;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterruptCapabilityMode {
    Msi { offset: u8 },
    MsixOnly,
    LegacyOnly,
}

fn interrupt_capability_mode(dev: &PciDeviceInfo) -> InterruptCapabilityMode {
    if let Some(offset) = dev.msi_cap_offset {
        InterruptCapabilityMode::Msi { offset }
    } else if dev.msix_cap_offset.is_some() {
        InterruptCapabilityMode::MsixOnly
    } else {
        InterruptCapabilityMode::LegacyOnly
    }
}

// We do not publicly re-export the contents of `virtio_gpu_init`; the
// methods are used internally by `SystemIntegration` only.
impl SystemIntegration {
    /// Create a new system integration controller
    pub fn new() -> Self {
        SystemIntegration {
            status: IntegrationStatus::Uninitialized,
            device_manager: DeviceManager::new(),
            interrupt_router: InterruptRouter::new(),
            security: SecurityIntegration::new(),
            boot_log: Vec::new(),
        }
    }

    /// Run full system integration
    pub fn integrate(&mut self) -> Result<(), IntegrationError> {
        self.log("Starting system integration...");

        // Phase 1: Parse ACPI tables
        self.integrate_acpi()?;

        // Phase 2: Scan PCI bus and configure devices
        self.integrate_pci()?;

        // Phase 3: Configure interrupt routing
        self.integrate_interrupts()?;

        // Phase 4: Initialize detected devices
        self.integrate_devices()?;

        // Phase 5: Bind security contexts
        self.integrate_security()?;

        self.status = IntegrationStatus::Complete;
        self.log("System integration complete!");

        // Diagnostic: print network port runtime and stack configuration/stats
        // NOTE: ブートストラップ時はエグゼキュータ未起動のため同期版を使用（許容）
        let port_keys = crate::net::runtime::device::list_port_keys(None);
        let mut rx_packets = 0u64;
        let mut tx_packets = 0u64;
        let mut tx_errors = 0u64;
        let mut rx_errors = 0u64;
        for key in &port_keys {
            if let Some(stats) = crate::net::runtime::device::port_stats(*key) {
                rx_packets = rx_packets.saturating_add(stats.rx_packets);
                tx_packets = tx_packets.saturating_add(stats.tx_packets);
                tx_errors = tx_errors.saturating_add(stats.tx_errors);
                rx_errors = rx_errors.saturating_add(stats.rx_errors);
            }
        }
        self.log(&alloc::format!(
            "  Net port runtime: stack_init={} ports={} rx={} tx={} tx_err={} rx_err={}",
            crate::net::runtime::device::is_initialized(),
            port_keys.len(),
            rx_packets,
            tx_packets,
            tx_errors,
            rx_errors
        ));
        if let Some(cfg) = crate::net::runtime::bridge::get_real_config() {
            self.log(&alloc::format!(
                "  Net Config: IP={:?} MAC={:02x?}",
                cfg.ip,
                cfg.mac
            ));
        } else {
            self.log("  Net Config: none");
        }
        let stats = crate::net::api::config::list_interface_stats_sync();
        if !stats.is_empty() {
            let rx_packets = stats.iter().map(|s| s.rx_packets).sum::<u64>();
            let tx_packets = stats.iter().map(|s| s.tx_packets).sum::<u64>();
            let rx_bytes = stats.iter().map(|s| s.rx_bytes).sum::<u64>();
            let tx_bytes = stats.iter().map(|s| s.tx_bytes).sum::<u64>();
            self.log(&alloc::format!(
                "  Net Stack stats: rx={} tx={} rx_bytes={} tx_bytes={}",
                rx_packets,
                tx_packets,
                rx_bytes,
                tx_bytes
            ));
        } else {
            self.log("  Net Stack stats: none");
        }

        Ok(())
    }

    /// Phase 1: ACPI integration
    pub(super) fn integrate_acpi(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 1: ACPI integration");

        // Get ACPI information
        let local_apics = crate::platform::acpi::local_apics();
        let io_apics = crate::platform::acpi::io_apics();
        let pcie_ecam = crate::platform::acpi::pcie_ecam_regions();

        self.log(&alloc::format!(
            "  Found {} processor(s)",
            local_apics.len()
        ));
        self.log(&alloc::format!("  Found {} I/O APIC(s)", io_apics.len()));
        self.log(&alloc::format!(
            "  Found {} PCIe ECAM region(s)",
            pcie_ecam.len()
        ));

        // Store APIC information for interrupt routing
        for apic in &io_apics {
            self.interrupt_router
                .add_io_apic(apic.id, apic.address, apic.gsi_base);
        }

        // Store interrupt overrides
        let overrides = crate::platform::acpi::interrupt_overrides();
        for ovr in &overrides {
            self.interrupt_router
                .add_override(ovr.source, ovr.gsi, ovr.polarity, ovr.trigger_mode);
        }

        self.status = IntegrationStatus::AcpiParsed;
        Ok(())
    }

    /// Phase 2: PCI integration
    pub(super) fn integrate_pci(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 2: PCI bus integration");

        // Initialize PCI bus
        crate::platform::pci::init();

        // Get all PCI devices
        let mut devices = crate::platform::pci::scan_all_devices();
        self.log(&alloc::format!("  Found {} PCI device(s)", devices.len()));

        #[cfg(not(test))]
        {
            let mut iommu_devices: Vec<_> = devices
                .iter()
                .map(crate::platform::pci::to_native_device)
                .collect();
            if let Err(e) =
                crate::io::iommu::api::setup_iommu_for_all_pci_devices(&mut iommu_devices)
            {
                self.log(&alloc::format!(
                    "  [IOMMU][WARNING] Failed to protect one or more PCI devices: {:?}. System may be vulnerable.",
                    e
                ));
            }
            for (device, iommu_device) in devices.iter_mut().zip(iommu_devices.iter()) {
                device.iommu_domain_id = iommu_device.iommu_domain_id;
            }
        }

        // Categorize devices
        let mut storage_count = 0;
        let mut network_count = 0;
        let mut virtio_count = 0;

        for dev in &devices {
            // Register device
            let device_info = DeviceInfo::from_pci_device(dev);
            self.device_manager.register(device_info);

            // Count by type
            match dev.class_code.class {
                0x01 => storage_count += 1, // Mass Storage
                0x02 => network_count += 1, // Network
                _ => {}
            }

            if dev.is_virtio() {
                virtio_count += 1;
            }
        }

        self.log(&alloc::format!("  Storage controllers: {}", storage_count));
        self.log(&alloc::format!("  Network controllers: {}", network_count));
        self.log(&alloc::format!("  VirtIO devices: {}", virtio_count));

        self.status = IntegrationStatus::PciScanned;
        Ok(())
    }

    /// Phase 3: Interrupt integration
    pub(super) fn integrate_interrupts(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 3: Interrupt routing configuration");

        // Initialize unified interrupt allocator before MSI/MSI-X vector allocation.
        crate::io::interrupt_manager::init();

        // Configure IOAPIC redirection entries
        let routes = self.interrupt_router.configure_routing();
        self.log(&alloc::format!(
            "  Configured {} interrupt route(s)",
            routes
        ));

        // Allocate MSI vectors for capable devices
        let msi_devices: Vec<_> = self
            .device_manager
            .get_msi_capable()
            .into_iter()
            .map(|d| (d.id, d.name.clone(), d.pci_location))
            .collect();
        self.log(&alloc::format!(
            "  {} device(s) support MSI/MSI-X",
            msi_devices.len()
        ));

        // Get PCI devices with MSI capability and allocate vectors
        let pci_devices = crate::platform::pci::scan_all_devices();
        for pci_dev in &pci_devices {
            for (dev_id, dev_name, pci_loc) in &msi_devices {
                if pci_loc
                    .map(|l| {
                        l.bus == pci_dev.bdf.bus()
                            && l.device == pci_dev.bdf.device()
                            && l.function == pci_dev.bdf.function()
                    })
                    .unwrap_or(false)
                {
                    match interrupt_capability_mode(pci_dev) {
                        InterruptCapabilityMode::Msi { offset } => {
                            let bdf = pci_dev.bdf.to_u16() as u32;
                            match crate::io::interrupt_manager::allocate_msi(
                                bdf,
                                dev_name.as_str(),
                                Some(0),
                            ) {
                                Ok(allocation) => {
                                    let vector = allocation.vector();
                                    unsafe {
                                        super::interrupt_routing::program_msi(
                                            pci_dev.bdf.bus(),
                                            pci_dev.bdf.device(),
                                            pci_dev.bdf.function(),
                                            offset,
                                            vector,
                                        );
                                    }
                                    let _ = crate::platform::pci::disable_intx(pci_dev);
                                    crate::io::interrupt_manager::register_handler(
                                        vector,
                                        alloc::boxed::Box::new(|| {
                                            crate::interrupts::dispatch_shared_pci_handlers();
                                        }),
                                    );
                                    self.interrupt_router.add_msi_route(*dev_id, vector);
                                    self.log(&alloc::format!(
                                        "    MSI enabled: {} {:02x}:{:02x}.{} -> vector {}",
                                        dev_name,
                                        pci_dev.bdf.bus(),
                                        pci_dev.bdf.device(),
                                        pci_dev.bdf.function(),
                                        vector
                                    ));
                                }
                                Err(e) => {
                                    self.log(&alloc::format!(
                                        "    MSI allocation failed for {} {:02x}:{:02x}.{}: {:?} (legacy IRQ fallback)",
                                        dev_name,
                                        pci_dev.bdf.bus(),
                                        pci_dev.bdf.device(),
                                        pci_dev.bdf.function(),
                                        e
                                    ));
                                }
                            }
                        }
                        InterruptCapabilityMode::MsixOnly => {
                            self.log(&alloc::format!(
                                "    Device {} {:02x}:{:02x}.{} is MSI-X-only; generic integration defers setup to the device driver",
                                dev_name,
                                pci_dev.bdf.bus(),
                                pci_dev.bdf.device(),
                                pci_dev.bdf.function()
                            ));
                        }
                        InterruptCapabilityMode::LegacyOnly => {
                            self.log(&alloc::format!(
                                "    Device {} {:02x}:{:02x}.{} has no MSI/MSI-X capability (legacy IRQ fallback)",
                                dev_name,
                                pci_dev.bdf.bus(),
                                pci_dev.bdf.device(),
                                pci_dev.bdf.function()
                            ));
                        }
                    }
                    break;
                }
            }
        }

        self.status = IntegrationStatus::InterruptsConfigured;
        Ok(())
    }

    /// Phase 4: Device initialization
    pub(super) fn integrate_devices(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 4: Device initialization");

        // Initialize VirtIO devices
        let virtio_devices = crate::platform::pci::find_virtio_devices();
        self.log(&alloc::format!(
            "  Found {} virtio device(s) during PCI scan",
            virtio_devices.len()
        ));
        for dev in &virtio_devices {
            self.log(&alloc::format!(
                "    virtio candidate {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:02x}.{:02x}",
                dev.bdf.bus(),
                dev.bdf.device(),
                dev.bdf.function(),
                dev.vendor_id.0,
                dev.device_id.0,
                dev.class_code.class,
                dev.class_code.subclass,
            ));
        }
        for dev in virtio_devices {
            match dev.device_id.0 {
                0x1001 | 0x1042 => self.init_virtio_blk_device(&dev),
                0x1000 | 0x1041 => self.init_virtio_net_device(&dev),
                0x1003 | 0x1043 => self.init_virtio_console_device(&dev),
                0x1052 => self.init_virtio_input_device(&dev),
                0x1005 | 0x1045 => self.init_virtio_balloon_device(&dev),
                0x1050 => self.init_virtio_gpu_device(&dev),
                _ => {}
            }
        }

        // Initialize NVMe controllers
        self.init_nvme_devices();

        // Initialize HDA Audio
        self.init_hda_devices();

        self.status = IntegrationStatus::DevicesInitialized;
        Ok(())
    }

    pub(super) fn init_virtio_blk_device(&mut self, dev: &PciDeviceInfo) {
        self.log(&alloc::format!(
            "  Initializing VirtIO-Blk at {:02x}:{:02x}.{}",
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function()
        ));
        let dma_bits = if dev.device_id.0 >= 0x1040 { 64 } else { 32 };
        register_pci_dma_width(dev, dma_bits);
        let iommu_device = crate::io::iommu::types::DeviceId::new(
            dev.segment,
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
        );
        dev.enable_bus_master();
        dev.enable_memory_space();

        if let Some(bar0) = dev.bars[0] {
            let bar0_phys = bar0.base();
            let bar0_virt =
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys)).as_u64();

            // Attempt PCI transport first
            let mut initialized_via_pci = false;
            if let Some(transport) =
                try_create_pci_transport(dev, crate::drivers::virtio::VirtioDeviceType::Block)
            {
                match unsafe {
                    crate::drivers::virtio::init_virtio_blk_with_transport(
                        alloc::boxed::Box::new(transport),
                        iommu_device,
                    )
                } {
                    Ok(()) => {
                        self.log("    VirtIO-blk PCI transport initialized");
                        initialized_via_pci = true;
                        // IoScheduler に登録
                        crate::drivers::virtio::blk_scheduler::register_virtio_blk_with_io_scheduler(0);
                        self.log("    VirtIO-blk registered with IoScheduler");
                    }
                    Err(e) => {
                        self.log(&alloc::format!(
                            "    VirtIO-blk PCI init failed: {:?}, falling back to MMIO",
                            e
                        ));
                    }
                }
            }

            if !initialized_via_pci {
                use crate::driver_registry::{driver_registry, register_driver};
                use crate::drivers::virtio::VirtioBlkDriver;
                use alloc::boxed::Box;

                let drv = Box::new(VirtioBlkDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!(
                                "    VirtIO-blk driver start failed: {:?}",
                                e
                            ));
                        } else {
                            self.log("    VirtIO-blk driver initialized via DriverRegistry");
                            // IoScheduler に登録
                            crate::drivers::virtio::blk_scheduler::register_virtio_blk_with_io_scheduler(0);
                            self.log("    VirtIO-blk registered with IoScheduler");
                        }
                    }
                    Err(e) => self.log(&alloc::format!(
                        "    VirtIO-blk driver registration failed: {:?}",
                        e
                    )),
                }
            }
        } else {
            self.log("    VirtIO-blk found but BAR0 is missing, skipping init");
        }
    }

    pub(super) fn register_and_start_virtio_net_driver(
        &mut self,
        drv: alloc::boxed::Box<crate::net::drivers::virtio_registry::VirtioNetDriver>,
    ) {
        use crate::driver_registry::{driver_registry, register_driver};

        match register_driver(drv) {
            Ok(handle) => {
                if let Err(e) = driver_registry().probe_and_start(handle) {
                    self.log(&alloc::format!(
                        "    VirtIO-net driver start failed: {:?}",
                        e
                    ));
                } else {
                    self.log("    VirtIO-net driver initialized via DriverRegistry");
                }
            }
            Err(e) => self.log(&alloc::format!(
                "    VirtIO-net driver registration failed: {:?}",
                e
            )),
        }
    }

    pub(super) fn init_virtio_net_device(&mut self, dev: &PciDeviceInfo) {
        self.log(&alloc::format!(
            "  Initializing VirtIO-Net at {:02x}:{:02x}.{}",
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function()
        ));
        let dma_bits = if dev.device_id.0 >= 0x1040 { 64 } else { 32 };
        register_pci_dma_width(dev, dma_bits);
        crate::io::log::early_print("[VIRTIO-DBG] DMA width registered\n");
        let iommu_device = crate::io::iommu::types::DeviceId::new(
            dev.segment,
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
        );
        dev.enable_bus_master();
        dev.enable_memory_space();
        crate::io::log::early_print("[VIRTIO-DBG] bus master + mem space enabled\n");

        // Try PCI transport regardless of BAR0 presence.  The transport
        // parser will examine virtio PCI capabilities and pick the correct BARs.
        let mut initialized_via_pci = false;
        crate::io::log::early_print("[VIRTIO-DBG] trying PCI transport...\n");
        if let Some(transport) =
            try_create_pci_transport(dev, crate::drivers::virtio::VirtioDeviceType::Network)
        {
            crate::io::log::early_print("[VIRTIO-DBG] PCI transport created, init device...\n");
            match crate::drivers::virtio::init_virtio_net_with_transport(
                alloc::boxed::Box::new(transport),
                iommu_device,
            ) {
                Ok(()) => {
                    crate::io::log::early_print("[VIRTIO-DBG] PCI transport init OK\n");
                    self.log("    VirtIO-net PCI transport initialized");
                    initialized_via_pci = true;
                }
                Err(e) => {
                    self.log(&alloc::format!(
                        "    VirtIO-net PCI init failed: {:?}, will try MMIO fallback",
                        e
                    ));
                }
            }
        } else {
            crate::io::log::early_print("[VIRTIO-DBG] PCI transport creation failed (None)\n");
        }

        // Determine legacy MMIO base from BAR0 if available
        let bar0_virt_opt = dev.bars[0].map(|bar0| {
            let phys = bar0.base();
            crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(phys)).as_u64()
        });

        // Register Driver via DriverRegistry
        use crate::net::drivers::virtio_registry::VirtioNetDriver;
        use alloc::boxed::Box;

        if initialized_via_pci {
            let drv = Box::new(VirtioNetDriver::new());
            self.register_and_start_virtio_net_driver(drv);
        } else if let Some(base) = bar0_virt_opt {
            let drv = Box::new(VirtioNetDriver::new_with_device(base as u64, iommu_device));
            self.register_and_start_virtio_net_driver(drv);
        } else {
            self.log(
                "    VirtIO-net found but no usable BAR0 and PCI transport failed, skipping init",
            );
        }
    }

    pub(super) fn init_virtio_console_device(&mut self, dev: &PciDeviceInfo) {
        self.log(&alloc::format!(
            "  Initializing VirtIO-Console at {:02x}:{:02x}.{}",
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function()
        ));
        let dma_bits = if dev.device_id.0 >= 0x1040 { 64 } else { 32 };
        register_pci_dma_width(dev, dma_bits);
        let iommu_device = crate::io::iommu::types::DeviceId::new(
            dev.segment,
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
        );
        dev.enable_bus_master();
        dev.enable_memory_space();

        if let Some(bar0) = dev.bars[0] {
            let bar0_phys = bar0.base();
            let bar0_virt =
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys)).as_u64();

            let mut initialized_via_pci = false;
            if let Some(transport) =
                try_create_pci_transport(dev, crate::drivers::virtio::VirtioDeviceType::Console)
            {
                match unsafe {
                    crate::drivers::virtio::init_virtio_console_with_transport(
                        alloc::boxed::Box::new(transport),
                        iommu_device,
                    )
                } {
                    Ok(()) => {
                        self.log("    VirtIO-console PCI transport initialized");
                        initialized_via_pci = true;
                    }
                    Err(e) => {
                        self.log(&alloc::format!(
                            "    VirtIO-console PCI init failed: {:?}, falling back to MMIO",
                            e
                        ));
                    }
                }
            }

            if !initialized_via_pci {
                use crate::driver_registry::{driver_registry, register_driver};
                use crate::drivers::virtio::VirtioConsoleDriver;
                use alloc::boxed::Box;

                let drv = Box::new(VirtioConsoleDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!(
                                "    VirtIO-console driver start failed: {:?}",
                                e
                            ));
                        } else {
                            self.log("    VirtIO-console driver initialized via DriverRegistry");
                        }
                    }
                    Err(e) => self.log(&alloc::format!(
                        "    VirtIO-console driver registration failed: {:?}",
                        e
                    )),
                }
            }
        } else {
            self.log("    VirtIO-console found but BAR0 is missing, skipping init");
        }
    }

    pub(super) fn init_virtio_input_device(&mut self, dev: &PciDeviceInfo) {
        self.log(&alloc::format!(
            "  Initializing VirtIO-Input at {:02x}:{:02x}.{}",
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function()
        ));
        let dma_bits: u8 = 64;
        register_pci_dma_width(dev, dma_bits);
        let iommu_device = crate::io::iommu::types::DeviceId::new(
            dev.segment,
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
        );
        dev.enable_bus_master();
        dev.enable_memory_space();

        if let Some(bar0) = dev.bars[0] {
            let bar0_phys = bar0.base();
            let bar0_virt =
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys)).as_u64();

            let mut initialized_via_pci = false;
            if let Some(transport) =
                try_create_pci_transport(dev, crate::drivers::virtio::VirtioDeviceType::Input)
            {
                match unsafe {
                    crate::drivers::virtio::init_virtio_input_with_transport(
                        alloc::boxed::Box::new(transport),
                        iommu_device,
                    )
                } {
                    Ok(()) => {
                        self.log("    VirtIO-input PCI transport initialized");
                        initialized_via_pci = true;
                    }
                    Err(e) => {
                        self.log(&alloc::format!(
                            "    VirtIO-input PCI init failed: {:?}, falling back to MMIO",
                            e
                        ));
                    }
                }
            }

            if !initialized_via_pci {
                use crate::driver_registry::{driver_registry, register_driver};
                use crate::drivers::virtio::VirtioInputDriver;
                use alloc::boxed::Box;

                let drv = Box::new(VirtioInputDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!(
                                "    VirtIO-input driver start failed: {:?}",
                                e
                            ));
                        } else {
                            self.log("    VirtIO-input driver initialized via DriverRegistry");
                        }
                    }
                    Err(e) => self.log(&alloc::format!(
                        "    VirtIO-input driver registration failed: {:?}",
                        e
                    )),
                }
            }
        } else {
            self.log("    VirtIO-input found but BAR0 is missing, skipping init");
        }
    }

    pub(super) fn init_virtio_balloon_device(&mut self, dev: &PciDeviceInfo) {
        self.log(&alloc::format!(
            "  Initializing VirtIO-Balloon at {:02x}:{:02x}.{}",
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function()
        ));
        let dma_bits = if dev.device_id.0 >= 0x1040 { 64 } else { 32 };
        register_pci_dma_width(dev, dma_bits);
        let iommu_device = crate::io::iommu::types::DeviceId::new(
            dev.segment,
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
        );
        dev.enable_bus_master();
        dev.enable_memory_space();

        if let Some(bar0) = dev.bars[0] {
            let bar0_phys = bar0.base();
            let bar0_virt =
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys)).as_u64();

            let mut initialized_via_pci = false;
            if let Some(transport) =
                try_create_pci_transport(dev, crate::drivers::virtio::VirtioDeviceType::Balloon)
            {
                match unsafe {
                    crate::drivers::virtio::init_virtio_balloon_with_transport(
                        alloc::boxed::Box::new(transport),
                        iommu_device,
                    )
                } {
                    Ok(()) => {
                        self.log("    VirtIO-balloon PCI transport initialized");
                        initialized_via_pci = true;
                    }
                    Err(e) => {
                        self.log(&alloc::format!(
                            "    VirtIO-balloon PCI init failed: {:?}, falling back to MMIO",
                            e
                        ));
                    }
                }
            }

            if !initialized_via_pci {
                use crate::driver_registry::{driver_registry, register_driver};
                use crate::drivers::virtio::VirtioBalloonDriver;
                use alloc::boxed::Box;

                let drv = Box::new(VirtioBalloonDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!(
                                "    VirtIO-balloon driver start failed: {:?}",
                                e
                            ));
                        } else {
                            self.log("    VirtIO-balloon driver initialized via DriverRegistry");
                        }
                    }
                    Err(e) => self.log(&alloc::format!(
                        "    VirtIO-balloon driver registration failed: {:?}",
                        e
                    )),
                }
            }
        } else {
            self.log("    VirtIO-balloon found but BAR0 is missing, skipping init");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_api::service::platform::{BdfAddress, ClassCode, DeviceId, VendorId};

    fn sample_pci_device() -> PciDeviceInfo {
        PciDeviceInfo {
            segment: 0,
            bdf: BdfAddress::new(0, 2, 0),
            vendor_id: VendorId(0x15B3),
            device_id: DeviceId(0x1013),
            revision_id: 0,
            class_code: ClassCode::new(0x02, 0x00, 0x00),
            header_type: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            interrupt_line: 0,
            interrupt_pin: 1,
            bars: [None; 6],
            capabilities: Vec::new(),
            msi_cap_offset: None,
            msix_cap_offset: None,
            pcie_cap_offset: None,
            iommu_domain_id: None,
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn prefers_msi_when_available() {
        let mut dev = sample_pci_device();
        dev.msi_cap_offset = Some(0x50);
        dev.msix_cap_offset = Some(0x90);

        assert_eq!(
            interrupt_capability_mode(&dev),
            InterruptCapabilityMode::Msi { offset: 0x50 }
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn detects_msix_only_devices() {
        let mut dev = sample_pci_device();
        dev.msix_cap_offset = Some(0x90);

        assert_eq!(
            interrupt_capability_mode(&dev),
            InterruptCapabilityMode::MsixOnly
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn falls_back_to_legacy_only_when_no_message_signaled_interrupts_exist() {
        let dev = sample_pci_device();

        assert_eq!(
            interrupt_capability_mode(&dev),
            InterruptCapabilityMode::LegacyOnly
        );
    }
}
