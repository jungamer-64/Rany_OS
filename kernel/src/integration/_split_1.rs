use super::*;


mod _split_1;
pub use self::_split_1::*;
mod _split_2;
pub use self::_split_2::*;
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

        // Diagnostic: print Net Bridge and Network configuration/stats
        let bridge_stats = crate::net::get_bridge_stats();
        self.log(&alloc::format!("  Net Bridge stats: init={} rx={} tx={}", bridge_stats.initialized, bridge_stats.rx_packets, bridge_stats.tx_packets));
        if let Some(cfg) = crate::net::get_real_config() {
            self.log(&alloc::format!("  Net Config: IP={:?} MAC={:02x?}", cfg.ip, cfg.mac));
        } else {
            self.log("  Net Config: none");
        }
        if let Some(stats) = crate::net::get_network_stats() {
            self.log(&alloc::format!("  Net Stack stats: rx={} tx={} rx_bytes={} tx_bytes={}", stats.rx_packets, stats.tx_packets, stats.rx_bytes, stats.tx_bytes));
        } else {
            self.log("  Net Stack stats: none");
        }

        Ok(())
    }

    /// Phase 1: ACPI integration
    pub(super) fn integrate_acpi(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 1: ACPI integration");

        // Get ACPI information
        let local_apics = crate::io::acpi::local_apics();
        let io_apics = crate::io::acpi::io_apics();
        let pcie_ecam = crate::io::acpi::pcie_ecam_regions();

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
        let overrides = crate::io::acpi::interrupt_overrides();
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
        crate::io::pci::init();

        // Get all PCI devices
        let mut devices = crate::io::pci::scan_all_devices();
        self.log(&alloc::format!("  Found {} PCI device(s)", devices.len()));

        #[cfg(not(test))]
        {
            crate::io::iommu::pci::setup_iommu_for_all_pci_devices(&mut devices);
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
        let pci_devices = crate::io::pci::scan_all_devices();
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
                    if let Some(vector) = crate::io::pci::allocate_vector(pci_dev.bdf) {
                        self.interrupt_router.add_msi_route(*dev_id, vector);
                        self.log(&alloc::format!(
                            "    Device {} -> vector {}",
                            dev_name,
                            vector
                        ));
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
        let virtio_devices = crate::io::pci::find_virtio_devices();
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

    pub(super) fn init_virtio_blk_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys))
                    .as_u64();

            // Attempt PCI transport first
            let mut initialized_via_pci = false;
            if let Some(transport) = try_create_pci_transport(
                dev,
                crate::io::virtio::VirtioDeviceType::Block,
            ) {
                match unsafe {
                    crate::io::virtio::init_virtio_blk_with_transport(
                        alloc::boxed::Box::new(transport),
                        Some(iommu_device),
                    )
                } {
                    Ok(()) => {
                        self.log("    VirtIO-blk PCI transport initialized");
                        initialized_via_pci = true;
                        // IoScheduler に登録
                        crate::io::virtio::blk_scheduler::register_virtio_blk_with_io_scheduler(0);
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
                use alloc::boxed::Box;
                use crate::driver_registry::{register_driver, driver_registry};
                use crate::io::virtio::VirtioBlkDriver;

                let drv = Box::new(VirtioBlkDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!("    VirtIO-blk driver start failed: {:?}", e));
                        } else {
                            self.log("    VirtIO-blk driver initialized via DriverRegistry");
                            // IoScheduler に登録
                            crate::io::virtio::blk_scheduler::register_virtio_blk_with_io_scheduler(0);
                            self.log("    VirtIO-blk registered with IoScheduler");
                        }
                    }
                    Err(e) => self.log(&alloc::format!("    VirtIO-blk driver registration failed: {:?}", e)),
                }
            }
        } else {
            self.log("    VirtIO-blk found but BAR0 is missing, skipping init");
        }
    }

    pub(super) fn register_and_start_virtio_net_driver(&mut self, drv: alloc::boxed::Box<crate::net::driver::VirtioNetDriver>) {
        use crate::driver_registry::{register_driver, driver_registry};
        match register_driver(drv) {
            Ok(handle) => {
                if let Err(e) = driver_registry().probe_and_start(handle) {
                    self.log(&alloc::format!("    VirtIO-net driver start failed: {:?}", e));
                } else {
                    self.log("    VirtIO-net driver initialized via DriverRegistry");
                }
            }
            Err(e) => self.log(&alloc::format!("    VirtIO-net driver registration failed: {:?}", e)),
        }
    }

    pub(super) fn init_virtio_net_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
        self.log(&alloc::format!(
            "  Initializing VirtIO-Net at {:02x}:{:02x}.{}",
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
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys))
                    .as_u64();

            // Attempt PCI transport first
            let mut initialized_via_pci = false;
            if let Some(transport) = try_create_pci_transport(
                dev,
                crate::io::virtio::VirtioDeviceType::Network,
            ) {
                match crate::io::virtio::init_virtio_net_with_transport(
                    alloc::boxed::Box::new(transport),
                ) {
                    Ok(()) => {
                        self.log("    VirtIO-net PCI transport initialized");
                        initialized_via_pci = true;

                        // Ensure Net Bridge is initialized (idempotent)
                        if !crate::net::driver_bridge::is_initialized() {
                            match crate::net::init_driver_bridge() {
                                Ok(()) => self.log("    Net Bridge initialized by integration"),
                                Err(_) => self.log("    Net Bridge init failed"),
                            }
                        } else {
                            self.log("    Net Bridge already initialized");
                        }
                    }
                    Err(e) => {
                        self.log(&alloc::format!(
                            "    VirtIO-net PCI init failed: {:?}, falling back to MMIO",
                            e
                        ));
                    }
                }
            }

            // Register Driver via DriverRegistry
            use alloc::boxed::Box;
            use crate::net::driver::VirtioNetDriver;

            if initialized_via_pci {
                let drv = Box::new(VirtioNetDriver::new());
                self.register_and_start_virtio_net_driver(drv);
            } else {
                let drv = Box::new(VirtioNetDriver::new_with_device(bar0_virt as u64, iommu_device));
                self.register_and_start_virtio_net_driver(drv);
            }
        } else {
            self.log("    VirtIO-net found but BAR0 is missing, skipping init");
        }
    }

    pub(super) fn init_virtio_console_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys))
                    .as_u64();

            let mut initialized_via_pci = false;
            if let Some(transport) = try_create_pci_transport(
                dev,
                crate::io::virtio::VirtioDeviceType::Console,
            ) {
                match unsafe {
                    crate::io::virtio::init_virtio_console_with_transport(
                        alloc::boxed::Box::new(transport),
                        Some(iommu_device),
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
                use alloc::boxed::Box;
                use crate::driver_registry::{register_driver, driver_registry};
                use crate::io::virtio::VirtioConsoleDriver;

                let drv = Box::new(VirtioConsoleDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!("    VirtIO-console driver start failed: {:?}", e));
                        } else {
                            self.log("    VirtIO-console driver initialized via DriverRegistry");
                        }
                    }
                    Err(e) => self.log(&alloc::format!("    VirtIO-console driver registration failed: {:?}", e)),
                }
            }
        } else {
            self.log("    VirtIO-console found but BAR0 is missing, skipping init");
        }
    }

    pub(super) fn init_virtio_input_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys))
                    .as_u64();

            let mut initialized_via_pci = false;
            if let Some(transport) = try_create_pci_transport(
                dev,
                crate::io::virtio::VirtioDeviceType::Input,
            ) {
                match unsafe {
                    crate::io::virtio::init_virtio_input_with_transport(
                        alloc::boxed::Box::new(transport),
                        Some(iommu_device),
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
                use alloc::boxed::Box;
                use crate::driver_registry::{register_driver, driver_registry};
                use crate::io::virtio::VirtioInputDriver;

                let drv = Box::new(VirtioInputDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!("    VirtIO-input driver start failed: {:?}", e));
                        } else {
                            self.log("    VirtIO-input driver initialized via DriverRegistry");
                        }
                    }
                    Err(e) => self.log(&alloc::format!("    VirtIO-input driver registration failed: {:?}", e)),
                }
            }
        } else {
            self.log("    VirtIO-input found but BAR0 is missing, skipping init");
        }
    }

    pub(super) fn init_virtio_balloon_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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
                crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys))
                    .as_u64();

            let mut initialized_via_pci = false;
            if let Some(transport) = try_create_pci_transport(
                dev,
                crate::io::virtio::VirtioDeviceType::Balloon,
            ) {
                match unsafe {
                    crate::io::virtio::init_virtio_balloon_with_transport(
                        alloc::boxed::Box::new(transport),
                        Some(iommu_device),
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
                use alloc::boxed::Box;
                use crate::driver_registry::{register_driver, driver_registry};
                use crate::io::virtio::VirtioBalloonDriver;

                let drv = Box::new(VirtioBalloonDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!("    VirtIO-balloon driver start failed: {:?}", e));
                        } else {
                            self.log("    VirtIO-balloon driver initialized via DriverRegistry");
                        }
                    }
                    Err(e) => self.log(&alloc::format!("    VirtIO-balloon driver registration failed: {:?}", e)),
                }
            }
        } else {
            self.log("    VirtIO-balloon found but BAR0 is missing, skipping init");
        }
    }
}
