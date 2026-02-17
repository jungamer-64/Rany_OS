//! System Integration Module for ExoRust Kernel
//!
//! This module integrates all kernel subsystems during boot:
//! - ACPI-based hardware discovery
//! - PCI/PCIe device initialization
//! - APIC/IOAPIC interrupt routing setup
//! - VirtIO device detection and MSI/MSI-X configuration
//! - Security context binding to domains

#![allow(dead_code)]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub mod device_manager;
pub mod interrupt_routing;
pub mod security_integration;
// Re-exports
#[allow(dead_code)]
pub use device_manager::{DeviceInfo, DeviceManager};
pub use interrupt_routing::InterruptRouter;
pub use security_integration::SecurityIntegration;

fn register_pci_dma_width(dev: &crate::io::pci::PciDeviceInfo, bits: u8) {
    let device = crate::io::iommu::types::DeviceId::new(
        dev.segment,
        dev.bdf.bus(),
        dev.bdf.device(),
        dev.bdf.function(),
    );
    if let Err(err) = crate::io::iommu::api::register_device_dma_width(device, bits) {
        log::warn!(
            "[INTEGRATION] Failed to register DMA width for {}: {:?}",
            dev.bdf,
            err
        );
    }
}

/// VirtIO PCI capabilities の解析結果
struct VirtioCapabilities {
    common_cfg: Option<(u8, u32, u32)>,
    notify_cfg: Option<(u8, u32, u32)>,
    isr_cfg: Option<(u8, u32, u32)>,
    device_cfg: Option<(u8, u32, u32)>,
    notify_multiplier: u32,
}

/// PCI vendor-specific ケーパビリティから VirtIO 構成を解析
fn parse_virtio_capabilities(dev: &crate::io::pci::PciDeviceInfo) -> VirtioCapabilities {
    let bus = dev.bdf.bus();
    let device = dev.bdf.device();
    let function = dev.bdf.function();

    let mut caps = VirtioCapabilities {
        common_cfg: None,
        notify_cfg: None,
        isr_cfg: None,
        device_cfg: None,
        notify_multiplier: 1,
    };

    for (_cap_id, cap_ptr) in &dev.capabilities {
        let cap_id_raw = crate::io::pci::pci_read8(bus, device, function, *cap_ptr);
        if cap_id_raw != 0x09 {
            continue;
        }
        let ptr = *cap_ptr;
        let cfg_type = crate::io::pci::pci_read8(bus, device, function, ptr + 3);
        let bar = crate::io::pci::pci_read8(bus, device, function, ptr + 4);
        let offset = crate::io::pci::pci_read(bus, device, function, (ptr + 8) as u8);
        let length = crate::io::pci::pci_read(bus, device, function, (ptr + 12) as u8);

        match cfg_type {
            1 => caps.common_cfg = Some((bar, offset, length)),
            2 => {
                caps.notify_cfg = Some((bar, offset, length));
                caps.notify_multiplier =
                    crate::io::pci::pci_read(bus, device, function, (ptr + 16) as u8) as u32;
            }
            3 => caps.isr_cfg = Some((bar, offset, length)),
            4 => caps.device_cfg = Some((bar, offset, length)),
            _ => {}
        }
    }

    caps
}

/// BAR 情報からオプショナルな仮想アドレスを解決
fn resolve_bar_virt_addr(
    dev: &crate::io::pci::PciDeviceInfo,
    cfg: Option<(u8, u32, u32)>,
) -> usize {
    let (bar, offset, _) = match cfg {
        Some(c) => c,
        None => return 0,
    };
    if (bar as usize) >= dev.bars.len() {
        return 0;
    }
    match dev.bars[bar as usize] {
        Some(bar_info) => {
            let phys = bar_info.base() + (offset as u64);
            crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(phys)).as_u64() as usize
        }
        None => 0,
    }
}

/// Attempt to create a VirtioPciTransport by parsing PCI vendor-specific capabilities.
///
/// Parses cfg_type 1 (common_cfg), 2 (notify_cfg), 3 (isr_cfg), 4 (device_cfg)
/// from VirtIO PCI capability structures. Returns `None` if the required capabilities
/// are not present or if BAR resolution fails.
fn try_create_pci_transport(
    dev: &crate::io::pci::PciDeviceInfo,
    device_type: crate::io::virtio::VirtioDeviceType,
) -> Option<crate::io::virtio::VirtioPciTransport> {
    let caps = parse_virtio_capabilities(dev);

    let (cbar, coff, _) = caps.common_cfg?;
    let (dbar, doff, _) = caps.device_cfg?;

    if (cbar as usize) >= dev.bars.len() || (dbar as usize) >= dev.bars.len() {
        return None;
    }

    let cbar_info = dev.bars[cbar as usize]?;
    let dbar_info = dev.bars[dbar as usize]?;

    let common_phys = cbar_info.base() + (coff as u64);
    let device_phys = dbar_info.base() + (doff as u64);

    let common_virt =
        crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(common_phys)).as_u64() as usize;
    let device_virt =
        crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(device_phys)).as_u64() as usize;

    let notify_virt = resolve_bar_virt_addr(dev, caps.notify_cfg);
    let isr_virt = resolve_bar_virt_addr(dev, caps.isr_cfg);

    unsafe {
        crate::io::virtio::VirtioPciTransport::new(
            dev.bdf.to_u16() as u32,
            common_virt,
            notify_virt,
            caps.notify_multiplier,
            isr_virt,
            device_virt,
            device_type,
        )
        .ok()
    }
}

/// Integration status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum IntegrationStatus {
    /// Not initialized
    Uninitialized,
    /// ACPI tables parsed
    AcpiParsed,
    /// PCI bus scanned
    PciScanned,
    /// Interrupts configured
    InterruptsConfigured,
    /// Devices initialized
    DevicesInitialized,
    /// Security bound
    SecurityBound,
    /// Fully integrated
    Complete,
    /// Failed
    Failed,
}

/// Integration error
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum IntegrationError {
    /// ACPI initialization failed
    AcpiError(String),
    /// PCI initialization failed
    PciError(String),
    /// Interrupt configuration failed
    InterruptError(String),
    /// Device initialization failed
    DeviceError(String),
    /// Security binding failed
    SecurityError(String),
}

/// System integration controller
pub struct SystemIntegration {
    /// Current status
    status: IntegrationStatus,
    /// Device manager
    device_manager: DeviceManager,
    /// Interrupt router
    interrupt_router: InterruptRouter,
    /// Security integration
    security: SecurityIntegration,
    /// Boot log
    boot_log: Vec<String>,
}

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
    fn integrate_acpi(&mut self) -> Result<(), IntegrationError> {
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
    fn integrate_pci(&mut self) -> Result<(), IntegrationError> {
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
    fn integrate_interrupts(&mut self) -> Result<(), IntegrationError> {
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
    fn integrate_devices(&mut self) -> Result<(), IntegrationError> {
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

    fn init_virtio_blk_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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

    fn register_and_start_virtio_net_driver(&mut self, drv: Box<VirtioNetDriver>) {
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

    fn init_virtio_net_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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

    fn init_virtio_console_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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

    fn init_virtio_input_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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

    fn init_virtio_balloon_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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

    fn init_virtio_gpu_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
        self.log(&alloc::format!(
            "  Initializing VirtIO-GPU at {:02x}:{:02x}.{}",
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
                crate::io::virtio::VirtioDeviceType::Gpu,
            ) {
                match unsafe {
                    crate::gpu::init_virtio_gpu_for_device(
                        alloc::boxed::Box::new(transport),
                        iommu_device,
                    )
                } {
                    Ok(()) => {
                        self.log("    VirtIO-gpu PCI transport initialized");
                        initialized_via_pci = true;
                    }
                    Err(e) => {
                        self.log(&alloc::format!(
                            "    VirtIO-gpu PCI init failed: {:?}, falling back to MMIO",
                            e
                        ));
                    }
                }
            }

            if !initialized_via_pci {
                use alloc::boxed::Box;
                use crate::driver_registry::{register_driver, driver_registry};
                use crate::gpu::gpu_driver::VirtioGpuDriver;

                let drv = Box::new(VirtioGpuDriver::new(bar0_virt, iommu_device));
                match register_driver(drv) {
                    Ok(handle) => {
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            self.log(&alloc::format!("    VirtIO-gpu driver start failed: {:?}", e));
                        } else {
                            self.log("    VirtIO-gpu driver initialized via DriverRegistry");
                        }
                    }
                    Err(e) => self.log(&alloc::format!("    VirtIO-gpu driver registration failed: {:?}", e)),
                }
            }
        } else {
            self.log("    VirtIO-gpu found but BAR0 is missing, skipping init");
        }
    }

    fn init_nvme_devices(&mut self) {
        let mut nvme_controller_id: u8 = 0;
        let nvme_devices = crate::io::pci::find_by_class(0x01, 0x08);
        for dev in nvme_devices {
            self.log(&alloc::format!(
                "  Initializing NVMe controller at {:02x}:{:02x}.{}",
                dev.bdf.bus(),
                dev.bdf.device(),
                dev.bdf.function()
            ));
            register_pci_dma_width(&dev, 64);
            dev.enable_bus_master();
            dev.enable_memory_space();

            let iommu_device = crate::io::iommu::types::DeviceId::new(
                dev.segment,
                dev.bdf.bus(),
                dev.bdf.device(),
                dev.bdf.function(),
            );
            crate::io::nvme::set_iommu_device(iommu_device);

            if crate::io::nvme::with_driver(|_| ()).is_some() {
                self.log("    NVMe driver already initialized, skipping");
                continue;
            }

            if let Some(bar0) = dev.bars[0] {
                let bar0_phys = bar0.base();
                let bar0_virt =
                    crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys))
                        .as_u64();
                let num_cores = crate::smp::cpu_count();

                match crate::io::nvme::init_nvme_polling(bar0_virt, num_cores) {
                    Ok(()) => {
                        self.log("    NVMe driver initialized (polling)");
                        let apic_id = crate::io::apic::local_apic().id() as u32;
                        let core_id = crate::smp::current_cpu();
                        crate::io::nvme::per_core::register_apic_mapping(apic_id, core_id);
                        if let Err(e) = crate::io::nvme::register_with_io_scheduler(
                            nvme_controller_id,
                            1,
                            num_cores,
                        ) {
                            self.log(&alloc::format!(
                                "    NVMe IoScheduler registration failed: {}",
                                e
                            ));
                        }
                    }
                    Err(e) => {
                        self.log(&alloc::format!(
                            "    NVMe driver init failed: {}",
                            e
                        ));
                    }
                }
            } else {
                self.log("    NVMe controller found but BAR0 is missing");
            }

            nvme_controller_id = nvme_controller_id.wrapping_add(1);
        }
    }

    fn init_hda_devices(&mut self) {
        let hda_devices = crate::io::pci::find_by_class(0x04, 0x03);
        for dev in hda_devices {
             self.log(&alloc::format!(
                "  Initializing HDA Audio at {:02x}:{:02x}.{}",
                dev.bdf.bus(),
                dev.bdf.device(),
                dev.bdf.function()
            ));

            dev.enable_bus_master();
            dev.enable_memory_space();

            if let Some(bar0) = dev.bars[0] {
                 let bar0_phys = bar0.base();
                 let bar0_virt = crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys)).as_u64();
                 
                 use crate::io::audio::hda::HdaDriver;
                 use crate::driver_registry::{register_driver, driver_registry};
                 use alloc::boxed::Box;

                 let drv = Box::new(HdaDriver::new(dev, bar0_virt));
                 match register_driver(drv) {
                     Ok(handle) => {
                         if let Err(e) = driver_registry().probe_and_start(handle) {
                             self.log(&alloc::format!("    HDA driver start failed: {:?}", e));
                         } else {
                             self.log("    HDA driver initialized via DriverRegistry");
                         }
                     }
                     Err(e) => self.log(&alloc::format!("    HDA driver registration failed: {:?}", e)),
                 }
            } else {
                self.log("    HDA device found but BAR0 is missing");
            }
        }
    }

    /// Phase 5: Security integration
    fn integrate_security(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 5: Security context binding");

        // Bind devices to security contexts
        self.security.bind_all_devices(&self.device_manager);

        // Create device-specific capability sets
        let device_count = self.device_manager.device_count();
        self.log(&alloc::format!(
            "  Bound {} device(s) to security contexts",
            device_count
        ));

        self.status = IntegrationStatus::SecurityBound;
        Ok(())
    }

    /// Get integration status
    pub fn status(&self) -> IntegrationStatus {
        self.status
    }

    /// Get boot log
    pub fn boot_log(&self) -> &[String] {
        &self.boot_log
    }

    /// Get device manager
    pub fn device_manager(&self) -> &DeviceManager {
        &self.device_manager
    }

    /// Get interrupt router
    pub fn interrupt_router(&self) -> &InterruptRouter {
        &self.interrupt_router
    }

    /// Add log entry
    fn log(&mut self, msg: &str) {
        crate::io::log::early_print("[INTEGRATION] ");
        crate::io::log::early_print(msg);
        crate::io::log::early_print("\n");
        // log::info!("[INTEGRATION] {}\n", msg);
        self.boot_log.push(String::from(msg));
    }
}

impl Default for SystemIntegration {
    fn default() -> Self {
        Self::new()
    }
}

// Global integration instance
static SYSTEM_INTEGRATION: Mutex<Option<SystemIntegration>> = Mutex::new(None);

/// Initialize system integration
pub fn init() -> Result<(), IntegrationError> {
    let mut integration = SystemIntegration::new();
    let result = integration.integrate();

    *SYSTEM_INTEGRATION.lock() = Some(integration);

    result
}

/// Get integration status
pub fn status() -> IntegrationStatus {
    SYSTEM_INTEGRATION
        .lock()
        .as_ref()
        .map(|i| i.status())
        .unwrap_or(IntegrationStatus::Uninitialized)
}

/// Get boot log
pub fn boot_log() -> Vec<String> {
    SYSTEM_INTEGRATION
        .lock()
        .as_ref()
        .map(|i| i.boot_log().to_vec())
        .unwrap_or_default()
}
