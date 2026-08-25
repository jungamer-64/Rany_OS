use super::*;
use kernel_api::service::platform::PciDeviceInfo;

mod global_init;
mod lifecycle;
mod nvme_init;
pub use self::global_init::*;

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
        let port_ids =
            crate::net::runtime::device::list_port_ids_in(crate::net::runtime::default_runtime());
        let mut rx_packets = 0u64;
        let mut tx_packets = 0u64;
        let mut tx_errors = 0u64;
        let mut rx_errors = 0u64;
        let runtime = crate::net::runtime::default_runtime();
        for port_id in &port_ids {
            if let Some(stats) = crate::net::runtime::device::port_stats_in(runtime, *port_id) {
                rx_packets = rx_packets.saturating_add(stats.rx_packets);
                tx_packets = tx_packets.saturating_add(stats.tx_packets);
                tx_errors = tx_errors.saturating_add(stats.tx_errors);
                rx_errors = rx_errors.saturating_add(stats.rx_errors);
            }
        }
        self.log(&alloc::format!(
            "  Net port runtime: stack_init={} ports={} rx={} tx={} tx_err={} rx_err={}",
            crate::net::runtime::device::is_initialized_in(runtime),
            port_ids.len(),
            rx_packets,
            tx_packets,
            tx_errors,
            rx_errors
        ));
        if let Some(cfg) = crate::net::api::config::primary_interface_config_from_runtime_in(
            crate::net::runtime::default_runtime(),
        ) {
            self.log(&alloc::format!(
                "  Net Config: IP={:?} MAC={:02x?}",
                cfg.ip,
                cfg.mac
            ));
        } else {
            self.log("  Net Config: none");
        }
        let stats = crate::net::api::config::list_interface_stats_from_runtime_in(
            crate::net::runtime::default_runtime(),
        );
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

        let catalog = crate::platform::firmware::tables().ok_or_else(|| {
            IntegrationError::AcpiError(String::from("ACPI table catalog is unavailable"))
        })?;
        let local_apics = catalog
            .firmware_cpus()
            .map_err(|error| IntegrationError::AcpiError(alloc::format!("{error:?}")))?;
        let io_apics = catalog
            .io_apics()
            .map_err(|error| IntegrationError::AcpiError(alloc::format!("{error:?}")))?;
        let pcie_ecam = catalog
            .mcfg_allocations()
            .map_err(|error| IntegrationError::AcpiError(alloc::format!("{error:?}")))?;

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
            self.interrupt_router.add_io_apic(
                apic.id,
                u64::from(apic.address),
                apic.global_interrupt_base,
            );
        }

        let overrides = catalog
            .interrupt_overrides()
            .map_err(|error| IntegrationError::AcpiError(alloc::format!("{error:?}")))?;
        for ovr in &overrides {
            if ovr.bus != 0 {
                return Err(IntegrationError::AcpiError(alloc::format!(
                    "unsupported MADT interrupt override bus {}",
                    ovr.bus
                )));
            }
            let polarity = match ovr.polarity {
                crate::drivers::acpi::InterruptPolarity::ConformsToBus
                | crate::drivers::acpi::InterruptPolarity::ActiveHigh => 0,
                crate::drivers::acpi::InterruptPolarity::ActiveLow => 1,
            };
            let trigger_mode = match ovr.trigger_mode {
                crate::drivers::acpi::InterruptTriggerMode::ConformsToBus
                | crate::drivers::acpi::InterruptTriggerMode::Edge => 0,
                crate::drivers::acpi::InterruptTriggerMode::Level => 1,
            };
            self.interrupt_router.add_override(
                ovr.source,
                ovr.global_interrupt,
                polarity,
                trigger_mode,
            );
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
        }

        self.log(&alloc::format!("  Storage controllers: {}", storage_count));
        self.log(&alloc::format!("  Network controllers: {}", network_count));

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
                                crate::cpu::CpuId::BOOTSTRAP,
                            ) {
                                Ok(allocation) => {
                                    let vector = allocation.vector();
                                    let message_address = match allocation.config.msi_address() {
                                        Ok(address) => address,
                                        Err(error) => {
                                            crate::io::interrupt_manager::free_vector(vector);
                                            self.log(&alloc::format!(
                                                "    MSI destination rejected for {}: {:?}",
                                                dev_name,
                                                error
                                            ));
                                            continue;
                                        }
                                    };
                                    if let Err(error) =
                                        crate::io::interrupt_manager::register_handler(
                                            vector,
                                            alloc::boxed::Box::new(|| {
                                                crate::interrupts::dispatch_shared_pci_handlers();
                                            }),
                                        )
                                    {
                                        crate::io::interrupt_manager::free_vector(vector);
                                        self.log(&alloc::format!(
                                            "    MSI handler registration failed for {}: {:?}",
                                            dev_name,
                                            error
                                        ));
                                        continue;
                                    }
                                    let program_result = unsafe {
                                        super::interrupt_routing::program_msi(
                                            pci_dev.bdf.bus(),
                                            pci_dev.bdf.device(),
                                            pci_dev.bdf.function(),
                                            offset,
                                            message_address,
                                            allocation.config.msi_data(),
                                        )
                                    };
                                    if let Err(error) = program_result {
                                        crate::io::interrupt_manager::unregister_handler(vector);
                                        crate::io::interrupt_manager::free_vector(vector);
                                        self.log(&alloc::format!(
                                            "    MSI programming failed for {}: {:?}",
                                            dev_name,
                                            error
                                        ));
                                        continue;
                                    }
                                    let _ = crate::platform::pci::disable_intx(pci_dev);
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

        self.start_staged_pci_drivers();

        // Initialize NVMe controllers
        self.init_nvme_devices();

        self.status = IntegrationStatus::DevicesInitialized;
        Ok(())
    }

    fn start_staged_pci_drivers(&mut self) {
        let devices = crate::platform::pci::scan_all_devices();
        let mut started = 0usize;
        for dev in devices {
            let Some(bar0) = dev.bars[0] else {
                continue;
            };
            dev.enable_bus_master();
            dev.enable_memory_space();
            let bar0_virt =
                crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0.base()))
                    .as_u64();
            let mut ctx = kernel_api::abi::driver::DriverContext::for_pci(
                bar0_virt,
                dev.interrupt_line as u32,
                dev.vendor_id.0,
                dev.device_id.0,
                ((dev.class_code.class as u32) << 16)
                    | ((dev.class_code.subclass as u32) << 8)
                    | dev.class_code.prog_if as u32,
                dev.packed_locator(),
            );
            ctx.device_address_secondary = 0;
            match crate::loader::staged_pci::try_start_for_device(&dev, ctx) {
                crate::loader::staged_pci::StagedPciBindOutcome::Started { .. } => {
                    started = started.saturating_add(1);
                    self.log(&alloc::format!(
                        "    Staged PCI driver started for {:02x}:{:02x}.{}",
                        dev.bdf.bus(),
                        dev.bdf.device(),
                        dev.bdf.function()
                    ));
                }
                crate::loader::staged_pci::StagedPciBindOutcome::AlreadyBound => {}
                crate::loader::staged_pci::StagedPciBindOutcome::Failed(reason) => {
                    self.log(&alloc::format!("    {}", reason));
                }
                crate::loader::staged_pci::StagedPciBindOutcome::NoMatch => {}
            }
        }
        self.log(&alloc::format!("  Staged PCI driver starts: {}", started));
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
