use super::*;

impl SystemIntegration {

    pub(super) fn init_virtio_gpu_device(&mut self, dev: &crate::io::pci::PciDeviceInfo) {
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

    pub(super) fn init_nvme_devices(&mut self) {
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

    pub(super) fn init_hda_devices(&mut self) {
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
    pub(super) fn integrate_security(&mut self) -> Result<(), IntegrationError> {
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
    pub(super) fn log(&mut self, msg: &str) {
        crate::io::log::early_print("[INTEGRATION] ");
        crate::io::log::early_print(msg);
        crate::io::log::early_print("\n");
        // log::info!("[INTEGRATION] {}\n", msg);
        self.boot_log.push(String::from(msg));
    }
}
