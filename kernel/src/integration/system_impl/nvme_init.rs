use super::*;

impl SystemIntegration {
    pub(super) fn init_nvme_devices(&mut self) {
        let mut nvme_controller_id: u8 = 0;
        let nvme_devices = crate::platform::pci::find_by_class(0x01, 0x08);
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
            crate::drivers::nvme::set_iommu_device(iommu_device);

            if crate::drivers::nvme::with_driver(|_| ()).is_some() {
                self.log("    NVMe driver already initialized, skipping");
                continue;
            }

            if let Some(bar0) = dev.bars[0] {
                let bar0_phys = bar0.base();
                let bar0_virt = crate::mm::virt::mapping::phys_to_virt(
                    x86_64::PhysAddr::new_truncate(bar0_phys),
                )
                .as_u64();
                let num_cores = crate::cpu::count() as u32;
                let packed_device_id = dev.packed_locator();

                let mut standalone_ctx = kernel_api::abi::driver::DriverContext::for_pci(
                    bar0_virt,
                    dev.interrupt_line as u32,
                    dev.vendor_id.0,
                    dev.device_id.0,
                    ((dev.class_code.class as u32) << 16)
                        | ((dev.class_code.subclass as u32) << 8)
                        | dev.class_code.prog_if as u32,
                    packed_device_id,
                );
                standalone_ctx.device_address_secondary = 0;
                match crate::loader::staged_pci::try_start_for_device(&dev, standalone_ctx) {
                    crate::loader::staged_pci::StagedPciBindOutcome::Started { .. }
                    | crate::loader::staged_pci::StagedPciBindOutcome::AlreadyBound => {
                        self.log("    NVMe controller initialized via staged standalone driver");
                        nvme_controller_id = nvme_controller_id.wrapping_add(1);
                        continue;
                    }
                    crate::loader::staged_pci::StagedPciBindOutcome::Failed(reason) => {
                        self.log(&alloc::format!(
                            "    {} ; falling back to built-in NVMe path",
                            reason
                        ));
                    }
                    crate::loader::staged_pci::StagedPciBindOutcome::NoMatch => {}
                }

                match crate::drivers::nvme::init_nvme_polling(
                    bar0_virt,
                    num_cores,
                    packed_device_id,
                ) {
                    Ok(()) => {
                        self.log("    NVMe driver initialized (polling)");
                        if let Err(e) = crate::drivers::nvme::register_with_io_scheduler(
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
                        self.log(&alloc::format!("    NVMe driver init failed: {}", e));
                    }
                }
            } else {
                self.log("    NVMe controller found but BAR0 is missing");
            }

            nvme_controller_id = nvme_controller_id.wrapping_add(1);
        }
    }
}
