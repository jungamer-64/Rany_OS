// ============================================================================
// kernel/src/net/drivers/mod.rs - ドライバ登録
// ============================================================================
//! # ドライバ登録
//!
//! ネットワークデバイスの検出・登録。

extern crate alloc;

use alloc::boxed::Box;
use kernel_api::abi::driver::DriverContext;
use kernel_api::service::platform::PciDeviceInfo;

pub mod virtio_runtime;

const PCI_CLASS_NETWORK: u8 = 0x02;

pub fn start_network_driver_class() {
    start_virtio_net_driver();
    start_staged_pci_network_drivers();
}

fn start_virtio_net_driver() {
    let adapter_info = virtio_driver::net::virtio_net_driver_adapter(0).info();
    if adapter_info.flags == 0 {
        log::info!(
            target: "net_boot",
            "No built-in VirtIO-Net device reported by transport discovery"
        );
        return;
    }

    let already_registered = crate::net::runtime::device::list_port_infos()
        .into_iter()
        .any(|info| info.port_id == adapter_info.port_id);
    if already_registered {
        log::info!(
            target: "net_boot",
            "Network port {} already registered; skipping built-in VirtIO-Net startup",
            adapter_info.port_id.as_u64()
        );
        return;
    }

    let hooks = virtio_runtime::kernel_virtio_net_driver_hooks();
    let handle = crate::driver_registry::register_driver(Box::new(
        virtio_driver::net::driver::VirtioNetDriver::new(0, hooks),
    ));
    match handle {
        Ok(handle) => {
            if let Err(err) = crate::driver_registry::driver_registry().probe_and_start(handle) {
                log::warn!(
                    target: "net_boot",
                    "Built-in network driver startup failed for port {}: {:?}",
                    adapter_info.port_id.as_u64(),
                    err
                );
            } else {
                log::info!(
                    target: "net_boot",
                    "Built-in network driver initialized for port {}",
                    adapter_info.port_id.as_u64()
                );
            }
        }
        Err(err) => {
            log::warn!(
                target: "net_boot",
                "Failed to register built-in network driver for port {}: {:?}",
                adapter_info.port_id.as_u64(),
                err
            );
        }
    }
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn start_staged_pci_network_drivers() {
    let mut started = 0usize;
    for dev in crate::platform::pci::scan_all_devices()
        .into_iter()
        .filter(is_network_pci_device)
    {
        let Some(bar0) = dev.bars[0] else {
            continue;
        };
        let ctx = DriverContext::for_pci(
            bar0.base(),
            dev.interrupt_line as u32,
            dev.vendor_id.0,
            dev.device_id.0,
            class_code_u32(&dev),
            dev.packed_locator(),
        );

        match crate::loader::staged_pci::try_start_for_device(&dev, ctx) {
            crate::loader::staged_pci::StagedPciBindOutcome::Started { .. } => {
                started = started.saturating_add(1);
            }
            crate::loader::staged_pci::StagedPciBindOutcome::AlreadyBound => {}
            crate::loader::staged_pci::StagedPciBindOutcome::Failed(reason) => {
                log::warn!(target: "net_boot", "{}", reason);
            }
            crate::loader::staged_pci::StagedPciBindOutcome::NoMatch => {}
        }
    }

    if started > 0 {
        log::info!(
            target: "net_boot",
            "Started {} staged PCI network driver(s)",
            started
        );
    }
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
fn start_staged_pci_network_drivers() {}

fn is_network_pci_device(dev: &PciDeviceInfo) -> bool {
    dev.class_code.class == PCI_CLASS_NETWORK
}

fn class_code_u32(dev: &PciDeviceInfo) -> u32 {
    ((dev.class_code.class as u32) << 16)
        | ((dev.class_code.subclass as u32) << 8)
        | dev.class_code.prog_if as u32
}
