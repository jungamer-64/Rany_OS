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
use kernel_api::service::platform::PciDeviceInfo;

pub mod device_manager;
pub mod interrupt_routing;
pub mod security_integration;
// Re-exports
mod system_impl;
#[allow(dead_code)]
pub use device_manager::{DeviceInfo, DeviceManager};
pub use interrupt_routing::InterruptRouter;
pub use security_integration::SecurityIntegration;
pub use system_impl::*;

fn register_pci_dma_width(dev: &PciDeviceInfo, bits: u8) {
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
fn parse_virtio_capabilities(dev: &PciDeviceInfo) -> VirtioCapabilities {
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
        let cap_id_raw = crate::io::pci::legacy::pci_read8(bus, device, function, *cap_ptr);
        if cap_id_raw != 0x09 {
            continue;
        }
        let ptr = *cap_ptr;
        let cfg_type = crate::io::pci::legacy::pci_read8(bus, device, function, ptr + 3);
        let bar = crate::io::pci::legacy::pci_read8(bus, device, function, ptr + 4);
        let offset = crate::io::pci::legacy::pci_read(bus, device, function, (ptr + 8) as u8);
        let length = crate::io::pci::legacy::pci_read(bus, device, function, (ptr + 12) as u8);

        match cfg_type {
            1 => caps.common_cfg = Some((bar, offset, length)),
            2 => {
                caps.notify_cfg = Some((bar, offset, length));
                caps.notify_multiplier =
                    crate::io::pci::legacy::pci_read(bus, device, function, (ptr + 16) as u8)
                        as u32;
            }
            3 => caps.isr_cfg = Some((bar, offset, length)),
            4 => caps.device_cfg = Some((bar, offset, length)),
            _ => {}
        }
    }

    caps
}

/// BAR 情報からオプショナルな仮想アドレスを解決
fn resolve_bar_virt_addr(dev: &PciDeviceInfo, cfg: Option<(u8, u32, u32)>) -> usize {
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
    dev: &PciDeviceInfo,
    device_type: crate::drivers::virtio::VirtioDeviceType,
) -> Option<crate::drivers::virtio::VirtioPciTransport> {
    let caps = parse_virtio_capabilities(dev);

    let (cbar, coff, _) = caps.common_cfg?;
    let (dbar, doff, _) = caps.device_cfg?;

    if (cbar as usize) >= dev.bars.len() || (dbar as usize) >= dev.bars.len() {
        return None;
    }

    let cbar_info = dev.bars[cbar as usize]?;
    let dbar_info = dev.bars[dbar as usize]?;

    // ensure the whole BARs are mapped so accesses to capability offsets work
    // map the BAR regions into the kernel page tables
    let _ = crate::ensure_phys_bar_mapped(cbar_info.base(), cbar_info.size());
    let _ = crate::ensure_phys_bar_mapped(dbar_info.base(), dbar_info.size());
    if let Some((nbar, _, _)) = caps.notify_cfg {
        if let Some(info) = dev.bars[nbar as usize] {
            let _ = crate::ensure_phys_bar_mapped(info.base(), info.size());
        }
    }
    if let Some((ibar, _, _)) = caps.isr_cfg {
        if let Some(info) = dev.bars[ibar as usize] {
            let _ = crate::ensure_phys_bar_mapped(info.base(), info.size());
        }
    }

    let common_phys = cbar_info.base() + (coff as u64);
    let device_phys = dbar_info.base() + (doff as u64);

    let common_virt =
        crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(common_phys)).as_u64() as usize;
    let device_virt =
        crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(device_phys)).as_u64() as usize;

    let notify_virt = resolve_bar_virt_addr(dev, caps.notify_cfg);
    let isr_virt = resolve_bar_virt_addr(dev, caps.isr_cfg);

    unsafe {
        crate::drivers::virtio::VirtioPciTransport::new(
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
