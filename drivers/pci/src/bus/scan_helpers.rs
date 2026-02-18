use super::*;


// ============================================================================
// Convenience Functions
// ============================================================================

use crate::legacy::get_legacy_accessor;

/// Scan all PCI devices using legacy I/O port access
pub fn scan_all_devices() -> Vec<PciDeviceInfo> {
    let accessor = get_legacy_accessor();
    let scanner = PciBusScanner::new(&accessor);
    scanner.scan_all()
}

/// Find devices by class and subclass using legacy I/O port access
pub fn find_by_class(class: u8, subclass: u8) -> Vec<PciDeviceInfo> {
    let accessor = get_legacy_accessor();
    let scanner = PciBusScanner::new(&accessor);
    scanner.find_by_class(class, subclass)
}

/// Find devices by vendor and device ID using legacy I/O port access
pub fn find_by_id(vendor_id: u16, device_id: u16) -> Vec<PciDeviceInfo> {
    let accessor = get_legacy_accessor();
    let scanner = PciBusScanner::new(&accessor);
    scanner.find_by_id(vendor_id, device_id)
}

/// Find all VirtIO devices (vendor 0x1AF4)
pub fn find_virtio_devices() -> Vec<PciDeviceInfo> {
    scan_all_devices()
        .into_iter()
        .filter(PciDeviceInfo::is_virtio)
        .collect()
}

/// Initialize PCI subsystem (scan and log devices)
pub fn init() {
    log::info!("[PCI] Initializing PCI bus...");
    let devices = scan_all_devices();
    log::info!("[PCI] Found {} device(s)", devices.len());

    for dev in &devices {
        log::info!(
            "[PCI] {:02x}:{:02x}.{} - {:04x}:{:04x} class {:02x}.{:02x}",
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
            dev.vendor_id.0,
            dev.device_id.0,
            dev.class_code.class,
            dev.class_code.subclass
        );
        for (i, bar) in dev.bars.iter().enumerate() {
            if let Some(bar) = bar {
                log::info!("[PCI]   BAR{i}: {bar:?}");
            }
        }
    }
}
