// ============================================================================
// I/O Subsystem Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================

// ============================================================================
// Submodules
// ============================================================================

pub mod acpi;
pub mod ahci;
pub mod apic;
pub mod audio;
pub mod dma;
pub mod hid;
pub mod ide;
pub mod interrupt_manager;
pub mod io_scheduler;
pub mod iommu;
pub mod log;
pub mod nvme;
pub mod pci;
pub mod rtc;
pub mod serial;
pub mod usb;
pub mod virtio;

// ============================================================================
// HAL Re-exports (convenience)
// ============================================================================

pub use hal::mmio;
pub use hal::port_io;

// Commonly used MMIO functions
pub use mmio::{
    mmio_read_u8, mmio_read_u16, mmio_read_u32, mmio_read_u64, mmio_write_u8, mmio_write_u16,
    mmio_write_u32, mmio_write_u64, volatile_read, volatile_write,
};

// Commonly used port I/O functions
pub use port_io::{inb, inl, inw, outb, outl, outw};

// ============================================================================
// Module Aliases (for compatibility)
// ============================================================================

// `io::keyboard` alias removed. Use `io::hid::keyboard`.

// ============================================================================
// Commonly Used DMA Types
// ============================================================================

pub use dma::{
    CACHE_LINE_SIZE, CacheMode, CpuOwned, DeviceOwned, DmaDirection, DmaState, SgDmaGuard, SgEntry,
    SliceDmaGuard, TypedDmaBuffer, TypedDmaGuard, TypedDmaSlice, TypedSgList, cache_line_size,
    flush_cache_range, invalidate_cache_range, writeback_cache_range,
};

// ============================================================================
// Commonly Used IOMMU Types
// ============================================================================

pub use iommu::api::{disable_iommu, enable_iommu, with_iommu};
pub use iommu::types::{DeviceId, IommuError};

// Benchmark exports (only available with "bench" feature)
#[cfg(feature = "bench")]
pub use iommu::{IovaBitmap, IovaBitmapV2, IovaAllocatorSimple};

// ============================================================================
// Usage Guide
// ============================================================================
//
// For specific subsystems, use direct module paths:
//
// - NVMe:        `use crate::io::nvme::{NvmePollingDriver, ...};`
// - VirtIO:      `use crate::io::virtio::{VirtioBlkDevice, ...};`
// - PCI:         `use crate::io::pci::{PciDeviceInfo, Bar, ...};`
// - ACPI:        `use crate::io::acpi::{AcpiParser, ...};`
// - I/O Sched:   `use crate::io::io_scheduler::{IoScheduler, ...};`
// - HID:         `use crate::io::hid::{KeyCode, KeyEvent, ...};`
// - ATAPI:       `use ahci_driver::atapi::{CdDvdDrive, ...};`
