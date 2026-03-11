// ============================================================================
// I/O Infrastructure Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================
//
// `crate::io` is the kernel-owned I/O framework layer:
// - DMA / IOMMU services
// - interrupt delivery and polling infrastructure
// - logging and HAL access wrappers
//
// Device-facing modules remain here as compatibility shims, but new kernel
// code should use `crate::drivers::*` as the explicit kernel/driver boundary.

// ============================================================================
// Submodules
// ============================================================================

// Driver/bus compatibility shims. Prefer `crate::drivers::*` from new code.
pub mod acpi;
pub mod ahci;
pub mod apic;
pub mod audio;
// Kernel-owned infrastructure.
pub mod dma;
pub mod gpu;
pub mod hid;
pub mod ide;
pub mod interrupt_manager;
pub mod io_scheduler;
pub mod iommu;
pub mod log;
pub mod msix;
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

// ============================================================================
// Usage Guide
// ============================================================================
//
// For specific subsystems, use direct module paths:
//
// - Driver boundary: `use crate::drivers::{nvme, virtio, pci, acpi, ...};`
// - DMA/IOMMU:       `use crate::io::{dma, iommu};`
// - Interrupts:      `use crate::io::interrupt_manager;`
// - Logging/HAL:     `use crate::io::{log, mmio, port_io};`
//
// Compatibility paths still exist:
// - NVMe:        `use crate::io::nvme::{NvmePollingDriver, ...};`
// - VirtIO:      `use crate::io::virtio::{VirtioBlkDevice, ...};`
// - PCI:         `use crate::io::pci::{PciDeviceInfo, Bar, ...};`
// - ACPI:        `use crate::io::acpi::{AcpiParser, ...};`
// - I/O Sched:   `use crate::io::io_scheduler::{IoScheduler, ...};`
// - HID:         `use crate::io::hid::{KeyCode, KeyEvent, ...};`
// - ATAPI:       `use ahci_driver::atapi::{CdDvdDrive, ...};`
