// ============================================================================
// I/O Subsystem Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================
pub mod acpi;
pub mod ahci;
// ATAPI support migrated to `ahci_driver` crate (re-exported later)
pub mod apic;
pub mod audio;
pub mod dma;
pub mod hid; // HID subsystem (directory) - keyboard.rs, mouse.rs, ps2.rs
pub mod ide;
pub mod interrupt_manager; // Unified interrupt management with Waker bridge (設計書 4.2)
pub mod io_scheduler; // Polling/Executor連携 I/Oスケジューラ
pub mod iommu;
pub mod log;
pub mod nvme; // NVMe module (directory) - includes driver.rs
pub mod pci; // PCI common module (directory)
// polling.rs は削除済み - io_scheduler.rs に統一
pub mod rtc;
pub mod serial;
pub mod usb;
pub mod virtio; // VirtIO module (directory) - includes net.rs and blk.rs
// Use `hal` crate for low-level MMIO and port I/O wrappers to centralize
// unsafe operations across kernel and drivers. The `hal` crate provides the
// safe functions `mmio_*` and `inb/outb` wrappers which are re-exported here
// for convenience.
pub use hal::mmio;
pub use hal::port_io;

#[allow(unused_imports)]
pub use dma::{
    CACHE_LINE_SIZE,
    // Cache coherency management (integrated from dma_cache.rs)
    CacheMode,
    CoherentDmaBuffer,
    CpuOwned,
    DeviceOwned,
    DmaDirection,
    DmaMemoryAttributes,
    DmaState,
    IommuDmaBuffer,
    SgEntry,
    StreamingDmaMapping,
    // 型安全DMA（型状態パターン）
    TypedDmaBuffer,
    TypedDmaGuard,
    TypedDmaSlice,
    TypedSgList,
    cache_line_size,
    clflush,
    clflushopt,
    clwb,
    flush_cache_range,
    invalidate_cache_range,
    lfence,
    mfence,
    sfence,
    supports_clflushopt,
    supports_clwb,
    writeback_cache_range,
};
#[allow(unused_imports)]
pub use iommu::{
    DeviceId, DmaMapping, IommuController, IommuDomain, IommuError, disable_iommu, enable_iommu,
    init_iommu, with_iommu,
};
// NVMe common types (from nvme/ directory)
#[allow(unused_imports)]
pub use nvme::{
    AdminOpcode,
    AsyncIoRequest,
    CompletionQueue,
    IdentifyController,
    IdentifyNamespace,
    IoOpcode,
    IoRequestState,
    NvmeCapabilities,
    NvmeCommand,
    NvmeCompletion,
    // Polling driver (from nvme/driver.rs split modules)
    NvmePollingDriver,
    NvmeQueueStats,
    NvmeStatus,
    PerCoreNvmeQueue,
    QueuePair,
    SubmissionQueue,
    init_nvme_polling,
    nvme_poll,
};
// polling.rs は削除済み - io_scheduler.rs に統一
// AdaptiveIoController, IoMode 等は io_scheduler から利用可能

// I/O Scheduler exports (Polling/Executor連携)
#[allow(unused_imports)]
pub use io_scheduler::{
    DeviceId as IoDeviceId,
    DeviceIoModeController,
    HybridIoCoordinator,
    IoError,
    IoFuture,
    // Bridge
    IoInterruptBridge,
    IoMode as SchedulerIoMode,
    IoModeStats,
    // Types
    IoOperationType,
    IoPriority,
    IoRequest,
    IoRequestId,
    IoResult,
    // Scheduler
    IoScheduler,
    IoSchedulerStats,
    IoState,
    // Mode control
    ModeThresholds,
    PollHandler,
    // Executor
    PollingExecutor,
    async_flush,
    // Convenience API
    async_read,
    async_write,
    hybrid_coordinator,
    // Global access
    init_io_scheduler,
    io_scheduler,
};

// VirtIO-Blk exports (from virtio/blk.rs)
#[allow(unused_imports)]
pub use virtio::{
    AsyncBlockDevice, BlkVirtQueue as VirtQueue, BlkVringDesc as VringDesc, BlockDeviceConfig,
    BlockError, VirtioBlkDevice, blk_features, handle_virtio_blk_interrupt, init_virtio_blk,
};
// VirtIO-Net exports (from virtio/net.rs)
#[allow(unused_imports)]
pub use virtio::{
    NetVirtQueue, VirtioNetConfig, VirtioNetDevice, VirtioNetHeader, VirtioNetStats,
    VringDesc as NetVringDesc, handle_virtio_net_interrupt, init_virtio_net, net_features,
    with_virtio_net,
};

// HID subsystem exports (keyboard, ps2)
#[allow(unused_imports)]
pub use hid::{
    CharFuture,
    DEFAULT_KEYMAP,
    // Keyboard driver
    KeyCode,
    KeyEvent,
    KeyEventFuture,
    KeyState,
    KeyboardDriver,
    KeyboardHandler,
    KeyboardStream,
    // Keymap support
    Keymap,
    MouseButton,
    MouseEvent,
    MouseHandler,
    Ps2Controller,
    Ps2DeviceType,
    Ps2KeyCode,
    Ps2KeyEvent,
    Ps2Modifiers,
    StreamAlreadyTaken,
    UsQwertyKeymap,
    get_key_event,
    get_modifiers,
    get_mouse_event,
    handle_keyboard_interrupt,
    keyboard,
    keyboard_init,
    keyboard_interrupt_handler,
    mouse_interrupt_handler,
    ps2_commands,
    ps2_init,
    ps2_kbd_commands,
    ps2_mouse_commands,
    // PS/2 Controller
    ps2_ports,
    ps2_status,
    set_leds,
};

// PCI common module exports (unified interface)
#[allow(unused_imports)]
pub use pci::{
    Bar,
    BdfAddress,
    CapabilityId as PciCapabilityId,
    ClassCode as PciClassCode,
    // Core traits and types
    ConfigSpaceAccessor,
    DeliveryMode,
    DeviceId as PciDeviceId,
    EcamAccess,
    EcamManager,
    LegacyPciAccessor,
    MsiCapability,
    // MSI/MSI-X support
    MsiConfig,
    MsixCapability,
    MsixTableEntry,
    PciBusScanner,
    PciDeviceInfo,
    TriggerMode,
    VendorId,
    allocate_vector,
    allocate_vectors,
    command_bits as pci_command_bits,
    // Config space helpers
    config_regs as pci_config_regs,
    disable_intx,
    enable_intx,
    find_by_class as pci_find_by_class,
    find_by_id,
    find_virtio_devices as pci_find_virtio_devices,
    init as pci_init,
    // Legacy I/O port access
    pci_read,
    pci_read8,
    pci_read16,
    pci_write,
    // Convenience functions
    scan_all_devices as pci_devices,
    setup_msi,
    setup_msix,
    status_bits as pci_status_bits,
};

// Deprecated: backward compatibility helper for legacy PCI accessors. Prefer
// `crate::io::pci::get_legacy_accessor` or the newer accessors in the
// `pci_driver` crate and avoid calling legacy accessors directly.
#[deprecated(
    note = "get_legacy_accessor is deprecated; prefer the newer accessors in the `pci_driver` crate."
)]
pub use crate::io::pci::get_legacy_accessor;

pub use mmio::{
    mmio_read_u8, mmio_read_u16, mmio_read_u32, mmio_read_u64, mmio_write_u8, mmio_write_u16,
    mmio_write_u32, mmio_write_u64, volatile_read, volatile_write,
};
#[allow(unused_imports)]
pub use port_io::{inb, inl, inw, outb, outl, outw};

// ACPI table parser
#[allow(unused_imports)]
pub use acpi::{
    AcpiError, AcpiInfo, AcpiParser, AcpiSdtHeader, Fadt, InterruptOverrideInfo, IoApicInfo,
    LocalApicInfo, Madt, Mcfg, PcieEcamInfo, Rsdp, init as acpi_init, interrupt_overrides,
    io_apics, local_apic_address, local_apics, pcie_ecam_regions, processor_count,
};
/// Helper to parse DMAR table; wraps the `acpi::dmar::parse_dmar` helper so
/// other `io` submodules (e.g., `iommu`) can call it without referencing the
/// `acpi` module directly by path (helps avoid some resolution issues).
pub fn parse_dmar_table(addr: usize) -> Result<acpi::dmar::DmarInfo, &'static str> {
    unsafe { acpi::dmar::parse_dmar(addr) }
}
// AHCI ATAPI exports (CD/DVD support) - re-export from ahci_driver crate
#[allow(unused_imports)]
pub use ahci_driver::atapi::{
    AtapiDeviceType,
    // ATAPI Port
    AtapiPort,
    CD_AUDIO_SECTOR_SIZE,
    // Constants
    CD_SECTOR_SIZE,
    // CD/DVD Drive
    CdDvdDrive,
    CdDvdDriveInfo,
    // Response structures
    InquiryResponse,
    ReadCapacityResponse,
    // SCSI CDB
    ScsiCdb12,
    ScsiOpcode,
    SenseData,
    SenseKey,
    TableOfContents,
    TocFormat,
    // TOC structures
    TocHeader,
    TocTrackDescriptor,
};

// VirtIO Common Module exports
#[allow(unused_imports)]
pub use virtio::{
    TrackedVirtQueue,
    VIRTQUEUE_DEFAULT_SIZE,
    VIRTQUEUE_MAX_SIZE,
    // Core types
    VirtQueue as CommonVirtQueue,
    VirtioDeviceType,
    VirtioPciCap,
    VirtioTransport,
    VringAvailHeader,
    VringDesc as CommonVringDesc,
    VringUsedElem as CommonVringUsedElem,
    VringUsedHeader,
    common_features as virtio_common_features,
    mmio_regs as virtio_mmio_regs,
    status as virtio_status,
    // Constants
    vring_flags,
};
