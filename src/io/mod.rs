// ============================================================================
// I/O Subsystem Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================
pub mod acpi;
pub mod ahci;
pub mod ahci_atapi;   // AHCI ATAPI (CD/DVD) Support
pub mod apic;
pub mod audio;
pub mod dma;
pub mod hid;         // HID subsystem (directory) - keyboard.rs, ps2.rs
pub mod ide;
pub mod io_scheduler; // Polling/Executor連携 I/Oスケジューラ
pub mod iommu;
pub mod log;
pub mod nvme;        // NVMe module (directory) - includes driver.rs
pub mod pci;         // PCI common module (directory)
// polling.rs は削除済み - io_scheduler.rs に統一
pub mod rtc;
pub mod serial;
pub mod usb;
pub mod virtio;      // VirtIO module (directory) - includes net.rs and blk.rs

#[allow(unused_imports)]
pub use dma::{
    CpuOwned,
    DeviceOwned,
    DmaState,
    SgEntry,
    // 型安全DMA（型状態パターン）
    TypedDmaBuffer,
    TypedDmaGuard,
    TypedDmaSlice,
    TypedSgList,
    // Cache coherency management (integrated from dma_cache.rs)
    CacheMode,
    CACHE_LINE_SIZE,
    clflush,
    clflushopt,
    clwb,
    mfence,
    sfence,
    lfence,
    flush_cache_range,
    invalidate_cache_range,
    writeback_cache_range,
    DmaDirection,
    DmaMemoryAttributes,
    CoherentDmaBuffer,
    StreamingDmaMapping,
    IommuDmaBuffer,
    supports_clflushopt,
    supports_clwb,
    cache_line_size,
};
#[allow(unused_imports)]
pub use iommu::{
    DeviceId, DmaMapping, IommuController, IommuDomain, IommuError, disable_iommu, enable_iommu,
    init_iommu, with_iommu,
};
// NVMe common types (from nvme/ directory)
#[allow(unused_imports)]
pub use nvme::{
    NvmeCommand, NvmeCompletion, NvmeStatus,
    IdentifyController, IdentifyNamespace, NvmeCapabilities,
    AdminOpcode, IoOpcode,
    // Polling driver (from nvme/driver.rs)
    NvmePollingDriver, PerCoreNvmeQueue, NvmeQueueStats,
    QueuePair, SubmissionQueue, CompletionQueue,
    AsyncIoRequest, IoRequestState,
    PollingNvmeCommand, PollingNvmeCompletion,
    init_nvme_polling, nvme_poll,
};
// polling.rs は削除済み - io_scheduler.rs に統一
// AdaptiveIoController, IoMode 等は io_scheduler から利用可能

// I/O Scheduler exports (Polling/Executor連携)
#[allow(unused_imports)]
pub use io_scheduler::{
    // Types
    IoOperationType, IoPriority, IoState, IoRequestId, DeviceId as IoDeviceId,
    IoRequest, IoResult, IoError, IoMode as SchedulerIoMode,
    // Mode control
    ModeThresholds, DeviceIoModeController, IoModeStats,
    // Scheduler
    IoScheduler, IoSchedulerStats,
    // Executor
    PollingExecutor, PollHandler, IoFuture,
    // Bridge
    IoInterruptBridge, HybridIoCoordinator,
    // Global access
    init_io_scheduler, io_scheduler, hybrid_coordinator,
    // Convenience API
    async_read, async_write, async_flush,
};

// VirtIO-Blk exports (from virtio/blk.rs)
#[allow(unused_imports)]
pub use virtio::{
    VirtioBlkDevice, BlkVirtQueue as VirtQueue, BlkVringDesc as VringDesc,
    AsyncBlockDevice, BlockDeviceConfig, BlockError,
    blk_features, handle_virtio_blk_interrupt, init_virtio_blk,
};
// VirtIO-Net exports (from virtio/net.rs)
#[allow(unused_imports)]
pub use virtio::{
    VirtioNetDevice, VirtioNetHeader, VirtioNetStats, VirtioNetConfig,
    NetVirtQueue, VringDesc as NetVringDesc,
    net_features, handle_virtio_net_interrupt, init_virtio_net,
    with_virtio_net,
};

// HID subsystem exports (keyboard, ps2)
#[allow(unused_imports)]
pub use hid::{
    // PS/2 Controller
    ps2_ports, ps2_status, ps2_commands, ps2_kbd_commands, ps2_mouse_commands,
    Ps2Controller, Ps2DeviceType, Ps2KeyCode, Ps2KeyEvent, Ps2Modifiers,
    MouseButton, MouseEvent, KeyboardHandler, MouseHandler,
    ps2_init, keyboard_interrupt_handler, mouse_interrupt_handler,
    get_key_event, get_mouse_event, get_modifiers, set_leds,
    // Keyboard driver
    KeyCode, KeyState, KeyEvent, KeyboardDriver,
    KeyEventFuture, CharFuture, LineFuture,
    keyboard, keyboard_init, handle_keyboard_interrupt,
};

// PCI common module exports (unified interface)
#[allow(unused_imports)]
pub use pci::{
    // Core traits and types
    ConfigSpaceAccessor, BdfAddress, Bar, ClassCode as PciClassCode,
    VendorId, DeviceId as PciDeviceId, LegacyPciAccessor, EcamAccess, EcamManager,
    PciBusScanner, PciDeviceInfo, CapabilityId as PciCapabilityId,
    // Config space helpers
    config_regs as pci_config_regs, command_bits as pci_command_bits, status_bits as pci_status_bits,
    // Legacy I/O port access
    pci_read, pci_read8, pci_read16, pci_write, get_legacy_accessor,
    // Convenience functions
    scan_all_devices as pci_devices, find_by_class as pci_find_by_class, find_by_id,
    find_virtio_devices as pci_find_virtio_devices, init as pci_init,
    // MSI/MSI-X support
    MsiConfig, MsiCapability, MsixCapability, MsixTableEntry,
    DeliveryMode, TriggerMode,
    allocate_vector, allocate_vectors, setup_msi, setup_msix,
    disable_intx, enable_intx,
};

// ACPI table parser
#[allow(unused_imports)]
pub use acpi::{
    AcpiError, AcpiInfo, AcpiParser, AcpiSdtHeader, Fadt, InterruptOverrideInfo, IoApicInfo,
    LocalApicInfo, Madt, Mcfg, PcieEcamInfo, Rsdp, init as acpi_init, interrupt_overrides,
    io_apics, local_apic_address, local_apics, pcie_ecam_regions, processor_count,
};

// AHCI ATAPI exports (CD/DVD support)
#[allow(unused_imports)]
pub use ahci_atapi::{
    // SCSI CDB
    ScsiCdb12, ScsiOpcode, TocFormat,
    // Response structures
    InquiryResponse, AtapiDeviceType, ReadCapacityResponse,
    SenseData, SenseKey,
    // TOC structures
    TocHeader, TocTrackDescriptor, TableOfContents,
    // ATAPI Port
    AtapiPort,
    // CD/DVD Drive
    CdDvdDrive, CdDvdDriveInfo,
    // Constants
    CD_SECTOR_SIZE, CD_AUDIO_SECTOR_SIZE,
};

// VirtIO Common Module exports
#[allow(unused_imports)]
pub use virtio::{
    // Core types
    VirtQueue as CommonVirtQueue,
    TrackedVirtQueue,
    VringDesc as CommonVringDesc,
    VringAvailHeader,
    VringUsedElem as CommonVringUsedElem,
    VringUsedHeader,
    VirtioDeviceType,
    VirtioTransport,
    VirtioPciCap,
    // Constants
    vring_flags,
    status as virtio_status,
    mmio_regs as virtio_mmio_regs,
    common_features as virtio_common_features,
    VIRTQUEUE_MAX_SIZE,
    VIRTQUEUE_DEFAULT_SIZE,
};
