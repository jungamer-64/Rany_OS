// ============================================================================
// I/O Subsystem Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================
pub mod virtio;
pub mod virtio_blk;
pub mod virtio_net;
pub mod nvme;
pub mod polling;
pub mod dma;
pub mod iommu;
pub mod keyboard;
pub mod apic;
pub mod serial;
pub mod pci;
pub mod acpi;
pub mod msi;
pub mod ahci;
pub mod usb;
pub mod pcie;
pub mod ide;
pub mod ps2;
pub mod rtc;

// Phase 4: High-Performance I/O
pub mod nvme_polling;

#[allow(unused_imports)]
pub use polling::{
    AdaptiveIoController, IoMode, IoStats, PollingConfig,
    net_io_controller, block_io_controller, polling_loop,
};
#[allow(unused_imports)]
pub use dma::{
    // 型安全DMA（型状態パターン）
    TypedDmaBuffer, TypedDmaSlice, TypedDmaGuard, TypedSgList,
    CpuOwned, DeviceOwned, DmaState,
    SgEntry,
};
#[allow(unused_imports)]
pub use virtio_blk::{
    VirtioBlkDevice, BlockDeviceConfig, BlockError, AsyncBlockDevice,
    VirtQueue, VringDesc, features as blk_features,
    init_virtio_blk, handle_virtio_blk_interrupt,
};
#[allow(unused_imports)]
pub use nvme::{
    NvmeController, NvmeNamespace, NvmeConfig, NvmeError, NvmeStatus,
    NvmeCommand, NvmeCompletion, NvmeQueuePair,
    init_nvme, handle_nvme_interrupt,
};
#[allow(unused_imports)]
pub use iommu::{
    IommuController, IommuDomain, IommuError, DeviceId, DmaMapping,
    init_iommu, enable_iommu, disable_iommu, with_iommu,
};
#[allow(unused_imports)]
pub use virtio_net::{
    VirtioNetDevice, VirtioNetHeader, VirtioNetStats,
    NetVirtQueue, VringDesc as NetVringDesc,
    init_virtio_net, handle_virtio_net_interrupt,
    features as net_features,
};

// PCI bus support
#[allow(unused_imports)]
pub use pci::{
    PciBus, PciDevice, PciBar, PciClass,
    pci_read, pci_write, pci_read16, pci_read8,
    init as pci_init, devices as pci_devices,
    find_by_class as pci_find_by_class,
    find_virtio_devices as pci_find_virtio_devices,
};

// ACPI table parser
#[allow(unused_imports)]
pub use acpi::{
    AcpiParser, AcpiInfo, AcpiError,
    LocalApicInfo, IoApicInfo, InterruptOverrideInfo, PcieEcamInfo,
    Rsdp, AcpiSdtHeader, Madt, Fadt, Mcfg,
    init as acpi_init, local_apic_address, local_apics, io_apics,
    interrupt_overrides, pcie_ecam_regions, processor_count,
};

// MSI/MSI-X interrupt support
#[allow(unused_imports)]
pub use msi::{
    MsiCapability, MsixCapability, MsixTableEntry,
    MsiConfig, DeliveryMode, TriggerMode,
    allocate_vector, allocate_vectors,
    setup_msi, setup_msix,
};

// Phase 4: High-Performance NVMe Polling
#[allow(unused_imports)]
pub use nvme_polling::{
    NvmePollingDriver, PerCoreNvmeQueue, NvmeQueueStats,
    NvmeCommand as PollingNvmeCommand, NvmeCompletion as PollingNvmeCompletion,
    QueuePair, SubmissionQueue, CompletionQueue,
    AsyncIoRequest, IoRequestState,
    init as init_nvme_polling, poll as nvme_poll,
};
