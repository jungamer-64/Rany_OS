// ============================================================================
// I/O Subsystem Module
// 設計書 6: I/Oサブシステム - ゼロコピーとポーリングの極致
// ============================================================================
pub mod acpi;
pub mod ahci;
pub mod apic;
pub mod dma;
pub mod ide;
pub mod iommu;
pub mod keyboard;
pub mod msi;
pub mod nvme;
pub mod pci;
pub mod pcie;
pub mod polling;
pub mod ps2;
pub mod rtc;
pub mod serial;
pub mod usb;
pub mod virtio;
pub mod virtio_blk;
pub mod virtio_net;

// Phase 4: High-Performance I/O
pub mod nvme_polling;

// DMA Cache Coherency Management
pub mod dma_cache;

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
};
#[allow(unused_imports)]
pub use iommu::{
    DeviceId, DmaMapping, IommuController, IommuDomain, IommuError, disable_iommu, enable_iommu,
    init_iommu, with_iommu,
};
#[allow(unused_imports)]
pub use nvme::{
    NvmeCommand, NvmeCompletion, NvmeConfig, NvmeController, NvmeError, NvmeNamespace,
    NvmeQueuePair, NvmeStatus, handle_nvme_interrupt, init_nvme,
};
#[allow(unused_imports)]
pub use polling::{
    AdaptiveIoController, IoMode, IoStats, PollingConfig, block_io_controller, net_io_controller,
    polling_loop,
};
#[allow(unused_imports)]
pub use virtio_blk::{
    AsyncBlockDevice, BlockDeviceConfig, BlockError, VirtQueue, VirtioBlkDevice, VringDesc,
    features as blk_features, handle_virtio_blk_interrupt, init_virtio_blk,
};
#[allow(unused_imports)]
pub use virtio_net::{
    NetVirtQueue, VirtioNetDevice, VirtioNetHeader, VirtioNetStats, VringDesc as NetVringDesc,
    features as net_features, handle_virtio_net_interrupt, init_virtio_net,
};

// PCI bus support
#[allow(unused_imports)]
pub use pci::{
    PciBar, PciBus, PciClass, PciDevice, devices as pci_devices,
    find_by_class as pci_find_by_class, find_virtio_devices as pci_find_virtio_devices,
    init as pci_init, pci_read, pci_read8, pci_read16, pci_write,
};

// ACPI table parser
#[allow(unused_imports)]
pub use acpi::{
    AcpiError, AcpiInfo, AcpiParser, AcpiSdtHeader, Fadt, InterruptOverrideInfo, IoApicInfo,
    LocalApicInfo, Madt, Mcfg, PcieEcamInfo, Rsdp, init as acpi_init, interrupt_overrides,
    io_apics, local_apic_address, local_apics, pcie_ecam_regions, processor_count,
};

// MSI/MSI-X interrupt support
#[allow(unused_imports)]
pub use msi::{
    DeliveryMode, MsiCapability, MsiConfig, MsixCapability, MsixTableEntry, TriggerMode,
    allocate_vector, allocate_vectors, setup_msi, setup_msix,
};

// Phase 4: High-Performance NVMe Polling
#[allow(unused_imports)]
pub use nvme_polling::{
    AsyncIoRequest, CompletionQueue, IoRequestState, NvmeCommand as PollingNvmeCommand,
    NvmeCompletion as PollingNvmeCompletion, NvmePollingDriver, NvmeQueueStats, PerCoreNvmeQueue,
    QueuePair, SubmissionQueue, init as init_nvme_polling, poll as nvme_poll,
};
