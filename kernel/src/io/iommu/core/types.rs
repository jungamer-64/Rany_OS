// ============================================================================
// kernel/src/io/iommu/types.rs
// ============================================================================

//! IOMMU Type Definitions

use alloc::vec::Vec;
use pci_driver::PcieError;

/// IOMMU error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuError {
    /// IOMMU not initialized
    NotInitialized,
    /// IOMMU not present
    NotPresent,
    /// Not supported
    NotSupported,
    /// Already initialized
    AlreadyInitialized,
    /// Invalid address
    InvalidAddress,
    /// Invalid alignment
    InvalidAlignment,
    /// Region already mapped
    AlreadyMapped,
    /// Region not mapped
    NotMapped,
    /// Domain not found
    DomainNotFound,
    /// Device not found
    DeviceNotFound,
    /// Hardware error
    HardwareError,
    /// Out of memory
    OutOfMemory,
    /// Out of IOVA space
    OutOfIova,
    /// Timeout
    Timeout,
    /// System entered poisoned state (critical error)
    Poisoned,
    /// RMRR (Reserved Memory Region) mapping failed.
    /// Device must not be used - may cause DMA faults or memory corruption.
    RmrrMapFailed,
}

impl From<PcieError> for IommuError {
    fn from(e: PcieError) -> Self {
        match e {
            PcieError::DeviceNotFound => IommuError::DeviceNotFound,
            PcieError::CapabilityNotFound => IommuError::NotSupported,
            PcieError::NotSupported => IommuError::NotSupported,
            PcieError::ConfigError => IommuError::HardwareError,
            PcieError::ResourceExhausted => IommuError::HardwareError,
            PcieError::VfAllocationFailed => IommuError::HardwareError,
            PcieError::AerError => IommuError::HardwareError,
        }
    }
}

/// Device identifier (BDF: Bus/Device/Function)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DeviceId {
    /// Segment number
    pub segment: u16,
    /// Bus number
    pub bus: u8,
    /// Device number
    pub device: u8,
    /// Function number
    pub function: u8,
}

impl DeviceId {
    /// Create a new device ID
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }

    /// Create from segment, bus, and devfn (device/function packed)
    pub const fn from_bus_devfn(segment: u16, bus: u8, devfn: u8) -> Self {
        Self {
            segment,
            bus,
            device: devfn >> 3,
            function: devfn & 0x07,
        }
    }

    /// Create from BDF packed as u16 (bus:8, device:5, function:3)
    pub const fn from_bdf(bdf: u16) -> Self {
        Self {
            segment: 0,
            bus: ((bdf >> 8) & 0xFF) as u8,
            device: ((bdf >> 3) & 0x1F) as u8,
            function: (bdf & 0x07) as u8,
        }
    }

    /// Get BDF as packed u16 (bus:8, device:5, function:3)
    pub const fn bdf(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }

    /// Get requester ID (used for root/context table indexing)
    pub fn requester_id(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }
}

/// I/O Virtual Address (IOVA) used for DMA operations.
/// Clearly distinguished from PhysAddr to prevent accidental misuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct DmaAddr(pub u64);

impl DmaAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for DmaAddr {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<DmaAddr> for u64 {
    fn from(val: DmaAddr) -> u64 {
        val.0
    }
}

/// Represents a unique identifier for an IOMMU Group.
/// Currently using DeviceId of the "root" of the group (e.g., a bridge or endpoint).
pub type IommuGroupId = DeviceId;

/// Represents an IOMMU Group, storing information about the assigned domain.
#[derive(Debug, Clone)]
pub struct IommuGroup {
    /// The unique identifier for this IOMMU Group.
    pub id: IommuGroupId,
    /// The IOMMU Domain ID assigned to this group.
    pub domain_id: u16,
    /// The controller index that manages this domain.
    pub controller_idx: usize,
}

/// Domain Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuDomainType {
    /// Normal translated domain
    Translated,
    /// Passthrough domain (identity)
    Passthrough,
}

/// Page Table Entry Format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PteFormat {
    /// Intel VT-d format
    Intel,
    /// AMD-Vi format
    Amd,
}

/// DMA mapping info
#[derive(Clone, Debug)]
pub struct DmaMapping {
    /// I/O virtual address
    pub iova: u64,
    /// Physical address
    pub phys: u64,
    /// Size in bytes
    pub size: u64,
    /// Read permission
    pub read: bool,
    /// Write permission
    pub write: bool,
    /// Domain ID (for IOTLB invalidation)
    pub domain_id_placeholder: u16,
}

/// Device scope type (from DRHD device scope structure)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceScopeType {
    /// PCI Endpoint Device
    PciEndpoint = 1,
    /// PCI Sub-hierarchy (bridge and all downstream devices)
    PciSubHierarchy = 2,
    /// IOAPIC
    Ioapic = 3,
    /// MSI-capable HPET
    MsiCapableHpet = 4,
    /// ACPI namespace device
    AcpiNamespaceDevice = 5,
}

impl DeviceScopeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PciEndpoint),
            2 => Some(Self::PciSubHierarchy),
            3 => Some(Self::Ioapic),
            4 => Some(Self::MsiCapableHpet),
            5 => Some(Self::AcpiNamespaceDevice),
            _ => None,
        }
    }
}

/// Device scope entry (from DRHD structure)
#[derive(Debug, Clone)]
pub struct IommuDeviceScope {
    /// Scope type
    pub scope_type: DeviceScopeType,
    /// Enumeration ID (for IOAPIC, HPET)
    pub enumeration_id: u8,
    /// Start bus number
    pub start_bus: u8,
    /// Path (device, function pairs)
    pub path: Vec<(u8, u8)>,
}

impl IommuDeviceScope {
    /// Create a new device scope
    pub fn new(
        scope_type: DeviceScopeType,
        enumeration_id: u8,
        start_bus: u8,
        path: Vec<(u8, u8)>,
    ) -> Self {
        Self {
            scope_type,
            enumeration_id,
            start_bus,
            path,
        }
    }

    /// Check if a device (bus, device, function) matches this scope
    pub fn matches(&self, bus: u8, device: u8, function: u8) -> bool {
        if self.path.is_empty() {
            return false;
        }

        match self.scope_type {
            DeviceScopeType::PciEndpoint => {
                // Endpoint: exact match required
                let (target_dev, target_func) = self.path[self.path.len() - 1];
                [bus, device, function] == [self.start_bus, target_dev, target_func]
            }
            DeviceScopeType::PciSubHierarchy => {
                // Sub-hierarchy: matches if bus >= start_bus
                if bus < self.start_bus {
                    return false;
                }
                // If device is directly on start_bus, check path
                if bus == self.start_bus {
                    let (bridge_dev, bridge_func) = self.path[0];
                    return device == bridge_dev && function == bridge_func;
                }
                // Device is downstream of start_bus - matches sub-hierarchy
                true
            }
            _ => false, // IOAPIC, HPET, etc. don't match PCI devices
        }
    }
}

/// IOMMU Capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuCapabilities {
    pub queued_invalidation: bool,
    pub interrupt_remapping: bool,
    pub super_page_2mb: bool,
    pub super_page_1gb: bool,
    pub page_walk_coherency: bool,
    pub snoop_control: bool,
    pub posted_interrupts: bool,
    pub scalable_mode: bool,
    pub performance_monitoring: bool,
}

/// Fault reason codes (Intel VT-d spec table 33)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    /// Reserved / No fault
    None,
    /// Root entry not present
    RootNotPresent,
    /// Context entry not present
    ContextNotPresent,
    /// Context entry invalid
    ContextInvalid,
    /// Address outside domain address width
    AddressOutOfRange,
    /// Read access denied
    ReadDenied,
    /// Write access denied
    WriteDenied,
    /// Page table entry invalid
    PageTableInvalid,
    /// Root table invalid
    RootTableInvalid,
    /// Context table invalid
    ContextTableInvalid,
    /// Unknown fault reason
    Unknown(u8),
}

impl From<u8> for FaultReason {
    fn from(code: u8) -> Self {
        match code {
            0x0 => FaultReason::None,
            0x1 => FaultReason::RootNotPresent,
            0x2 => FaultReason::ContextNotPresent,
            0x3 => FaultReason::ContextInvalid,
            0x4 => FaultReason::AddressOutOfRange,
            0x5 => FaultReason::ReadDenied,
            0x6 => FaultReason::WriteDenied,
            0x7 => FaultReason::PageTableInvalid,
            0x8 => FaultReason::RootTableInvalid,
            0x9 => FaultReason::ContextTableInvalid,
            n => FaultReason::Unknown(n),
        }
    }
}
