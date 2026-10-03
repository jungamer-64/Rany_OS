// ============================================================================
// kernel/src/io/iommu/common/types.rs
// ============================================================================

//! IOMMU Type Definitions

use alloc::vec::Vec;
use pci_driver::PcieError;

/// IOMMU error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuError {
    /// IOMMU not initialized
    NotInitialized,
    /// Kernel task runtime cannot host an IOMMU service task.
    RuntimeUnavailable,
    /// The published backend and any admitted service task remain owned;
    /// retrying service admission must use their existing owners.
    ServiceAdmission(kernel_api::resource::task::SpawnError),
    /// IOMMU not present
    NotPresent,
    /// Not supported
    NotSupported,
    /// PCI configuration failure retains the precise hardware/resource cause.
    PciConfiguration(PcieError),
    /// Firmware PCI paths or bridge bus ranges cannot be resolved.
    FirmwareScope,
    /// Firmware resource admission or cache/mapping validation failed.
    RegisterMapping(kernel_api::mmio::MmioAcquireError),
    /// A register layout is outside its admitted aperture or misaligned.
    RegisterAccess(hal::mmio::MmioAccessError),
    /// Device trust policy does not admit ATS.
    AtsPolicyDenied,
    /// Already initialized
    AlreadyInitialized,
    /// Invalid address
    InvalidAddress,
    /// Invalid alignment
    InvalidAlignment,
    /// A mapping requires at least one hardware data access permission.
    InvalidPermissions,
    /// Region already mapped
    AlreadyMapped,
    /// Teardown cannot acquire unique ownership while a CPU operation retains a domain.
    InUse,
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
    /// Physical admission retains exhaustion, topology, alignment and metadata causes.
    PhysicalAllocation(crate::mm::phys::frame_allocator::FrameAllocError),
    /// Queue/pool metadata could not be admitted before publication.
    MetadataAllocation,
    /// Out of IOVA space
    OutOfIova,
    /// Retirement generations are exhausted; this allocator cannot safely reuse epochs.
    GenerationExhausted,
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
            PcieError::InvalidBusRange { .. } | PcieError::ConfigMapping(_) => {
                IommuError::PciConfiguration(e)
            }
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

/// A resolved firmware PCI scope. Bus ranges come from the final retained
/// bridge, never from a comparison against the firmware path's starting bus.
#[derive(Debug, Clone, Copy)]
pub(crate) enum IommuDeviceScope {
    Endpoint(DeviceId),
    SubHierarchy {
        bridge: DeviceId,
        secondary: u8,
        subordinate: u8,
    },
}

impl IommuDeviceScope {
    pub(crate) fn matches(&self, device: DeviceId) -> bool {
        match *self {
            Self::Endpoint(target) => device == target,
            Self::SubHierarchy {
                bridge,
                secondary,
                subordinate,
            } => {
                device == bridge
                    || (device.segment == bridge.segment
                        && (secondary..=subordinate).contains(&device.bus))
            }
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

#[cfg(test)]
mod scope_tests {
    use super::*;
    #[cfg_attr(feature = "std", test)]
    #[cfg_attr(not(feature = "std"), test_case)]
    fn resolved_scope_matches_only_its_actual_segment_and_bridge_extent() {
        let endpoint = IommuDeviceScope::Endpoint(DeviceId::new(2, 7, 3, 1));
        assert!(endpoint.matches(DeviceId::new(2, 7, 3, 1)));
        assert!(!endpoint.matches(DeviceId::new(2, 0, 3, 1)));
        assert!(!endpoint.matches(DeviceId::new(0, 7, 3, 1)));
        let scope = IommuDeviceScope::SubHierarchy {
            bridge: DeviceId::new(2, 0, 3, 0),
            secondary: 7,
            subordinate: 9,
        };
        assert!(scope.matches(DeviceId::new(2, 0, 3, 0)));
        assert!(scope.matches(DeviceId::new(2, 7, 0, 0)));
        assert!(scope.matches(DeviceId::new(2, 9, 31, 7)));
        assert!(!scope.matches(DeviceId::new(2, 6, 0, 0)));
        assert!(!scope.matches(DeviceId::new(2, 10, 0, 0)));
        assert!(!scope.matches(DeviceId::new(0, 7, 0, 0)));
    }
}
