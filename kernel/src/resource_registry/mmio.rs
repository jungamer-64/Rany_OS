//! Resource claims and register mappings outlast every derived access.

use crate::domain::DomainId;
use crate::sync::InitOnce;
use alloc::sync::{Arc, Weak};
use boot_proto::MemoryDescriptor;
use core::sync::atomic::{AtomicU64, Ordering};
use exorust_sync::Mutex;
use kernel_api::abi::driver::AbiMmioGrant;
use kernel_api::mmio::{MmioAcquireError, PciMmioRequest};

const MAX_GRANTS: usize = 256;
static MEMORY_MAP: InitOnce<&'static [MemoryDescriptor]> = InitOnce::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static CLAIMS: Mutex<[Option<Weak<MappingOwner>>; MAX_GRANTS]> =
    Mutex::new([const { None }; MAX_GRANTS]);
static EXPORTED: Mutex<[Option<ExportedGrant>; MAX_GRANTS]> =
    Mutex::new([const { None }; MAX_GRANTS]);

struct MappingOwner {
    identity: u64,
    domain: DomainId,
    start: u64,
    end: u64,
    _resource: MappingResource,
}

enum MappingResource {
    Pci {
        _function: Arc<crate::drivers::pci::resource::FunctionResources>,
    },
    AcpiFirmware {
        _source: &'static (dyn Send + Sync),
    },
    IntelFirmware {
        _table: Arc<crate::drivers::acpi::AcpiTable>,
    },
    AmdFirmware {
        _table: crate::drivers::acpi::AcpiTable,
        _function: Arc<crate::drivers::pci::resource::FunctionResources>,
    },
}

struct Acquired {
    mapping: hal::MappedMmio,
    owner: Arc<MappingOwner>,
    base: usize,
}
struct ExportedGrant {
    _mapping: hal::MappedMmio,
    owner: Arc<MappingOwner>,
}

pub(crate) fn initialize(memory_map: &'static [MemoryDescriptor]) {
    MEMORY_MAP.call_once(|| memory_map);
}

fn acquire(domain: DomainId, request: PciMmioRequest) -> Result<Acquired, MmioAcquireError> {
    if request.device().segment() != 0 {
        return Err(MmioAcquireError::Unavailable);
    }
    let bdf = crate::drivers::pci::BdfAddress::new(
        request.device().bus(),
        request.device().device(),
        request.device().function(),
    );
    let function = crate::drivers::pci::resource::retain(bdf).map_err(|error| match error {
        crate::drivers::pci::resource::FunctionResourceError::Absent => {
            MmioAcquireError::Request(kernel_api::mmio::MmioRequestError::InvalidDevice)
        }
        crate::drivers::pci::resource::FunctionResourceError::Busy => {
            MmioAcquireError::ResourceBusy
        }
        crate::drivers::pci::resource::FunctionResourceError::Exhausted => {
            MmioAcquireError::ResourceExhausted
        }
    })?;
    let snapshot = crate::platform::pci::from_native_device(function.info().clone());
    let geometry = request
        .resolve(&snapshot)
        .map_err(MmioAcquireError::Request)?;
    let start = geometry.physical_start().as_u64();
    let length = geometry.range().byte_count();
    acquire_aperture(
        domain,
        start,
        length,
        MappingResource::Pci {
            _function: function,
        },
    )
}

/// Only an immutable, catalogued IVHD descriptor admits an AMD register claim.
/// The common claim index excludes overlapping PCI and firmware apertures.
pub(crate) fn acquire_amd_iommu(
    unit: &crate::drivers::acpi::ivrs::IvhdInfo,
) -> Result<
    (
        hal::MappedMmio,
        Arc<crate::drivers::pci::resource::FunctionResources>,
    ),
    MmioAcquireError,
> {
    let table = crate::platform::firmware::tables()
        .and_then(|catalog| catalog.first(crate::drivers::acpi::TableSignature::IVRS))
        .ok_or(MmioAcquireError::Unavailable)?;
    let description = crate::drivers::acpi::ivrs::parse(table.bytes())
        .map_err(|_| MmioAcquireError::MappingFailed)?;
    if !description.ivhds.iter().any(|record| record == unit) {
        return Err(MmioAcquireError::PermissionDenied);
    }
    // AMD IOMMU specification, Base Address Low: the control register prefix
    // occupies 16 KiB at a 16 KiB aligned address. Counter extensions lie outside
    // this claim and require their own admission before access.
    if unit.iommu_base == 0 || !unit.iommu_base.is_multiple_of(0x4000) {
        return Err(MmioAcquireError::MappingFailed);
    }
    if unit.pci_segment != 0 {
        return Err(MmioAcquireError::Unavailable);
    }
    let bdf = crate::drivers::pci::BdfAddress::from_u16(unit.device_id);
    let function = crate::drivers::pci::resource::retain(bdf).map_err(|error| match error {
        crate::drivers::pci::resource::FunctionResourceError::Absent => {
            MmioAcquireError::Unavailable
        }
        crate::drivers::pci::resource::FunctionResourceError::Busy => {
            MmioAcquireError::ResourceBusy
        }
        crate::drivers::pci::resource::FunctionResourceError::Exhausted => {
            MmioAcquireError::ResourceExhausted
        }
    })?;
    acquire_aperture(
        DomainId::KERNEL,
        unit.iommu_base,
        0x4000,
        MappingResource::AmdFirmware {
            _table: table.clone(),
            _function: Arc::clone(&function),
        },
    )
    .map(|grant| (grant.mapping, function))
}

/// Firmware grants the register resource independently of a PCI BAR. The probe
/// and complete claim share the claim lock, so no other aperture can be admitted
/// between the two reads and final publication. The probe never escapes here.
pub(crate) fn acquire_intel_iommu(
    unit: &crate::drivers::acpi::dmar::DrhdUnit,
) -> Result<hal::MappedMmio, MmioAcquireError> {
    let table = crate::platform::firmware::tables()
        .and_then(|catalog| catalog.first(crate::drivers::acpi::TableSignature::DMAR))
        .ok_or(MmioAcquireError::Unavailable)?;
    let description = crate::drivers::acpi::dmar::parse(table.bytes())
        .map_err(|_| MmioAcquireError::MappingFailed)?;
    if !description.drhd_units.iter().any(|record| record == unit) {
        return Err(MmioAcquireError::PermissionDenied);
    }
    if unit.register_base == 0 || !unit.register_base.is_multiple_of(4096) {
        return Err(MmioAcquireError::MappingFailed);
    }
    let table = Arc::try_new(table.clone()).map_err(|_| MmioAcquireError::OutOfMemory)?;
    let mut claims = CLAIMS.lock();
    let probe_geometry = validate_aperture(unit.register_base, 4096, &claims)?;
    // SAFETY: this catalogued DRHD owns the firmware device aperture. The claim
    // lock excludes all overlapping admissions, validation excludes RAM and
    // checks effective UC and translation, and permanent page tables retain it.
    let probe =
        unsafe { hal::MappedMmio::from_raw_parts(table.clone(), probe_geometry.base, 4096) }
            .map_err(|_| MmioAcquireError::MappingFailed)?;
    let region = probe.region();
    let cap = region
        .read_only::<u64>(8)
        .map_err(|_| MmioAcquireError::MappingFailed)?
        .read();
    let ecap = region
        .read_only::<u64>(16)
        .map_err(|_| MmioAcquireError::MappingFailed)?
        .read();
    let length = crate::io::iommu::vendors::intel::registers::register_extent(cap, ecap)
        .map_err(|_| MmioAcquireError::MappingFailed)?;
    let geometry = validate_aperture(unit.register_base, length, &claims)?;
    publish_aperture(
        DomainId::KERNEL,
        geometry,
        MappingResource::IntelFirmware { _table: table },
        &mut claims,
    )
    .map(|acquired| acquired.mapping)
}

struct ValidatedAperture {
    start: u64,
    end: u64,
    base: usize,
    length: usize,
}

fn validate_aperture(
    start: u64,
    length: usize,
    claims: &[Option<Weak<MappingOwner>>; MAX_GRANTS],
) -> Result<ValidatedAperture, MmioAcquireError> {
    let end = start
        .checked_add(length as u64)
        .ok_or(MmioAcquireError::MappingFailed)?;
    let memory_map = MEMORY_MAP.get().ok_or(MmioAcquireError::Unavailable)?;
    // LOOP_PROOF: mode=bounded; reason=The immutable boot memory map has a finite descriptor count; every descriptor is checked exactly once.;
    for entry in *memory_map {
        let bytes = entry
            .page_count
            .checked_mul(4096)
            .ok_or(MmioAcquireError::PhysicalMemoryConflict)?;
        let entry_end = entry
            .phys_start
            .checked_add(bytes)
            .ok_or(MmioAcquireError::PhysicalMemoryConflict)?;
        if start < entry_end && entry.phys_start < end && entry.r#type != 11 {
            return Err(MmioAcquireError::PhysicalMemoryConflict);
        }
    }
    // LOOP_PROOF: mode=bounded; reason=The claim index contains at most MAX_GRANTS entries.;
    for owner in claims.iter().flatten().filter_map(Weak::upgrade) {
        if start < owner.end && owner.start < end {
            return Err(MmioAcquireError::ResourceBusy);
        }
    }
    let base = crate::mm::virt::higher_half::validate_device_aperture(start, length)?;
    Ok(ValidatedAperture {
        start,
        end,
        base,
        length,
    })
}

fn publish_aperture(
    domain: DomainId,
    geometry: ValidatedAperture,
    resource: MappingResource,
    claims: &mut [Option<Weak<MappingOwner>>; MAX_GRANTS],
) -> Result<Acquired, MmioAcquireError> {
    let slot = claims
        .iter_mut()
        .find(|entry| entry.as_ref().is_none_or(|weak| weak.strong_count() == 0))
        .ok_or(MmioAcquireError::ResourceExhausted)?;
    let identity = NEXT_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| MmioAcquireError::ResourceExhausted)?;
    let owner = Arc::try_new(MappingOwner {
        identity,
        domain,
        start: geometry.start,
        end: geometry.end,
        _resource: resource,
    })
    .map_err(|_| MmioAcquireError::OutOfMemory)?;
    // SAFETY: the retained resource excludes configuration repurposing;
    // validation under the still-held claim lock excludes RAM and overlapping
    // admissions and checks both permanent aliases for UC and translation.
    let mapping =
        unsafe { hal::MappedMmio::from_raw_parts(owner.clone(), geometry.base, geometry.length) }
            .map_err(|_| MmioAcquireError::MappingFailed)?;
    *slot = Some(Arc::downgrade(&owner));
    Ok(Acquired {
        mapping,
        owner,
        base: geometry.base,
    })
}

fn acquire_aperture(
    domain: DomainId,
    start: u64,
    length: usize,
    resource: MappingResource,
) -> Result<Acquired, MmioAcquireError> {
    let mut claims = CLAIMS.lock();
    let geometry = validate_aperture(start, length, &claims)?;
    publish_aperture(domain, geometry, resource, &mut claims)
}

/// Admission accepts only a claim derived from the retained immutable firmware
/// namespace. The common index keeps PCI and firmware mappings disjoint.
pub(crate) fn acquire_firmware_registers(
    claim: &crate::platform::firmware_registers::FirmwareMemoryClaim,
) -> Result<hal::MappedMmio, MmioAcquireError> {
    let (base, length) = claim.range();
    acquire_aperture(
        DomainId::KERNEL,
        base,
        length,
        MappingResource::AcpiFirmware {
            _source: claim.retained_source(),
        },
    )
    .map(|grant| grant.mapping)
}

pub(crate) fn acquire_native(
    domain: DomainId,
    request: PciMmioRequest,
) -> Result<hal::MappedMmio, MmioAcquireError> {
    acquire(domain, request).map(|grant| grant.mapping)
}

/// Reserves ABI storage before acquisition; no fallible publication follows a
/// transfer of access authority to the caller's output.
pub(crate) fn export(
    domain: DomainId,
    request: PciMmioRequest,
) -> Result<AbiMmioGrant, MmioAcquireError> {
    let mut exported = EXPORTED.lock();
    let slot = exported
        .iter_mut()
        .find(|entry| entry.is_none())
        .ok_or(MmioAcquireError::ResourceExhausted)?;
    let acquired = acquire(domain, request)?;
    let metadata = AbiMmioGrant {
        identity: acquired.owner.identity,
        base: acquired.base,
        length: acquired.mapping.len(),
    };
    *slot = Some(ExportedGrant {
        _mapping: acquired.mapping,
        owner: acquired.owner,
    });
    Ok(metadata)
}

/// Private ABI retirement is linear and caller-scoped. Unknown/foreign identities
/// indicate a broken runtime contract and never revoke someone else's mapping.
pub(crate) fn release(domain: DomainId, identity: u64) {
    let removed = {
        let mut exported = EXPORTED.lock();
        let entry = exported.iter_mut().find(|entry| {
            entry.as_ref().is_some_and(|grant| {
                grant.owner.identity == identity && grant.owner.domain == domain
            })
        });
        entry.and_then(Option::take)
    };
    assert!(
        removed.is_some(),
        "invalid or repeated MMIO grant retirement"
    );
    drop(removed);
}
