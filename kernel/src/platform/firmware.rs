use crate::sync::InitOnce;
use acpi_driver::{AcpiError, AcpiRuntime, HhdmAcpiMemory, TableCatalog};

static TABLE_CATALOG: InitOnce<TableCatalog> = InitOnce::new();
static ACPI_RUNTIME: InitOnce<AcpiRuntime> = InitOnce::new();
static NUMA_PLACEMENT: InitOnce<crate::mm::numa::placement::NumaPlacement> = InitOnce::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwarePlacementError {
    Acpi(AcpiError),
    Placement(crate::mm::numa::placement::PlacementError),
}

impl From<AcpiError> for FirmwarePlacementError {
    fn from(error: AcpiError) -> Self {
        Self::Acpi(error)
    }
}
impl From<crate::mm::numa::placement::PlacementError> for FirmwarePlacementError {
    fn from(error: crate::mm::numa::placement::PlacementError) -> Self {
        Self::Placement(error)
    }
}

/// Decode the static firmware catalog once into kernel locality coordinates.
/// CPU publication and PMM admission borrow this same immutable placement.
/// Failed decoding publishes nothing and remains retryable. An absent catalog
/// represents the single-node boot environment and must not later be replaced.
pub fn numa_placement()
-> Result<&'static crate::mm::numa::placement::NumaPlacement, FirmwarePlacementError> {
    use crate::mm::numa::placement::{CpuAffinity, MemoryAffinity, NumaPlacement, PlacementError};
    NUMA_PLACEMENT.try_call_once(|| {
        let Some(catalog) = tables() else {
            return NumaPlacement::try_new(&[], &[], |a, b| Some(if a == b { 10 } else { 20 }))
                .map_err(Into::into);
        };
        let firmware_cpus = catalog.numa_cpu_affinity()?;
        let firmware_memory = catalog.numa_memory_affinity()?;
        let mut cpus = alloc::vec::Vec::new();
        cpus.try_reserve_exact(firmware_cpus.len())
            .map_err(|_| PlacementError::MetadataAllocation)?;
        cpus.extend(
            firmware_cpus
                .iter()
                .filter(|cpu| cpu.enabled)
                .map(|cpu| CpuAffinity {
                    apic_id: crate::cpu::ApicId::new(cpu.apic_id),
                    proximity_domain: cpu.proximity_domain,
                }),
        );
        let mut memory = alloc::vec::Vec::new();
        memory
            .try_reserve_exact(firmware_memory.len())
            .map_err(|_| PlacementError::MetadataAllocation)?;
        for region in firmware_memory
            .iter()
            .filter(|region| region.enabled && region.length != 0)
        {
            memory.push(MemoryAffinity {
                base: x86_64::PhysAddr::try_new(region.base)
                    .map_err(|_| PlacementError::InvalidMemoryRange)?,
                bytes: region.length,
                proximity_domain: region.proximity_domain,
            });
        }
        let distances = catalog.numa_distances()?;
        NumaPlacement::try_new(&cpus, &memory, |a, b| match distances {
            Some(distances) => distances.distance(a, b),
            None => Some(if a == b { 10 } else { 20 }),
        })
        .map_err(Into::into)
    })
}

/// Copies the firmware table graph into the kernel-owned catalog.
///
/// # Safety
///
/// `rsdp_address` and all physical pointers reachable from it must be readable
/// through the supplied HHDM mapping for the duration of this call.
///
/// # Errors
///
/// Returns a typed ACPI error when the RSDP or any referenced table is invalid.
pub unsafe fn initialize_tables(
    rsdp_address: u64,
    hhdm_offset: u64,
) -> Result<&'static TableCatalog, AcpiError> {
    if let Some(catalog) = TABLE_CATALOG.get() {
        return Ok(catalog);
    }
    let memory = HhdmAcpiMemory::new(hhdm_offset);
    let catalog = unsafe { TableCatalog::load(&memory, rsdp_address)? };
    Ok(TABLE_CATALOG.call_once(|| catalog))
}

/// Builds the AML namespace and resumable execution runtime from the static
/// catalog. Failure leaves static table consumers operational.
///
/// # Errors
///
/// Returns an error if the static table catalog has not been initialized.
pub fn initialize_runtime() -> Result<&'static AcpiRuntime, &'static str> {
    if let Some(runtime) = ACPI_RUNTIME.get() {
        return Ok(runtime);
    }
    let catalog = TABLE_CATALOG
        .get()
        .ok_or("ACPI table catalog has not been initialized")?
        .clone();
    Ok(ACPI_RUNTIME.call_once(|| AcpiRuntime::new(catalog)))
}

pub fn tables() -> Option<&'static TableCatalog> {
    TABLE_CATALOG.get()
}

pub fn runtime() -> Option<&'static AcpiRuntime> {
    ACPI_RUNTIME.get()
}
