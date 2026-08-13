use acpi_driver::{AcpiError, AcpiRuntime, HhdmAcpiMemory, TableCatalog};
use spin::Once;

static TABLE_CATALOG: Once<TableCatalog> = Once::new();
static ACPI_RUNTIME: Once<AcpiRuntime> = Once::new();

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
