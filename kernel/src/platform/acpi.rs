use alloc::vec::Vec;
use kernel_api::service::platform::{
    self as kplatform, AcpiServices, InterruptOverrideInfo, IoApicInfo, LocalApicInfo, PcieEcamInfo,
};

struct BuiltinAcpiProvider;

static BUILTIN_ACPI_PROVIDER: BuiltinAcpiProvider = BuiltinAcpiProvider;

impl AcpiServices for BuiltinAcpiProvider {
    fn local_apics(&self) -> Vec<LocalApicInfo> {
        crate::io::acpi::local_apics()
            .iter()
            .map(|entry| LocalApicInfo {
                processor_id: entry.processor_id,
                apic_id: entry.apic_id,
                enabled: entry.enabled,
                online_capable: entry.online_capable,
            })
            .collect()
    }

    fn io_apics(&self) -> Vec<IoApicInfo> {
        crate::io::acpi::io_apics()
            .iter()
            .map(|entry| IoApicInfo {
                id: entry.id,
                address: entry.address,
                gsi_base: entry.gsi_base,
            })
            .collect()
    }

    fn interrupt_overrides(&self) -> Vec<InterruptOverrideInfo> {
        crate::io::acpi::interrupt_overrides()
            .iter()
            .map(|entry| InterruptOverrideInfo {
                bus: entry.bus,
                source: entry.source,
                gsi: entry.gsi,
                polarity: entry.polarity,
                trigger_mode: entry.trigger_mode,
            })
            .collect()
    }

    fn pcie_ecam_regions(&self) -> Vec<PcieEcamInfo> {
        crate::io::acpi::pcie_ecam_regions()
            .iter()
            .map(|entry| PcieEcamInfo {
                base_address: entry.base_address,
                segment: entry.segment,
                start_bus: entry.start_bus,
                end_bus: entry.end_bus,
            })
            .collect()
    }

    fn local_apic_address(&self) -> Option<u64> {
        crate::io::acpi::local_apic_address()
    }
}

pub fn register_builtin_service() {
    crate::provider_registry::provider_registry().register_builtin_acpi(&BUILTIN_ACPI_PROVIDER);
}

pub fn local_apics() -> Vec<LocalApicInfo> {
    kplatform::try_acpi()
        .map(AcpiServices::local_apics)
        .unwrap_or_else(|| BUILTIN_ACPI_PROVIDER.local_apics())
}

pub fn io_apics() -> Vec<IoApicInfo> {
    kplatform::try_acpi()
        .map(AcpiServices::io_apics)
        .unwrap_or_else(|| BUILTIN_ACPI_PROVIDER.io_apics())
}

pub fn interrupt_overrides() -> Vec<InterruptOverrideInfo> {
    kplatform::try_acpi()
        .map(AcpiServices::interrupt_overrides)
        .unwrap_or_else(|| BUILTIN_ACPI_PROVIDER.interrupt_overrides())
}

pub fn pcie_ecam_regions() -> Vec<PcieEcamInfo> {
    kplatform::try_acpi()
        .map(AcpiServices::pcie_ecam_regions)
        .unwrap_or_else(|| BUILTIN_ACPI_PROVIDER.pcie_ecam_regions())
}

pub fn local_apic_address() -> Option<u64> {
    kplatform::try_acpi()
        .and_then(AcpiServices::local_apic_address)
        .or_else(|| BUILTIN_ACPI_PROVIDER.local_apic_address())
}
