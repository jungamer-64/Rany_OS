use alloc::vec::Vec;
use boot_proto::AcpiBootSnapshot;
use kernel_api::service::platform::{
    self as kplatform, AcpiServices, InterruptOverrideInfo, IoApicInfo, LocalApicInfo, PcieEcamInfo,
};
use spin::Mutex;

struct BuiltinAcpiProvider;

static BUILTIN_ACPI_PROVIDER: BuiltinAcpiProvider = BuiltinAcpiProvider;
static BOOT_ACPI_SNAPSHOT: Mutex<Option<&'static AcpiBootSnapshot>> = Mutex::new(None);

fn boot_snapshot() -> Option<&'static AcpiBootSnapshot> {
    *BOOT_ACPI_SNAPSHOT.lock()
}

pub fn install_boot_snapshot(snapshot: &'static AcpiBootSnapshot) {
    let mut slot = BOOT_ACPI_SNAPSHOT.lock();
    *slot = snapshot.is_valid().then_some(snapshot);
}

#[cfg(test)]
pub(crate) fn clear_boot_snapshot_for_tests() {
    *BOOT_ACPI_SNAPSHOT.lock() = None;
}

fn snapshot_local_apics() -> Option<Vec<LocalApicInfo>> {
    let snapshot = boot_snapshot()?;
    Some(
        snapshot
            .local_apics()
            .iter()
            .map(|entry| LocalApicInfo {
                processor_id: entry.processor_id,
                apic_id: entry.apic_id,
                enabled: entry.enabled(),
                online_capable: entry.online_capable(),
            })
            .collect(),
    )
}

fn snapshot_io_apics() -> Option<Vec<IoApicInfo>> {
    let snapshot = boot_snapshot()?;
    Some(
        snapshot
            .io_apics()
            .iter()
            .map(|entry| IoApicInfo {
                id: entry.id,
                address: entry.address,
                gsi_base: entry.gsi_base,
            })
            .collect(),
    )
}

fn snapshot_interrupt_overrides() -> Option<Vec<InterruptOverrideInfo>> {
    let snapshot = boot_snapshot()?;
    Some(
        snapshot
            .interrupt_overrides()
            .iter()
            .map(|entry| InterruptOverrideInfo {
                bus: entry.bus,
                source: entry.source,
                gsi: entry.gsi,
                polarity: entry.polarity,
                trigger_mode: entry.trigger_mode,
            })
            .collect(),
    )
}

fn snapshot_pcie_ecam_regions() -> Option<Vec<PcieEcamInfo>> {
    let snapshot = boot_snapshot()?;
    Some(
        snapshot
            .pcie_ecam()
            .iter()
            .map(|entry| PcieEcamInfo {
                base_address: entry.base_address,
                segment: entry.segment,
                start_bus: entry.start_bus,
                end_bus: entry.end_bus,
            })
            .collect(),
    )
}

fn snapshot_local_apic_address() -> Option<u64> {
    let snapshot = boot_snapshot()?;
    Some(snapshot.local_apic_address)
}

impl AcpiServices for BuiltinAcpiProvider {
    fn local_apics(&self) -> Vec<LocalApicInfo> {
        snapshot_local_apics().unwrap_or_else(|| {
            crate::io::acpi::local_apics()
                .iter()
                .map(|entry| LocalApicInfo {
                    processor_id: entry.processor_id,
                    apic_id: entry.apic_id,
                    enabled: entry.enabled,
                    online_capable: entry.online_capable,
                })
                .collect()
        })
    }

    fn io_apics(&self) -> Vec<IoApicInfo> {
        snapshot_io_apics().unwrap_or_else(|| {
            crate::io::acpi::io_apics()
                .iter()
                .map(|entry| IoApicInfo {
                    id: entry.id,
                    address: entry.address,
                    gsi_base: entry.gsi_base,
                })
                .collect()
        })
    }

    fn interrupt_overrides(&self) -> Vec<InterruptOverrideInfo> {
        snapshot_interrupt_overrides().unwrap_or_else(|| {
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
        })
    }

    fn pcie_ecam_regions(&self) -> Vec<PcieEcamInfo> {
        snapshot_pcie_ecam_regions().unwrap_or_else(|| {
            crate::io::acpi::pcie_ecam_regions()
                .iter()
                .map(|entry| PcieEcamInfo {
                    base_address: entry.base_address,
                    segment: entry.segment,
                    start_bus: entry.start_bus,
                    end_bus: entry.end_bus,
                })
                .collect()
        })
    }

    fn local_apic_address(&self) -> Option<u64> {
        snapshot_local_apic_address().or_else(crate::io::acpi::local_apic_address)
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

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use super::*;

    fn sample_snapshot() -> AcpiBootSnapshot {
        let mut snapshot = AcpiBootSnapshot {
            flags: boot_proto::acpi_snapshot_flags::VALID,
            revision: 2,
            _reserved: [0; 3],
            local_apic_address: 0xfee0_0000,
            dmar_addr: 0,
            ivrs_addr: 0,
            local_apic_count: 1,
            io_apic_count: 1,
            interrupt_override_count: 1,
            pcie_ecam_count: 1,
            ..AcpiBootSnapshot::default()
        };
        snapshot.local_apics[0] = boot_proto::BootLocalApicRecord {
            processor_id: 0,
            apic_id: 7,
            flags: boot_proto::acpi_local_apic_flags::ENABLED,
            _reserved: 0,
        };
        snapshot.io_apics[0] = boot_proto::BootIoApicRecord {
            address: 0xfec0_0000,
            gsi_base: 0,
            id: 2,
            _reserved: [0; 3],
        };
        snapshot.interrupt_overrides[0] = boot_proto::BootInterruptOverrideRecord {
            gsi: 9,
            bus: 0,
            source: 9,
            polarity: 3,
            trigger_mode: 3,
        };
        snapshot.pcie_ecam[0] = boot_proto::BootPcieEcamRecord {
            base_address: 0xe000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 255,
        };
        snapshot
    }

    #[test_case]
    fn builtin_provider_prefers_valid_boot_snapshot() {
        clear_boot_snapshot_for_tests();
        let snapshot = Box::leak(Box::new(sample_snapshot()));
        install_boot_snapshot(snapshot);

        let local_apics = BUILTIN_ACPI_PROVIDER.local_apics();
        assert_eq!(local_apics.len(), 1);
        assert_eq!(local_apics[0].apic_id, 7);
        assert_eq!(
            BUILTIN_ACPI_PROVIDER.local_apic_address(),
            Some(0xfee0_0000)
        );
    }

    #[test_case]
    fn invalid_snapshot_falls_back_to_parser_path() {
        clear_boot_snapshot_for_tests();
        let snapshot = Box::leak(Box::new(AcpiBootSnapshot::default()));
        install_boot_snapshot(snapshot);

        assert!(BUILTIN_ACPI_PROVIDER.local_apics().is_empty());
        assert_eq!(BUILTIN_ACPI_PROVIDER.local_apic_address(), None);
    }
}
