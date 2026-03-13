// ============================================================================
// kernel/src/provider_registry.rs - Runtime provider registry
// ============================================================================

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use kernel_api::provider::{ProviderDescriptorV1, ProviderHandle, ProviderKind};
use kernel_api::service::audio::AudioServices;
use kernel_api::service::graphics::GraphicsServices;
use kernel_api::service::input::InputServices;
use kernel_api::service::netdev::NetDeviceServices;
use kernel_api::service::platform::{AcpiServices, ApicServices, PciServices};
use kernel_api::service::serial::SerialServices;
use kernel_api::service::storage::StorageServices;
use kernel_api::service::time::TimeService;

use crate::driver_registry::DriverHandle;
use crate::sync::PoisonLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderOwner {
    KernelBuiltin,
    Driver(DriverHandle),
}

enum ProviderRef {
    Acpi(&'static dyn AcpiServices),
    Pci(&'static dyn PciServices),
    Apic(&'static dyn ApicServices),
    Time(&'static dyn TimeService),
    Descriptor(ProviderDescriptorV1),
    Storage(&'static dyn StorageServices),
    Netdev(&'static dyn NetDeviceServices),
    Input(&'static dyn InputServices),
    Serial(&'static dyn SerialServices),
    Graphics(&'static dyn GraphicsServices),
    Audio(&'static dyn AudioServices),
}

struct ProviderEntry {
    handle: ProviderHandle,
    owner: ProviderOwner,
    kind: ProviderKind,
    provider: ProviderRef,
}

pub struct ProviderRegistry {
    entries: PoisonLock<Vec<ProviderEntry>>,
    next_handle: AtomicU64,
}

impl ProviderRegistry {
    pub const fn new() -> Self {
        Self {
            entries: PoisonLock::new(Vec::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    #[cfg(test)]
    fn reset_for_tests(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.clear();
        self.next_handle.store(1, Ordering::Relaxed);
    }

    fn allocate_handle(&self) -> ProviderHandle {
        ProviderHandle::new(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }

    fn register_driver_provider(
        &self,
        owner: DriverHandle,
        kind: ProviderKind,
        provider: ProviderRef,
    ) -> ProviderHandle {
        self.insert_or_replace(ProviderOwner::Driver(owner), kind, provider)
    }

    fn insert_or_replace(
        &self,
        owner: ProviderOwner,
        kind: ProviderKind,
        provider: ProviderRef,
    ) -> ProviderHandle {
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => panic!("provider registry lock poisoned"),
        };

        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.owner == owner && entry.kind == kind)
        {
            entry.provider = provider;
            return entry.handle;
        }

        let handle = self.allocate_handle();
        entries.push(ProviderEntry {
            handle,
            owner,
            kind,
            provider,
        });
        handle
    }

    pub fn register_builtin_acpi(&self, provider: &'static dyn AcpiServices) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::PlatformAcpi,
            ProviderRef::Acpi(provider),
        )
    }

    pub fn register_builtin_pci(&self, provider: &'static dyn PciServices) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::PlatformPci,
            ProviderRef::Pci(provider),
        )
    }

    pub fn register_builtin_apic(&self, provider: &'static dyn ApicServices) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::PlatformApic,
            ProviderRef::Apic(provider),
        )
    }

    pub fn register_builtin_time(&self, provider: &'static dyn TimeService) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::Time,
            ProviderRef::Time(provider),
        )
    }

    pub fn register_builtin_storage(
        &self,
        provider: &'static dyn StorageServices,
    ) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::Storage,
            ProviderRef::Storage(provider),
        )
    }

    pub fn register_builtin_netdev(
        &self,
        provider: &'static dyn NetDeviceServices,
    ) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::Netdev,
            ProviderRef::Netdev(provider),
        )
    }

    pub fn register_builtin_input(&self, provider: &'static dyn InputServices) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::Input,
            ProviderRef::Input(provider),
        )
    }

    pub fn register_builtin_serial(&self, provider: &'static dyn SerialServices) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::Serial,
            ProviderRef::Serial(provider),
        )
    }

    pub fn register_builtin_graphics(
        &self,
        provider: &'static dyn GraphicsServices,
    ) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::Graphics,
            ProviderRef::Graphics(provider),
        )
    }

    pub fn register_builtin_audio(&self, provider: &'static dyn AudioServices) -> ProviderHandle {
        self.insert_or_replace(
            ProviderOwner::KernelBuiltin,
            ProviderKind::Audio,
            ProviderRef::Audio(provider),
        )
    }

    pub fn register_driver_acpi(
        &self,
        owner: DriverHandle,
        provider: &'static dyn AcpiServices,
    ) -> ProviderHandle {
        self.register_driver_provider(
            owner,
            ProviderKind::PlatformAcpi,
            ProviderRef::Acpi(provider),
        )
    }

    pub fn register_driver_pci(
        &self,
        owner: DriverHandle,
        provider: &'static dyn PciServices,
    ) -> ProviderHandle {
        self.register_driver_provider(owner, ProviderKind::PlatformPci, ProviderRef::Pci(provider))
    }

    pub fn register_driver_apic(
        &self,
        owner: DriverHandle,
        provider: &'static dyn ApicServices,
    ) -> ProviderHandle {
        self.register_driver_provider(
            owner,
            ProviderKind::PlatformApic,
            ProviderRef::Apic(provider),
        )
    }

    pub fn register_driver_time(
        &self,
        owner: DriverHandle,
        provider: &'static dyn TimeService,
    ) -> ProviderHandle {
        self.register_driver_provider(owner, ProviderKind::Time, ProviderRef::Time(provider))
    }

    pub fn register_driver_storage(
        &self,
        owner: DriverHandle,
        provider: &'static dyn StorageServices,
    ) -> ProviderHandle {
        self.register_driver_provider(owner, ProviderKind::Storage, ProviderRef::Storage(provider))
    }

    pub fn register_driver_netdev(
        &self,
        owner: DriverHandle,
        provider: &'static dyn NetDeviceServices,
    ) -> ProviderHandle {
        self.register_driver_provider(owner, ProviderKind::Netdev, ProviderRef::Netdev(provider))
    }

    pub fn register_driver_input(
        &self,
        owner: DriverHandle,
        provider: &'static dyn InputServices,
    ) -> ProviderHandle {
        self.register_driver_provider(owner, ProviderKind::Input, ProviderRef::Input(provider))
    }

    pub fn register_driver_serial(
        &self,
        owner: DriverHandle,
        provider: &'static dyn SerialServices,
    ) -> ProviderHandle {
        self.register_driver_provider(owner, ProviderKind::Serial, ProviderRef::Serial(provider))
    }

    pub fn register_driver_graphics(
        &self,
        owner: DriverHandle,
        provider: &'static dyn GraphicsServices,
    ) -> ProviderHandle {
        self.register_driver_provider(
            owner,
            ProviderKind::Graphics,
            ProviderRef::Graphics(provider),
        )
    }

    pub fn register_driver_audio(
        &self,
        owner: DriverHandle,
        provider: &'static dyn AudioServices,
    ) -> ProviderHandle {
        self.register_driver_provider(owner, ProviderKind::Audio, ProviderRef::Audio(provider))
    }

    pub fn register_driver_descriptors(
        &self,
        owner: DriverHandle,
        descriptors: &[ProviderDescriptorV1],
    ) -> Vec<ProviderHandle> {
        let mut handles = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            if !descriptor.validate() {
                log::warn!(
                    target: "provider",
                    "ignoring invalid provider descriptor for driver {} kind {:?}",
                    owner.index(),
                    descriptor.kind
                );
                continue;
            }

            handles.push(self.register_driver_provider(
                owner,
                descriptor.kind,
                ProviderRef::Descriptor(*descriptor),
            ));
        }
        handles
    }

    pub fn unregister_driver(&self, handle: DriverHandle) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|entry| entry.owner != ProviderOwner::Driver(handle));
        }
    }

    pub fn contains(&self, handle: ProviderHandle) -> bool {
        self.entries
            .lock()
            .map(|entries| entries.iter().any(|entry| entry.handle == handle))
            .unwrap_or(false)
    }

    pub fn acpi(&self) -> Option<&'static dyn AcpiServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Acpi(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn pci(&self) -> Option<&'static dyn PciServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Pci(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn apic(&self) -> Option<&'static dyn ApicServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Apic(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn time(&self) -> Option<&'static dyn TimeService> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Time(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn storage(&self) -> Option<&'static dyn StorageServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Storage(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn netdev(&self) -> Option<&'static dyn NetDeviceServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Netdev(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn input(&self) -> Option<&'static dyn InputServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Input(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn serial(&self) -> Option<&'static dyn SerialServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Serial(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn graphics(&self) -> Option<&'static dyn GraphicsServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Graphics(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn audio(&self) -> Option<&'static dyn AudioServices> {
        self.entries.lock().ok().and_then(|entries| {
            entries.iter().rev().find_map(|entry| match entry.provider {
                ProviderRef::Audio(provider) => Some(provider),
                _ => None,
            })
        })
    }

    pub fn descriptors_for_driver(&self, owner: DriverHandle) -> Vec<ProviderDescriptorV1> {
        self.entries
            .lock()
            .ok()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| entry.owner == ProviderOwner::Driver(owner))
                    .filter_map(|entry| match entry.provider {
                        ProviderRef::Descriptor(descriptor) => Some(descriptor),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

static PROVIDER_REGISTRY: ProviderRegistry = ProviderRegistry::new();

pub fn provider_registry() -> &'static ProviderRegistry {
    &PROVIDER_REGISTRY
}

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    PROVIDER_REGISTRY.reset_for_tests();
}

pub fn acpi_service() -> Option<&'static dyn AcpiServices> {
    provider_registry().acpi()
}

pub fn pci_service() -> Option<&'static dyn PciServices> {
    provider_registry().pci()
}

pub fn apic_service() -> Option<&'static dyn ApicServices> {
    provider_registry().apic()
}

pub fn time_service() -> Option<&'static dyn TimeService> {
    provider_registry().time()
}

pub fn storage_service() -> Option<&'static dyn StorageServices> {
    provider_registry().storage()
}

pub fn netdev_service() -> Option<&'static dyn NetDeviceServices> {
    provider_registry().netdev()
}

pub fn input_service() -> Option<&'static dyn InputServices> {
    provider_registry().input()
}

pub fn serial_service() -> Option<&'static dyn SerialServices> {
    provider_registry().serial()
}

pub fn graphics_service() -> Option<&'static dyn GraphicsServices> {
    provider_registry().graphics()
}

pub fn audio_service() -> Option<&'static dyn AudioServices> {
    provider_registry().audio()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::task::Waker;
    use kernel_api::service::audio::{AudioDeviceInfo, AudioServices};
    use kernel_api::service::netdev::{
        MacAddress, NETDEV_FLAG_BOUND_PORT, NETDEV_FLAG_PRIMARY, NetDeviceInfo, NetDeviceServices,
        NetPortKind,
    };
    use kernel_api::service::platform::{
        BdfAddress, ClassCode, DeviceId, IoApicInfo, LocalApicInfo, PciDeviceInfo, VendorId,
    };
    use kernel_api::service::storage::{StorageDeviceInfo, StorageServices, StorageTransport};
    use kernel_api::service::time::{
        CpuTimeStats, TimeService, TimerHandle, TimerMode, TimerServiceStats,
    };

    struct FakeAcpi;
    struct FakePci;
    struct FakeApic;
    struct FakeTime;
    struct FakeStorage;
    struct FakeNetdev;
    struct FakeAudio;

    impl kernel_api::service::platform::AcpiServices for FakeAcpi {
        fn local_apics(&self) -> Vec<LocalApicInfo> {
            vec![LocalApicInfo {
                processor_id: 0,
                apic_id: 1,
                enabled: true,
                online_capable: true,
            }]
        }

        fn io_apics(&self) -> Vec<IoApicInfo> {
            vec![IoApicInfo {
                id: 0,
                address: 0xFEC0_0000,
                gsi_base: 0,
            }]
        }

        fn interrupt_overrides(&self) -> Vec<kernel_api::service::platform::InterruptOverrideInfo> {
            Vec::new()
        }

        fn pcie_ecam_regions(&self) -> Vec<kernel_api::service::platform::PcieEcamInfo> {
            Vec::new()
        }

        fn local_apic_address(&self) -> Option<u64> {
            Some(0xFEE0_0000)
        }
    }

    impl kernel_api::service::platform::PciServices for FakePci {
        fn scan_all_devices(&self) -> Vec<PciDeviceInfo> {
            vec![PciDeviceInfo {
                segment: 0,
                bdf: BdfAddress::new(0, 2, 0),
                vendor_id: VendorId(0x1AF4),
                device_id: DeviceId(0x1041),
                revision_id: 0,
                class_code: ClassCode::new(0xFF, 0, 0),
                header_type: 0,
                subsystem_vendor_id: 0,
                subsystem_id: 0,
                interrupt_line: 0,
                interrupt_pin: 0,
                bars: [None, None, None, None, None, None],
                capabilities: Vec::new(),
                msi_cap_offset: None,
                msix_cap_offset: None,
                pcie_cap_offset: None,
                iommu_domain_id: None,
            }]
        }

        fn find_by_class(&self, _class: u8, _subclass: u8) -> Vec<PciDeviceInfo> {
            self.scan_all_devices()
        }

        fn find_virtio_devices(&self) -> Vec<PciDeviceInfo> {
            self.scan_all_devices()
        }

        fn set_bus_master(&self, _bdf: BdfAddress, _enabled: bool) -> kernel_api::KapiResult<()> {
            Ok(())
        }

        fn set_memory_space(&self, _bdf: BdfAddress, _enabled: bool) -> kernel_api::KapiResult<()> {
            Ok(())
        }

        fn set_io_space(&self, _bdf: BdfAddress, _enabled: bool) -> kernel_api::KapiResult<()> {
            Ok(())
        }

        fn disable_intx(&self, _bdf: BdfAddress) -> kernel_api::KapiResult<()> {
            Ok(())
        }
    }

    impl kernel_api::service::platform::ApicServices for FakeApic {
        fn local_apic_id(&self) -> u32 {
            7
        }
    }

    impl TimeService for FakeTime {
        fn compute_wake_tick(&self, duration_ms: u64) -> u64 {
            duration_ms
        }
        fn register_timer(
            &self,
            _interval_ms: u64,
            _mode: TimerMode,
            _waker: Waker,
        ) -> TimerHandle {
            TimerHandle(1)
        }
        fn cancel_timer(&self, _handle: TimerHandle) -> bool {
            true
        }
        fn current_tick_ms(&self) -> u64 {
            0
        }
        fn uptime_ns(&self) -> u64 {
            0
        }
        fn unix_timestamp(&self) -> u64 {
            0
        }
        fn unix_timestamp_ms(&self) -> u64 {
            0
        }
        fn stats(&self) -> TimerServiceStats {
            TimerServiceStats::default()
        }
        fn task_cpu_stats(&self, _task_id: u64) -> Option<CpuTimeStats> {
            None
        }
        fn record_task_start(&self, _task_id: u64) {}
        fn record_task_stop(&self, _task_id: u64) {}
        fn on_timer_interrupt(&self) {}
        fn process_pending_wakers(&self) {}
        fn adjust_wall_clock(&self, _delta_ns: i64) {}
        fn register_sleep(&self, _wake_tick: u64, _waker: Waker) {}
        fn unregister_sleep(&self, _wake_tick: u64) {}
    }

    impl StorageServices for FakeStorage {
        fn devices(&self) -> Vec<StorageDeviceInfo> {
            vec![StorageDeviceInfo {
                device_id: 0x100,
                namespace_id: 1,
                block_size: 4096,
                max_transfer_blocks: 128,
                transport: StorageTransport::Nvme,
                flags: 1,
            }]
        }
    }

    impl NetDeviceServices for FakeNetdev {
        fn devices(&self) -> Vec<NetDeviceInfo> {
            vec![NetDeviceInfo {
                port_id: 7,
                if_id: Some(3),
                kind: NetPortKind::Virtio,
                driver_name: "fake-net",
                queue_pairs: 1,
                mtu: 1500,
                mac: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x07]),
                flags: NETDEV_FLAG_BOUND_PORT | NETDEV_FLAG_PRIMARY,
            }]
        }
    }

    impl AudioServices for FakeAudio {
        fn devices(&self) -> Vec<AudioDeviceInfo> {
            vec![AudioDeviceInfo {
                device_id: 9,
                output_channels: 2,
                input_channels: 1,
                sample_rate_hz: 48_000,
                flags: 1,
            }]
        }
    }

    static FAKE_ACPI: FakeAcpi = FakeAcpi;
    static FAKE_PCI: FakePci = FakePci;
    static FAKE_APIC: FakeApic = FakeApic;
    static FAKE_TIME: FakeTime = FakeTime;
    static FAKE_STORAGE: FakeStorage = FakeStorage;
    static FAKE_NETDEV: FakeNetdev = FakeNetdev;
    static FAKE_AUDIO: FakeAudio = FakeAudio;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn builtin_provider_registration_smoke() {
        let registry = ProviderRegistry::new();
        let acpi_handle = registry.register_builtin_acpi(&FAKE_ACPI);
        let pci_handle = registry.register_builtin_pci(&FAKE_PCI);
        let apic_handle = registry.register_builtin_apic(&FAKE_APIC);
        let time_handle = registry.register_builtin_time(&FAKE_TIME);

        assert!(registry.contains(acpi_handle));
        assert!(registry.contains(pci_handle));
        assert!(registry.contains(apic_handle));
        assert!(registry.contains(time_handle));
        assert_eq!(registry.apic().map(|svc| svc.local_apic_id()), Some(7));
        assert_eq!(registry.pci().unwrap().scan_all_devices().len(), 1);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn builtin_service_provider_registration_smoke() {
        let registry = ProviderRegistry::new();
        let storage_handle = registry.register_builtin_storage(&FAKE_STORAGE);
        let netdev_handle = registry.register_builtin_netdev(&FAKE_NETDEV);
        let audio_handle = registry.register_builtin_audio(&FAKE_AUDIO);

        assert!(registry.contains(storage_handle));
        assert!(registry.contains(netdev_handle));
        assert!(registry.contains(audio_handle));
        assert_eq!(registry.storage().unwrap().devices().len(), 1);
        assert_eq!(
            registry.netdev().unwrap().primary_device().unwrap().mtu,
            1500
        );
        assert_eq!(registry.audio().unwrap().devices()[0].device_id, 9);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn unregister_driver_only_removes_matching_owner() {
        let registry = ProviderRegistry::new();
        let handle = DriverHandle::from_index(42);
        let registered = registry.insert_or_replace(
            ProviderOwner::Driver(handle),
            ProviderKind::Time,
            ProviderRef::Time(&FAKE_TIME),
        );
        assert!(registry.contains(registered));

        registry.unregister_driver(handle);

        assert!(!registry.contains(registered));
    }
}
