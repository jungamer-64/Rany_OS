//! The composition root retains AHCI acquisition, discovery and rundown across
//! waits. No await owns a controller outside this table: cancelling integration
//! returns the complete table to the composition slot.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::num::NonZeroUsize;
use kernel_api::KapiError;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{DmaAllocationRequest, DmaDirection};
use kernel_api::mmio::{MmioAcquireError, MmioRequestError, PciMmioRequest};
use kernel_api::service::platform::PciDeviceInfo;

use crate::drivers::ahci::{
    AhciAcquisition, AhciAcquisitionPoll, AhciController, AhciPoller, AhciPortOps, AhciRuntime,
    AhciRuntimeShutdown, ControllerOpenError, PORT_DMA_BYTES, PortAdmission, PortNumber,
    RuntimeShutdownCause, RuntimeShutdownStartError,
};
use crate::integration::{IntegrationError, SystemIntegration};
use crate::io::io_scheduler::{BlockGeometry, DeviceId, IoError, hybrid_coordinator, io_scheduler};

const PORT_COUNT: usize = 32;
const HANDOFF_DEADLINE_NS: u64 = 2_025_000_000;
const IDENTIFY_DEADLINE_NS: u64 = 30_000_000_000;
const ENGINE_POLL_BUDGET: NonZeroUsize = NonZeroUsize::new(100_000).unwrap();

pub(in crate::integration) struct AhciControllerOwner {
    device: PackedPciLocation,
    state: ControllerState,
    discovery_failures: [Option<DiscoveryFailure>; PORT_COUNT],
}

enum ControllerState {
    Acquiring {
        owner: AhciAcquisition,
        started: u64,
    },
    Discovering {
        runtime: Arc<AhciRuntime>,
        ports: [DiscoveryPort; PORT_COUNT],
    },
    Published {
        runtime: Arc<AhciRuntime>,
        devices: [Option<DeviceId>; PORT_COUNT],
    },
    Draining {
        runtime: Arc<AhciRuntime>,
        poller: Option<DeviceId>,
        cause: Option<ShutdownBlocker>,
    },
    Closing {
        shutdown: AhciRuntimeShutdown,
        cause: Option<RuntimeShutdownCause>,
    },
    Closed,
    Failed(StartupFailure),
}

enum DiscoveryPort {
    Unimplemented,
    Pending,
    Identifying { started: u64 },
    Ready(BlockGeometry),
    Rejected(DiscoveryFailure),
}

#[derive(Debug)]
enum DiscoveryFailure {
    Allocation(KapiError),
    Admission(PortAdmission),
    Identify(IoError),
    IdentifyDeadline,
    IdentifyLateCompletion(Result<(), IoError>),
}

#[derive(Debug)]
enum ShutdownBlocker {
    RequestsActive(u32),
    Shared,
    Preparation,
    Poisoned,
}

#[derive(Debug)]
enum StartupFailure {
    Request(MmioRequestError),
    Mapping(MmioAcquireError),
    PciMemory(KapiError),
    PciBusMaster {
        cause: KapiError,
        memory_rollback: Result<(), KapiError>,
    },
    PciUnavailable,
    Acquisition(ControllerOpenError),
    HandoffDeadline(AhciAcquisition),
    DmaWidth {
        cause: crate::io::iommu::types::IommuError,
        controller: AhciController,
    },
    Metadata(AhciController),
}

impl SystemIntegration {
    pub(super) async fn init_ahci_devices(&mut self) -> Result<(), IntegrationError> {
        let devices: Vec<_> = crate::platform::pci::scan_all_devices()
            .into_iter()
            .filter(|device| {
                device.class_code.class == 1
                    && device.class_code.subclass == 6
                    && device.class_code.prog_if == 1
            })
            .collect();
        self.ahci_controllers
            .try_reserve_exact(devices.len())
            .map_err(|_| {
                IntegrationError::DeviceError(String::from(
                    "AHCI controller owner table allocation failed",
                ))
            })?;
        // LOOP_PROOF: mode=bounded; reason=The immutable PCI scan enumerates each AHCI function once; existing owners are retained across retries.;
        for device in devices {
            let locator = device.packed_locator();
            if crate::loader::staged_pci::is_device_claimed(locator)
                || self
                    .ahci_controllers
                    .iter()
                    .any(|owner| owner.device == locator)
            {
                continue;
            }
            self.ahci_controllers
                .push(AhciControllerOwner::begin(&device));
        }
        // LOOP_PROOF: mode=bounded; reason=Every admitted controller owner is advanced once in this finite table; waits occur in the per-owner event loop.;
        for index in 0..self.ahci_controllers.len() {
            // LOOP_PROOF: mode=event; reason=Each unfinished hardware acquisition or IDENTIFY is sampled once and yields, with deadlines retaining the owner and ending discovery.;
            loop {
                let owner = self.ahci_controllers.remove(index);
                let (owner, done) = owner.advance();
                self.ahci_controllers.insert(index, owner);
                if done {
                    break;
                }
                crate::task::yield_now().await;
            }
            let message = self.ahci_controllers[index].summary();
            self.log(&message);
        }
        Ok(())
    }

    pub(super) fn progress_ahci_maintenance(&mut self) {
        // LOOP_PROOF: mode=bounded; reason=The composition table retains each controller and visits it once per maintenance tick.;
        for index in 0..self.ahci_controllers.len() {
            let owner = self.ahci_controllers.remove(index);
            let owner = owner.progress_late_identify();
            let owner = if io_scheduler().is_shutdown() {
                owner.retire()
            } else {
                owner
            };
            self.ahci_controllers.insert(index, owner);
        }
    }
}

impl AhciControllerOwner {
    fn begin(device: &PciDeviceInfo) -> Self {
        let state = match begin_acquisition(device) {
            Ok(owner) => ControllerState::Acquiring {
                owner,
                started: now(),
            },
            Err(cause) => ControllerState::Failed(cause),
        };
        Self {
            device: device.packed_locator(),
            state,
            discovery_failures: core::array::from_fn(|_| None),
        }
    }

    fn advance(self) -> (Self, bool) {
        let Self {
            device,
            state,
            mut discovery_failures,
        } = self;
        let (state, done) = match state {
            ControllerState::Acquiring { owner, started } => match owner.poll() {
                Ok(AhciAcquisitionPoll::Waiting(owner)) => {
                    if expired(started, HANDOFF_DEADLINE_NS) {
                        (
                            ControllerState::Failed(StartupFailure::HandoffDeadline(owner)),
                            true,
                        )
                    } else {
                        (ControllerState::Acquiring { owner, started }, false)
                    }
                }
                Ok(AhciAcquisitionPoll::Ready(controller)) => {
                    let width = match controller.address_width() {
                        crate::drivers::ahci::DmaAddressWidth::Bits32 => 32,
                        crate::drivers::ahci::DmaAddressWidth::Bits64 => 64,
                    };
                    let iommu_device = crate::io::iommu::types::DeviceId::new(
                        device.segment(),
                        device.bus(),
                        device.device(),
                        device.function(),
                    );
                    if let Err(cause) =
                        crate::io::iommu::api::register_device_dma_width(iommu_device, width)
                    {
                        (
                            ControllerState::Failed(StartupFailure::DmaWidth { cause, controller }),
                            true,
                        )
                    } else {
                        let implemented = controller.ports_implemented();
                        match AhciRuntime::new(controller) {
                            Ok(runtime) => (
                                ControllerState::Discovering {
                                    runtime: Arc::new(runtime),
                                    ports: core::array::from_fn(|index| {
                                        if implemented & (1 << index) != 0 {
                                            DiscoveryPort::Pending
                                        } else {
                                            DiscoveryPort::Unimplemented
                                        }
                                    }),
                                },
                                false,
                            ),
                            Err(controller) => (
                                ControllerState::Failed(StartupFailure::Metadata(controller)),
                                true,
                            ),
                        }
                    }
                }
                Err(cause) => (
                    ControllerState::Failed(StartupFailure::Acquisition(cause)),
                    true,
                ),
            },
            ControllerState::Discovering { runtime, mut ports } => {
                if let Some(index) = ports.iter().position(|port| {
                    matches!(
                        port,
                        DiscoveryPort::Pending | DiscoveryPort::Identifying { .. }
                    )
                }) {
                    let port = PortNumber::new(index as u8);
                    ports[index] = match ports[index] {
                        DiscoveryPort::Pending => start_port(&runtime, device, port),
                        DiscoveryPort::Identifying { started } => match runtime.poll_identify(port)
                        {
                            Ok(Some(geometry)) => DiscoveryPort::Ready(geometry),
                            Ok(None) if expired(started, IDENTIFY_DEADLINE_NS) => {
                                DiscoveryPort::Rejected(DiscoveryFailure::IdentifyDeadline)
                            }
                            Ok(None) => DiscoveryPort::Identifying { started },
                            Err(cause) => {
                                DiscoveryPort::Rejected(DiscoveryFailure::Identify(cause))
                            }
                        },
                        _ => unreachable!("discovery selected a pending port"),
                    };
                    (ControllerState::Discovering { runtime, ports }, false)
                } else {
                    let scheduler = io_scheduler();
                    let executor = hybrid_coordinator().polling_executor();
                    let mut published = [None; PORT_COUNT];
                    // LOOP_PROOF: mode=bounded; reason=Each of the fixed 32 port discoveries publishes at most one device capability.;
                    for (index, port) in ports.into_iter().enumerate() {
                        match port {
                            DiscoveryPort::Ready(geometry) => {
                                let id = DeviceId::Ahci {
                                    controller: device,
                                    port: index as u8,
                                };
                                let ops = Arc::new(AhciPortOps::new(
                                    Arc::clone(&runtime),
                                    PortNumber::new(index as u8),
                                    geometry,
                                    device,
                                ));
                                scheduler.register_device(id, Default::default());
                                // One controller poller visits all ports, so it is registered
                                // once. The first device owns withdrawal of that registration.
                                if published.iter().all(Option::is_none) {
                                    executor.register_handler(
                                        id,
                                        Arc::new(AhciPoller::new(Arc::clone(&runtime))),
                                    );
                                }
                                scheduler.register_device_ops(id, ops);
                                published[index] = Some(id);
                            }
                            DiscoveryPort::Rejected(cause) => {
                                log::warn!(
                                    "AHCI {:?} port {} discovery retained: {:?}",
                                    device,
                                    index,
                                    cause
                                );
                                discovery_failures[index] = Some(cause);
                            }
                            _ => {}
                        }
                    }
                    (
                        ControllerState::Published {
                            runtime,
                            devices: published,
                        },
                        true,
                    )
                }
            }
            state => (state, true),
        };
        (
            Self {
                device,
                state,
                discovery_failures,
            },
            done,
        )
    }

    fn progress_late_identify(mut self) -> Self {
        let runtime = match &self.state {
            ControllerState::Published { runtime, .. }
            | ControllerState::Draining { runtime, .. } => runtime,
            _ => return self,
        };
        // LOOP_PROOF: mode=bounded; reason=Every deadline-retained IDENTIFY is sampled once in the fixed 32-port failure table.;
        for (index, cause) in self.discovery_failures.iter_mut().enumerate() {
            if !matches!(cause, Some(DiscoveryFailure::IdentifyDeadline)) {
                continue;
            }
            match runtime.poll_identify(PortNumber::new(index as u8)) {
                Ok(None) => {}
                Ok(Some(_)) => *cause = Some(DiscoveryFailure::IdentifyLateCompletion(Ok(()))),
                Err(error) => *cause = Some(DiscoveryFailure::IdentifyLateCompletion(Err(error))),
            }
        }
        self
    }

    fn retire(self) -> Self {
        let Self {
            device,
            state,
            discovery_failures,
        } = self;
        let state = match state {
            ControllerState::Published { runtime, devices } => {
                runtime.close_admission();
                let poller = devices.iter().flatten().copied().next();
                // LOOP_PROOF: mode=bounded; reason=Every published port registration appears once in this fixed table.;
                for id in devices.into_iter().flatten() {
                    io_scheduler().unregister_device(id);
                }
                ControllerState::Draining {
                    runtime,
                    poller,
                    cause: None,
                }
            }
            state => state,
        };
        let state = match state {
            ControllerState::Draining {
                runtime,
                mut poller,
                ..
            } => {
                let active_ports = runtime.active_ports();
                if active_ports != 0 {
                    ControllerState::Draining {
                        runtime,
                        poller,
                        cause: Some(ShutdownBlocker::RequestsActive(active_ports)),
                    }
                } else {
                    if let Some(id) = poller.take() {
                        hybrid_coordinator()
                            .polling_executor()
                            .unregister_handler(id);
                    }
                    match AhciRuntime::begin_shutdown(runtime) {
                        Ok(shutdown) => ControllerState::Closing {
                            shutdown,
                            cause: None,
                        },
                        Err(failure) => {
                            let (runtime, cause) = match failure {
                                RuntimeShutdownStartError::RequestsActive { ports, runtime } => {
                                    (runtime, ShutdownBlocker::RequestsActive(ports))
                                }
                                RuntimeShutdownStartError::StillShared(runtime) => {
                                    (runtime, ShutdownBlocker::Shared)
                                }
                                RuntimeShutdownStartError::PreparationFailed(runtime) => {
                                    (runtime, ShutdownBlocker::Preparation)
                                }
                                RuntimeShutdownStartError::Poisoned(runtime) => {
                                    (runtime, ShutdownBlocker::Poisoned)
                                }
                            };
                            ControllerState::Draining {
                                runtime,
                                poller,
                                cause: Some(cause),
                            }
                        }
                    }
                }
            }
            state => state,
        };
        let state = match state {
            ControllerState::Closing { shutdown, .. } => match shutdown.advance(ENGINE_POLL_BUDGET)
            {
                Ok(()) => ControllerState::Closed,
                Err(failure) => ControllerState::Closing {
                    shutdown: failure.shutdown,
                    cause: Some(failure.cause),
                },
            },
            state => state,
        };
        Self {
            device,
            state,
            discovery_failures,
        }
    }

    fn summary(&self) -> String {
        match &self.state {
            ControllerState::Published { devices, .. } => alloc::format!(
                "    AHCI {:?}: {} identified port(s) published",
                self.device,
                devices.iter().flatten().count()
            ),
            ControllerState::Failed(cause) => {
                alloc::format!("    AHCI {:?}: startup retained {:?}", self.device, cause)
            }
            ControllerState::Draining { cause, .. } => {
                alloc::format!("    AHCI {:?}: rundown blocked {:?}", self.device, cause)
            }
            ControllerState::Closing { cause, .. } => {
                alloc::format!("    AHCI {:?}: release incomplete {:?}", self.device, cause)
            }
            ControllerState::Closed => alloc::format!("    AHCI {:?}: closed", self.device),
            _ => alloc::format!("    AHCI {:?}: discovery in progress", self.device),
        }
    }
}

fn start_port(runtime: &AhciRuntime, device: PackedPciLocation, port: PortNumber) -> DiscoveryPort {
    let allocation = |bytes, direction| {
        kernel_api::service::kernel::instance().alloc_dma_for_device(
            DmaAllocationRequest::new(bytes, direction)
                .expect("fixed AHCI buffer byte count is positive"),
            device,
        )
    };
    let metadata = match allocation(PORT_DMA_BYTES, DmaDirection::Bidirectional) {
        Ok(memory) => memory,
        Err(cause) => return DiscoveryPort::Rejected(DiscoveryFailure::Allocation(cause)),
    };
    match runtime.attach_port(port, metadata, ENGINE_POLL_BUDGET) {
        PortAdmission::Attached => {}
        cause => return DiscoveryPort::Rejected(DiscoveryFailure::Admission(cause)),
    }
    let identify = match allocation(512, DmaDirection::FromDevice) {
        Ok(memory) => memory,
        Err(cause) => return DiscoveryPort::Rejected(DiscoveryFailure::Allocation(cause)),
    };
    match runtime.start_identify(port, identify) {
        Ok(()) => DiscoveryPort::Identifying { started: now() },
        Err(cause) => DiscoveryPort::Rejected(DiscoveryFailure::Identify(cause)),
    }
}

fn begin_acquisition(device: &PciDeviceInfo) -> Result<AhciAcquisition, StartupFailure> {
    let request =
        PciMmioRequest::whole_bar(device.packed_locator(), 5).map_err(StartupFailure::Request)?;
    let mapping =
        crate::resource_registry::mmio::acquire_native(crate::domain::DomainId::KERNEL, request)
            .map_err(StartupFailure::Mapping)?;
    let pci = kernel_api::service::platform::try_pci().ok_or(StartupFailure::PciUnavailable)?;
    pci.set_memory_space(device.bdf, true)
        .map_err(StartupFailure::PciMemory)?;
    if let Err(cause) = pci.set_bus_master(device.bdf, true) {
        return Err(StartupFailure::PciBusMaster {
            cause,
            memory_rollback: pci.set_memory_space(device.bdf, false),
        });
    }
    // SAFETY: the resource registry reserved this exact BAR5, excluded RAM and
    // conflicting claims, and verified permanent UC mappings. Staged drivers
    // were excluded before admission. UEFI boot-service retirement precedes
    // this task: firmware DMA to released boot-service RAM has ended; any
    // remaining firmware activity must use its reserved memory. Acquisition
    // observes BIOS/OS handoff before any new port address can be programmed.
    unsafe { AhciAcquisition::begin(mapping, device.packed_locator()) }
        .map_err(StartupFailure::Acquisition)
}

fn now() -> u64 {
    crate::time::best_effort_time_nanos()
}
fn expired(started: u64, limit: u64) -> bool {
    now().saturating_sub(started) >= limit
}
