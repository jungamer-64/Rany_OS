use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU16;

use crate::drivers::nvme::{
    AdminQueueInstallError, ControllerAcquire, ControllerAcquireError, ControllerDisableError,
    ControllerDisablePoll, ControllerDisabled, ControllerDisabling, ControllerEnableError,
    ControllerEnablePoll, ControllerEnabling, IdentifyNamespaceError, IdentifyNamespacePoll,
    IdentifyNamespaceRequest, IdentifySubmitError, IoQueueCreatePoll, IoQueueCreation,
    IoQueueProvisioner, NvmeAdminController, QueueBudgetError, QueueBudgetPoll, QueueBudgetRequest,
    QueueCreateError, QueueMemory,
};
use kernel_api::KapiError;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuDmaLease, DmaAllocationRequest, DmaCloseError, DmaDirection};
use kernel_api::service::platform::{self, Bar, PciDeviceInfo, PciServices};

use crate::integration::{IntegrationError, SystemIntegration};
use crate::io::nvme::{
    NvmeRuntime, NvmeRuntimeRundown, PreparedNvmeRuntime, PublishedNvmeRuntime, RuntimeCreateError,
    RuntimePublishError, RuntimeRundownPoll,
};

const INITIAL_CONTROLLER_GENERATION: u64 = 1;
const NAMESPACE_ONE: u32 = 1;
const QUEUE_DEPTH_LIMIT: u32 = 64;
const IDENTIFY_BYTES: usize = 4096;
const SUBMISSION_ENTRY_BYTES: usize = 64;
const COMPLETION_ENTRY_BYTES: usize = 16;
const CONTROLLER_TIMEOUT_UNIT_NS: u64 = 500_000_000;
const ADMIN_COMMAND_TIMEOUT_NS: u64 = 30_000_000_000;

/// Composition-root owner for one physical NVMe function generation.
pub(in crate::integration) struct NvmeControllerOwner {
    locator: PackedPciLocation,
    generation: u64,
    state: NvmeControllerState,
}

enum NvmeControllerState {
    Published {
        runtime: PublishedNvmeRuntime,
        identify_close_failure: Option<DmaCloseError>,
    },
    Rundown {
        runtime: NvmeRuntimeRundown,
        identify_close_failure: Option<DmaCloseError>,
    },
    RundownOwned {
        runtime: NvmeRuntime,
        identify_close_failure: Option<DmaCloseError>,
    },
    Failed(NvmeStartupFailure),
}

impl NvmeControllerOwner {
    fn published(
        locator: PackedPciLocation,
        runtime: PublishedNvmeRuntime,
        identify_close_failure: Option<DmaCloseError>,
    ) -> Self {
        Self {
            locator,
            generation: INITIAL_CONTROLLER_GENERATION,
            state: NvmeControllerState::Published {
                runtime,
                identify_close_failure,
            },
        }
    }

    fn failed(locator: PackedPciLocation, failure: NvmeStartupFailure) -> Self {
        Self {
            locator,
            generation: INITIAL_CONTROLLER_GENERATION,
            state: NvmeControllerState::Failed(failure),
        }
    }

    fn running_device(&self) -> Option<crate::io::io_scheduler::DeviceId> {
        match &self.state {
            NvmeControllerState::Published { runtime, .. } => Some(runtime.device()),
            NvmeControllerState::Rundown { .. } | NvmeControllerState::RundownOwned { .. } => None,
            NvmeControllerState::Failed(_) => None,
        }
    }

    fn identify_close_failed(&self) -> bool {
        match &self.state {
            NvmeControllerState::Published {
                identify_close_failure,
                ..
            }
            | NvmeControllerState::Rundown {
                identify_close_failure,
                ..
            }
            | NvmeControllerState::RundownOwned {
                identify_close_failure,
                ..
            } => identify_close_failure.is_some(),
            NvmeControllerState::Failed(_) => false,
        }
    }

    fn retained_failure(&self) -> Option<&NvmeStartupFailure> {
        match &self.state {
            NvmeControllerState::Published { .. }
            | NvmeControllerState::Rundown { .. }
            | NvmeControllerState::RundownOwned { .. } => None,
            NvmeControllerState::Failed(failure) => Some(failure),
        }
    }

    fn begin_rundown(self) -> Self {
        let Self {
            locator,
            generation,
            state,
        } = self;
        let state = match state {
            NvmeControllerState::Published {
                runtime,
                identify_close_failure,
            } => NvmeControllerState::Rundown {
                runtime: runtime.begin_rundown(),
                identify_close_failure,
            },
            state => state,
        };
        Self {
            locator,
            generation,
            state,
        }
    }

    fn poll_rundown(self) -> Self {
        let Self {
            locator,
            generation,
            state,
        } = self;
        let state = match state {
            NvmeControllerState::Rundown {
                runtime,
                identify_close_failure,
            } => match runtime.poll() {
                RuntimeRundownPoll::Waiting(runtime) => NvmeControllerState::Rundown {
                    runtime,
                    identify_close_failure,
                },
                RuntimeRundownPoll::Owned(runtime) => NvmeControllerState::RundownOwned {
                    runtime,
                    identify_close_failure,
                },
            },
            state => state,
        };
        Self {
            locator,
            generation,
            state,
        }
    }
}

impl core::fmt::Debug for NvmeControllerOwner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NvmeControllerOwner")
            .field("locator", &self.locator)
            .field("generation", &self.generation)
            .field("running_device", &self.running_device())
            .field("failure", &self.retained_failure())
            .finish()
    }
}

#[derive(Clone, Copy)]
enum DmaAllocationCause {
    InvalidByteCount {
        bytes: usize,
        direction: DmaDirection,
    },
    Service(KapiError),
}

enum QueueMemoryAllocationError {
    Geometry {
        depth: u16,
        entry_bytes: usize,
        direction: DmaDirection,
    },
    Submission(DmaAllocationCause),
    Completion {
        cause: DmaAllocationCause,
        submission: CpuDmaLease,
    },
}

impl core::fmt::Debug for QueueMemoryAllocationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Geometry {
                depth,
                entry_bytes,
                direction,
            } => formatter
                .debug_struct("Geometry")
                .field("depth", depth)
                .field("entry_bytes", entry_bytes)
                .field("direction", direction)
                .finish(),
            Self::Submission(cause) => formatter.debug_tuple("Submission").field(cause).finish(),
            Self::Completion { cause, submission } => formatter
                .debug_struct("Completion")
                .field("cause", cause)
                .field("retained_submission_direction", &submission.direction())
                .finish(),
        }
    }
}

impl core::fmt::Debug for DmaAllocationCause {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidByteCount { bytes, direction } => formatter
                .debug_struct("InvalidByteCount")
                .field("bytes", bytes)
                .field("direction", direction)
                .finish(),
            Self::Service(cause) => formatter.debug_tuple("Service").field(cause).finish(),
        }
    }
}

enum PciEnableFailure {
    ServicesUnavailable,
    Memory(KapiError),
    BusMaster {
        cause: KapiError,
        memory_rollback: Result<(), KapiError>,
    },
}

struct PciDisableOutcome {
    bus_master: Result<(), KapiError>,
    memory_space: Result<(), KapiError>,
}

impl core::fmt::Debug for PciEnableFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ServicesUnavailable => formatter.write_str("ServicesUnavailable"),
            Self::Memory(cause) => formatter.debug_tuple("Memory").field(cause).finish(),
            Self::BusMaster {
                cause,
                memory_rollback,
            } => formatter
                .debug_struct("BusMaster")
                .field("cause", cause)
                .field("memory_rollback", memory_rollback)
                .finish(),
        }
    }
}

impl core::fmt::Debug for PciDisableOutcome {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PciDisableOutcome")
            .field("bus_master", &self.bus_master)
            .field("memory_space", &self.memory_space)
            .finish()
    }
}

enum NvmeStartupFailure {
    ControllerIdExhausted,
    MissingBar,
    NonMemoryBar(Bar),
    InvalidBarLength(u64),
    DmaWidth(crate::io::iommu::types::IommuError),
    PciEnable(PciEnableFailure),
    Mapping {
        cause: crate::mm::virt::higher_half::MapError,
        rollback: PciDisableOutcome,
    },
    Acquire(ControllerAcquireError),
    Disable(ControllerDisableError),
    DisableTimeout(ControllerDisabling),
    InvalidQueueGeometry(ControllerDisabled),
    AdminMemory {
        cause: QueueMemoryAllocationError,
        controller: ControllerDisabled,
    },
    AdminInstall(AdminQueueInstallError),
    Enable(ControllerEnableError),
    EnableTimeout(ControllerEnabling),
    IdentifyMemory {
        cause: DmaAllocationCause,
        controller: NvmeAdminController,
    },
    IdentifySubmit(IdentifySubmitError),
    Identify(IdentifyNamespaceError),
    IdentifyTimeout(IdentifyNamespaceRequest),
    QueueBudget(QueueBudgetError),
    QueueBudgetTimeout(QueueBudgetRequest),
    IoQueueMemory {
        cause: QueueMemoryAllocationError,
        provisioner: Box<IoQueueProvisioner>,
    },
    IoQueueCreate(QueueCreateError),
    IoQueueTimeout(IoQueueCreation),
    NoIoQueue(Box<IoQueueProvisioner>),
    Runtime(RuntimeCreateError),
    Publication(RuntimePublishError),
}

impl core::fmt::Debug for NvmeStartupFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ControllerIdExhausted => formatter.write_str("ControllerIdExhausted"),
            Self::MissingBar => formatter.write_str("MissingBar"),
            Self::NonMemoryBar(bar) => formatter.debug_tuple("NonMemoryBar").field(bar).finish(),
            Self::InvalidBarLength(length) => formatter
                .debug_tuple("InvalidBarLength")
                .field(length)
                .finish(),
            Self::DmaWidth(cause) => formatter.debug_tuple("DmaWidth").field(cause).finish(),
            Self::PciEnable(cause) => formatter.debug_tuple("PciEnable").field(cause).finish(),
            Self::Mapping { cause, rollback } => formatter
                .debug_struct("Mapping")
                .field("cause", cause)
                .field("rollback", rollback)
                .finish(),
            Self::Acquire(cause) => formatter.debug_tuple("Acquire").field(cause).finish(),
            Self::Disable(cause) => formatter.debug_tuple("Disable").field(cause).finish(),
            Self::DisableTimeout(controller) => formatter
                .debug_struct("DisableTimeout")
                .field("capabilities", &controller.capabilities())
                .finish(),
            Self::InvalidQueueGeometry(controller) => formatter
                .debug_struct("InvalidQueueGeometry")
                .field("capabilities", &controller.capabilities())
                .finish(),
            Self::AdminMemory { cause, controller } => formatter
                .debug_struct("AdminMemory")
                .field("cause", cause)
                .field("capabilities", &controller.capabilities())
                .finish(),
            Self::AdminInstall(cause) => {
                formatter.debug_tuple("AdminInstall").field(cause).finish()
            }
            Self::Enable(cause) => formatter.debug_tuple("Enable").field(cause).finish(),
            Self::EnableTimeout(controller) => formatter
                .debug_struct("EnableTimeout")
                .field("retained_owner_bytes", &core::mem::size_of_val(controller))
                .finish(),
            Self::IdentifyMemory { cause, controller } => formatter
                .debug_struct("IdentifyMemory")
                .field("cause", cause)
                .field("retained_owner_bytes", &core::mem::size_of_val(controller))
                .finish(),
            Self::IdentifySubmit(cause) => formatter
                .debug_tuple("IdentifySubmit")
                .field(cause)
                .finish(),
            Self::Identify(cause) => formatter.debug_tuple("Identify").field(cause).finish(),
            Self::IdentifyTimeout(request) => formatter
                .debug_struct("IdentifyTimeout")
                .field("retained_owner_bytes", &core::mem::size_of_val(request))
                .finish(),
            Self::QueueBudget(cause) => formatter.debug_tuple("QueueBudget").field(cause).finish(),
            Self::QueueBudgetTimeout(request) => formatter
                .debug_struct("QueueBudgetTimeout")
                .field("retained_owner_bytes", &core::mem::size_of_val(request))
                .finish(),
            Self::IoQueueMemory { cause, provisioner } => formatter
                .debug_struct("IoQueueMemory")
                .field("cause", cause)
                .field("queue_limit", &provisioner.queue_limit())
                .field("created_queues", &provisioner.queue_count())
                .finish(),
            Self::IoQueueCreate(cause) => {
                formatter.debug_tuple("IoQueueCreate").field(cause).finish()
            }
            Self::IoQueueTimeout(creation) => formatter
                .debug_struct("IoQueueTimeout")
                .field("stage", &creation.stage())
                .finish(),
            Self::NoIoQueue(provisioner) => formatter
                .debug_struct("NoIoQueue")
                .field("queue_limit", &provisioner.queue_limit())
                .field("created_queues", &provisioner.queue_count())
                .finish(),
            Self::Runtime(cause) => formatter.debug_tuple("Runtime").field(cause).finish(),
            Self::Publication(cause) => formatter.debug_tuple("Publication").field(cause).finish(),
        }
    }
}

impl SystemIntegration {
    pub(super) fn init_nvme_devices(&mut self) -> Result<(), IntegrationError> {
        let devices: Vec<_> = crate::platform::pci::scan_all_devices()
            .into_iter()
            .filter(|device| device.class_code.is_nvme())
            .collect();
        self.nvme_controllers
            .try_reserve_exact(devices.len())
            .map_err(|_| {
                IntegrationError::DeviceError(String::from(
                    "NVMe controller owner table allocation failed",
                ))
            })?;

        let mut builtin_index = 0usize;
        for device in devices {
            let locator = device.packed_locator();
            if crate::loader::staged_pci::is_device_claimed(locator) {
                self.log(&alloc::format!(
                    "    NVMe {} remains owned by its staged PCI driver",
                    device.bdf
                ));
                continue;
            }

            let controller_id = u8::try_from(builtin_index);
            builtin_index = builtin_index.saturating_add(1);
            let owner = match controller_id {
                Ok(controller_id) => match bootstrap_controller(&device, controller_id) {
                    Ok(success) => {
                        let runtime = success.runtime.publish();
                        NvmeControllerOwner::published(locator, runtime, success.close_failure)
                    }
                    Err(failure) => NvmeControllerOwner::failed(locator, failure),
                },
                Err(_) => {
                    NvmeControllerOwner::failed(locator, NvmeStartupFailure::ControllerIdExhausted)
                }
            };
            self.nvme_controllers.push(owner);
            let retained = self
                .nvme_controllers
                .last()
                .expect("capacity was reserved and one controller owner was appended");
            let running_device = retained.running_device();
            let identify_close_failed = retained.identify_close_failed();
            let failure_message = retained
                .retained_failure()
                .map(|failure| alloc::format!("{:?}", failure));
            if let Some(device_id) = running_device {
                self.log(&alloc::format!(
                    "    NVMe {} published as {:?}",
                    device.bdf,
                    device_id
                ));
                if identify_close_failed {
                    self.log("      Identify buffer close is retained for IOMMU reconciliation");
                }
            } else if let Some(failure) = failure_message {
                self.log(&alloc::format!(
                    "    NVMe {} startup retained failure: {}",
                    device.bdf,
                    failure
                ));
            }
        }
        Ok(())
    }
}

struct BootstrapSuccess {
    runtime: PreparedNvmeRuntime,
    close_failure: Option<DmaCloseError>,
}

fn bootstrap_controller(
    device: &PciDeviceInfo,
    controller_id: u8,
) -> Result<BootstrapSuccess, NvmeStartupFailure> {
    let bar = device.bars[0].ok_or(NvmeStartupFailure::MissingBar)?;
    if !bar.is_memory() {
        return Err(NvmeStartupFailure::NonMemoryBar(bar));
    }
    let bar_length = usize::try_from(bar.size())
        .ok()
        .filter(|length| *length != 0)
        .ok_or(NvmeStartupFailure::InvalidBarLength(bar.size()))?;
    super::super::register_pci_dma_width(device, 64).map_err(NvmeStartupFailure::DmaWidth)?;

    let pci = platform::try_pci().ok_or(NvmeStartupFailure::PciEnable(
        PciEnableFailure::ServicesUnavailable,
    ))?;
    enable_pci(pci, device).map_err(NvmeStartupFailure::PciEnable)?;

    let physical = x86_64::PhysAddr::new(bar.base());
    // SAFETY: PCI enumeration identifies BAR0 as this unbound NVMe function's
    // memory resource. SystemIntegration is the sole built-in owner, staged
    // binding was excluded before this call, and the direct map is permanent.
    let mapping =
        match unsafe { crate::mm::virt::mapping::retain_device_registers(physical, bar_length) } {
            Ok(mapping) => mapping,
            Err(cause) => {
                return Err(NvmeStartupFailure::Mapping {
                    cause,
                    rollback: disable_pci(pci, device),
                });
            }
        };

    let acquire = ControllerAcquire::begin(
        mapping,
        device.packed_locator(),
        INITIAL_CONTROLLER_GENERATION,
    )
    .map_err(NvmeStartupFailure::Acquire)?;
    let capabilities = acquire.capabilities();
    let ready_timeout =
        u64::from(capabilities.timeout_units()).saturating_mul(CONTROLLER_TIMEOUT_UNIT_NS);
    let queue_depth = u16::try_from(capabilities.max_queue_entries().min(QUEUE_DEPTH_LIMIT))
        .ok()
        .filter(|depth| *depth >= 2);

    let disabled = await_disabled(acquire, ready_timeout)?;
    let Some(queue_depth) = queue_depth else {
        return Err(NvmeStartupFailure::InvalidQueueGeometry(disabled));
    };
    let admin_memory = match allocate_queue_memory(device.packed_locator(), queue_depth) {
        Ok(memory) => memory,
        Err(cause) => {
            return Err(NvmeStartupFailure::AdminMemory {
                cause,
                controller: disabled,
            });
        }
    };
    let enabling = disabled
        .install_admin_queue(queue_depth, admin_memory)
        .map_err(NvmeStartupFailure::AdminInstall)?;
    let admin = await_enabled(enabling, ready_timeout)?;

    let identify_buffer = match allocate_dma(
        device.packed_locator(),
        IDENTIFY_BYTES,
        DmaDirection::FromDevice,
    ) {
        Ok(buffer) => buffer,
        Err(cause) => {
            return Err(NvmeStartupFailure::IdentifyMemory {
                cause,
                controller: admin,
            });
        }
    };
    let identify = admin
        .identify_namespace(NAMESPACE_ONE, identify_buffer)
        .map_err(NvmeStartupFailure::IdentifySubmit)?;
    let identified = await_identify(identify)?;
    let (admin, namespace, identify_buffer) = identified.into_parts();
    let close_failure = identify_buffer.close().err();

    let requested = requested_queue_count();
    let budget = admin
        .request_io_queues(requested)
        .map_err(NvmeStartupFailure::QueueBudget)?;
    let mut provisioner = await_queue_budget(budget)?;
    let queue_count = provisioner.queue_limit().get();
    for _ in 0..queue_count {
        let memory = match allocate_queue_memory(device.packed_locator(), queue_depth) {
            Ok(memory) => memory,
            Err(cause) => {
                return Err(NvmeStartupFailure::IoQueueMemory {
                    cause,
                    provisioner: Box::new(provisioner),
                });
            }
        };
        let creation = provisioner
            .begin_next_queue(queue_depth, memory)
            .map_err(NvmeStartupFailure::IoQueueCreate)?;
        provisioner = await_io_queue(creation)?;
    }
    let controller = provisioner
        .finish()
        .map_err(NvmeStartupFailure::NoIoQueue)?;
    let runtime = NvmeRuntime::new(controller, controller_id, namespace)
        .map_err(NvmeStartupFailure::Runtime)?;
    let runtime = PreparedNvmeRuntime::prepare(runtime).map_err(NvmeStartupFailure::Publication)?;
    Ok(BootstrapSuccess {
        runtime,
        close_failure,
    })
}

fn enable_pci(pci: &dyn PciServices, device: &PciDeviceInfo) -> Result<(), PciEnableFailure> {
    pci.set_memory_space(device.bdf, true)
        .map_err(PciEnableFailure::Memory)?;
    if let Err(cause) = pci.set_bus_master(device.bdf, true) {
        return Err(PciEnableFailure::BusMaster {
            cause,
            memory_rollback: pci.set_memory_space(device.bdf, false),
        });
    }
    Ok(())
}

fn disable_pci(pci: &dyn PciServices, device: &PciDeviceInfo) -> PciDisableOutcome {
    PciDisableOutcome {
        bus_master: pci.set_bus_master(device.bdf, false),
        memory_space: pci.set_memory_space(device.bdf, false),
    }
}

fn allocate_dma(
    device: PackedPciLocation,
    bytes: usize,
    direction: DmaDirection,
) -> Result<CpuDmaLease, DmaAllocationCause> {
    let request = DmaAllocationRequest::new(bytes, direction)
        .ok_or(DmaAllocationCause::InvalidByteCount { bytes, direction })?;
    kernel_api::service::kernel::instance()
        .alloc_dma_for_device(request, device)
        .map_err(DmaAllocationCause::Service)
}

fn allocate_queue_memory(
    device: PackedPciLocation,
    depth: u16,
) -> Result<QueueMemory, QueueMemoryAllocationError> {
    let submission_bytes = usize::from(depth)
        .checked_mul(SUBMISSION_ENTRY_BYTES)
        .ok_or(QueueMemoryAllocationError::Geometry {
            depth,
            entry_bytes: SUBMISSION_ENTRY_BYTES,
            direction: DmaDirection::ToDevice,
        })?;
    let completion_bytes = usize::from(depth)
        .checked_mul(COMPLETION_ENTRY_BYTES)
        .ok_or(QueueMemoryAllocationError::Geometry {
            depth,
            entry_bytes: COMPLETION_ENTRY_BYTES,
            direction: DmaDirection::FromDevice,
        })?;
    let submission = allocate_dma(device, submission_bytes, DmaDirection::ToDevice)
        .map_err(QueueMemoryAllocationError::Submission)?;
    let completion = match allocate_dma(device, completion_bytes, DmaDirection::FromDevice) {
        Ok(completion) => completion,
        Err(cause) => {
            return Err(QueueMemoryAllocationError::Completion { cause, submission });
        }
    };
    Ok(QueueMemory {
        submission,
        completion,
    })
}

fn await_disabled(
    acquire: ControllerAcquire,
    timeout_ns: u64,
) -> Result<ControllerDisabled, NvmeStartupFailure> {
    let mut controller = match acquire {
        ControllerAcquire::Disabled(controller) => return Ok(controller),
        ControllerAcquire::Disabling(controller) => controller,
    };
    let start = crate::time::best_effort_time_nanos();
    loop {
        match controller.poll().map_err(NvmeStartupFailure::Disable)? {
            ControllerDisablePoll::Disabled(disabled) => return Ok(disabled),
            ControllerDisablePoll::Waiting(waiting) => {
                controller = waiting;
                if timed_out(start, timeout_ns) {
                    return Err(NvmeStartupFailure::DisableTimeout(controller));
                }
                core::hint::spin_loop();
            }
        }
    }
}

fn await_enabled(
    mut controller: ControllerEnabling,
    timeout_ns: u64,
) -> Result<NvmeAdminController, NvmeStartupFailure> {
    let start = crate::time::best_effort_time_nanos();
    loop {
        match controller.poll().map_err(NvmeStartupFailure::Enable)? {
            ControllerEnablePoll::Ready(ready) => return Ok(ready),
            ControllerEnablePoll::Waiting(waiting) => {
                controller = waiting;
                if timed_out(start, timeout_ns) {
                    return Err(NvmeStartupFailure::EnableTimeout(controller));
                }
                core::hint::spin_loop();
            }
        }
    }
}

fn await_identify(
    mut request: IdentifyNamespaceRequest,
) -> Result<crate::drivers::nvme::IdentifiedNamespace, NvmeStartupFailure> {
    let start = crate::time::best_effort_time_nanos();
    loop {
        match request.poll().map_err(NvmeStartupFailure::Identify)? {
            IdentifyNamespacePoll::Ready(identified) => return Ok(identified),
            IdentifyNamespacePoll::Waiting(waiting) => {
                request = waiting;
                if timed_out(start, ADMIN_COMMAND_TIMEOUT_NS) {
                    return Err(NvmeStartupFailure::IdentifyTimeout(request));
                }
                core::hint::spin_loop();
            }
        }
    }
}

fn await_queue_budget(
    mut request: QueueBudgetRequest,
) -> Result<IoQueueProvisioner, NvmeStartupFailure> {
    let start = crate::time::best_effort_time_nanos();
    loop {
        match request.poll().map_err(NvmeStartupFailure::QueueBudget)? {
            QueueBudgetPoll::Ready(provisioner) => return Ok(provisioner),
            QueueBudgetPoll::Waiting(waiting) => {
                request = waiting;
                if timed_out(start, ADMIN_COMMAND_TIMEOUT_NS) {
                    return Err(NvmeStartupFailure::QueueBudgetTimeout(request));
                }
                core::hint::spin_loop();
            }
        }
    }
}

fn await_io_queue(mut creation: IoQueueCreation) -> Result<IoQueueProvisioner, NvmeStartupFailure> {
    let start = crate::time::best_effort_time_nanos();
    loop {
        match creation.poll().map_err(NvmeStartupFailure::IoQueueCreate)? {
            IoQueueCreatePoll::Ready(provisioner) => return Ok(provisioner),
            IoQueueCreatePoll::Waiting(waiting) => {
                creation = waiting;
                if timed_out(start, ADMIN_COMMAND_TIMEOUT_NS) {
                    return Err(NvmeStartupFailure::IoQueueTimeout(creation));
                }
                core::hint::spin_loop();
            }
        }
    }
}

fn requested_queue_count() -> NonZeroU16 {
    let online = crate::cpu::snapshot().online().len().max(1);
    let requested = u16::try_from(online).unwrap_or(u16::MAX);
    NonZeroU16::new(requested).unwrap_or(NonZeroU16::MIN)
}

fn timed_out(start: u64, timeout_ns: u64) -> bool {
    crate::time::best_effort_time_nanos().saturating_sub(start) >= timeout_ns
}
