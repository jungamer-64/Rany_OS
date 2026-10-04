use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use super::firmware_registers::{FirmwareRegisters, RegisterError, fixed_address};
use crate::power::{
    PowerCommand, PowerEvents, PowerFailure, PowerRequestError, PowerSnapshot, PowerState,
};
use crate::sync::{InitOnce, IrqMutex};
use acpi_driver::aml::{
    AmlBudget, AmlObject, AmlPath, AmlValue, VmEnvironment, VmProgress, VmWait,
};
use acpi_driver::power::PowerRegisterDescription;
use acpi_driver::{
    AcpiError, AcpiErrorKind, AcpiRuntime, AmlError, AmlErrorKind, CpuFirmwareEvent,
    CpuNamespaceBinding, FirmwareUid, FixedEventDescription, GenericAddress, GpeController,
    GpeEvent, GpeNumber, GpeQueue, InterruptPolarity, InterruptTriggerMode, NamespaceBinding,
    RegisterAccessSize,
};

use crate::cpu::{
    ApicId, CpuEjectCapability, CpuId, CpuSlotState, CpuTopologyIssue, CpuTransitionError,
    FirmwareCpuIdentity, FirmwareCpuUid, FirmwareError, FirmwareErrorKind, PhysicalHotplugStatus,
};
use crate::io::interrupt_manager::{InterruptError, Polarity, TriggerMode};
use crate::sync::AtomicWaker;

const GPE_QUEUE_CAPACITY: usize = 256;
const AML_METHOD_DEADLINE_MS: u64 = 5_000;
const NOTIFY_CASCADE_BUDGET: usize = 256;
const OST_EJECT_REQUEST: u64 = 0x03;

/// ACPI 6.6 Table 6.22/6.24 status for an ejection request.
#[derive(Clone, Copy)]
enum EjectOstStatus {
    Success,
    Failure,
    NotSupported,
    DeviceBusy,
}

impl EjectOstStatus {
    const fn value(self) -> u64 {
        match self {
            Self::Success => 0x00,
            Self::Failure => 0x01,
            Self::NotSupported => 0x80,
            Self::DeviceBusy => 0x82,
        }
    }
}

static FIRMWARE_SERVICE: InitOnce<Result<FirmwareService, FirmwareError>> = InitOnce::new();

enum WorkerState {
    Starting,
    Running(crate::task::TaskId),
    Failed {
        task: Option<crate::task::TaskId>,
        error: FirmwareError,
    },
}
enum PowerOperation {
    Idle,
    Requested(PowerCommand),
    Running(PowerCommand),
    Committing(PowerCommand),
    Published(PowerCommand),
    Failed {
        command: PowerCommand,
        failure: PowerFailure,
    },
    Fenced {
        command: PowerCommand,
        failure: PowerFailure,
    },
}
/// Owns the SCI route, register ranges, firmware worker and its failure.
/// Static CPU topology remains available when AML hotplug cannot run. Power
/// commands use this same interpreter environment even without GPE methods.
pub fn initialize() {
    let initial = FIRMWARE_SERVICE.call_once(build_service);
    let service = match initial {
        Ok(service) => service,
        Err(error) => {
            publish_unavailable(error.clone());
            log::warn!("ACPI firmware service unavailable: {error:?}");
            return;
        }
    };
    if let Ok(power) = &service.power {
        match service.registers.timer(power) {
            Ok(Some(timer)) => crate::time::system_clock().install_firmware_timer(timer),
            Ok(None) => {}
            Err(error) => log::warn!("ACPI PM clock admission failed: {error:?}"),
        }
    }
    let mut worker = service.worker.lock();
    if !matches!(*worker, WorkerState::Starting) {
        return;
    }
    if let Some(vector) = service.route_vector {
        let handler = match Box::try_new(capture_sci_interrupt as fn()) {
            Ok(handler) => handler,
            Err(_) => {
                let error = firmware_error(
                    FirmwareErrorKind::Resource,
                    None,
                    "SCI handler metadata allocation failed",
                );
                *worker = WorkerState::Failed {
                    task: None,
                    error: error.clone(),
                };
                publish_unavailable(error);
                return;
            }
        };
        if let Err(error) = crate::io::interrupt_manager::register_handler(vector, handler) {
            let error = map_interrupt_error(error);
            *worker = WorkerState::Failed {
                task: None,
                error: error.clone(),
            };
            publish_unavailable(error);
            return;
        }
    }
    match crate::task::spawn_in_domain(
        firmware_worker(),
        crate::task::TaskOptions::pinned(CpuId::BOOTSTRAP),
        crate::domain::DomainId::KERNEL,
    ) {
        Ok(task) => *worker = WorkerState::Running(task),
        Err(cause) => {
            let error = firmware_error(
                FirmwareErrorKind::Resource,
                None,
                alloc::format!("ACPI firmware worker admission failed: {cause:?}"),
            );
            *worker = WorkerState::Failed {
                task: None,
                error: error.clone(),
            };
            publish_unavailable(error);
        }
    }
}

fn build_service() -> Result<FirmwareService, FirmwareError> {
    let runtime = crate::platform::firmware::runtime().ok_or_else(|| {
        firmware_error(
            FirmwareErrorKind::Namespace,
            None,
            "ACPI runtime is unavailable",
        )
    })?;
    let fixed = runtime.catalog().fixed_events().map_err(map_acpi_error)?;
    let power = runtime.catalog().power_registers().map_err(map_acpi_error);
    let registers = FirmwareRegisters::acquire(runtime, &fixed, power.as_ref().ok())
        .map_err(map_register_error)?;
    let controller = FixedGpeController::new(&registers, &fixed)?;
    controller.mask_all(&registers);
    let events = if runtime.namespace().is_some() {
        GpeEventMap::build(runtime, &fixed)?
    } else {
        GpeEventMap {
            events: [None; 256],
            count: 0,
        }
    };
    let needs_sci = !events.is_empty()
        || power.as_ref().is_ok_and(|description| {
            description.pm1a_event.is_some() || description.pm1b_event.is_some()
        });
    let route_vector = if needs_sci {
        let route = SciRoute::resolve(runtime, &fixed)?;
        let allocation = crate::io::interrupt_manager::allocate_gsi(
            route.gsi,
            "ACPI SCI",
            route.trigger,
            route.polarity,
        )
        .map_err(map_interrupt_error)?;
        let vector = allocation.vector();
        if let Err(error) =
            crate::io::interrupt_manager::configure_ioapic_interrupt(route.gsi, &allocation.config)
        {
            crate::io::interrupt_manager::free_vector(vector);
            return Err(map_interrupt_error(error));
        }
        Some(vector)
    } else {
        None
    };
    Ok(FirmwareService {
        runtime,
        registers,
        controller,
        events,
        power,
        route_vector,
        queue: GpeQueue::new(),
        worker_waker: AtomicWaker::new(),
        delivery_failed: AtomicBool::new(false),
        register_failure: IrqMutex::new(None),
        worker: IrqMutex::new(WorkerState::Starting),
        operation: IrqMutex::new(PowerOperation::Idle),
        power_events: PowerEvents::new(),
    })
}

struct FirmwareService {
    runtime: &'static AcpiRuntime,
    registers: FirmwareRegisters,
    controller: FixedGpeController,
    events: GpeEventMap,
    power: Result<PowerRegisterDescription, FirmwareError>,
    queue: GpeQueue<GPE_QUEUE_CAPACITY>,
    worker_waker: AtomicWaker,
    delivery_failed: AtomicBool,
    register_failure: IrqMutex<Option<RegisterError>>,
    route_vector: Option<u8>,
    worker: IrqMutex<WorkerState>,
    operation: IrqMutex<PowerOperation>,
    power_events: PowerEvents,
}

fn service() -> Option<&'static FirmwareService> {
    FIRMWARE_SERVICE.get().and_then(|value| value.as_ref().ok())
}

pub(crate) fn request_power(command: PowerCommand) -> Result<(), PowerRequestError> {
    let service = service().ok_or(PowerRequestError::Unavailable)?;
    if !matches!(*service.worker.lock(), WorkerState::Running(_)) {
        return Err(PowerRequestError::Unavailable);
    }
    let description = service
        .power
        .as_ref()
        .map_err(|_| PowerRequestError::Unavailable)?;
    if (command == PowerCommand::Reset && description.reset.is_none())
        || (command == PowerCommand::Shutdown
            && description.pm1a_control.is_none()
            && description.sleep_control.is_none())
    {
        return Err(PowerRequestError::Unsupported);
    }
    let mut operation = service.operation.lock();
    if !matches!(*operation, PowerOperation::Idle) {
        return Err(PowerRequestError::Busy);
    }
    *operation = PowerOperation::Requested(command);
    drop(operation);
    service.worker_waker.wake();
    Ok(())
}

pub(crate) fn power_snapshot() -> PowerSnapshot {
    let mut snapshot = PowerSnapshot {
        state: PowerState::Unavailable,
        power_button_presses: 0,
        sleep_button_presses: 0,
        idle_entries: 0,
        failure: None,
        worker_task: None,
        worker_failure: None,
    };
    let Some(service) = service() else {
        if let Some(Err(error)) = FIRMWARE_SERVICE.get() {
            snapshot.worker_failure = Some(error.clone());
        }
        return snapshot;
    };
    let worker = service.worker.lock();
    let running = match &*worker {
        WorkerState::Starting => false,
        WorkerState::Running(task) => {
            snapshot.worker_task = Some(*task);
            true
        }
        WorkerState::Failed { task, error } => {
            snapshot.worker_task = *task;
            snapshot.worker_failure = Some(error.clone());
            false
        }
    };
    drop(worker);
    snapshot.state = match &*service.operation.lock() {
        PowerOperation::Idle => {
            if running && service.power.is_ok() {
                PowerState::Working
            } else {
                PowerState::Unavailable
            }
        }
        PowerOperation::Requested(PowerCommand::Shutdown)
        | PowerOperation::Running(PowerCommand::Shutdown)
        | PowerOperation::Committing(PowerCommand::Shutdown)
        | PowerOperation::Published(PowerCommand::Shutdown) => PowerState::ShutdownRequested,
        PowerOperation::Requested(PowerCommand::Reset)
        | PowerOperation::Running(PowerCommand::Reset)
        | PowerOperation::Committing(PowerCommand::Reset)
        | PowerOperation::Published(PowerCommand::Reset) => PowerState::ResetRequested,
        PowerOperation::Failed { command, failure }
        | PowerOperation::Fenced { command, failure } => {
            snapshot.failure = Some(failure.clone());
            match command {
                PowerCommand::Shutdown => PowerState::ShutdownFailed,
                PowerCommand::Reset => PowerState::ResetFailed,
            }
        }
    };
    if let Err(error) = &service.power {
        snapshot.failure = Some(PowerFailure::Preparation(error.clone()));
    }
    let (power, sleep) = service.power_events.counts();
    snapshot.power_button_presses = power;
    snapshot.sleep_button_presses = sleep;
    snapshot
}

impl FirmwareService {
    fn capture(&self) {
        if matches!(
            &*self.operation.lock(),
            PowerOperation::Committing(_)
                | PowerOperation::Published(_)
                | PowerOperation::Fenced { .. }
        ) {
            return;
        }
        if let Ok(power) = &self.power {
            for block in [power.pm1a_event, power.pm1b_event].into_iter().flatten() {
                let status = self.registers.read(fixed_address(block, 0), 2);
                let enabled = self
                    .registers
                    .read(fixed_address(block, usize::from(block.bytes() / 2)), 2);
                match (status, enabled) {
                    (Ok(status), Ok(enabled)) => {
                        let pending = u16::try_from(status & enabled)
                            .expect("PM1 word values fit u16")
                            & 0x0731;
                        self.power_events.capture(pending);
                        if pending != 0
                            && let Err(error) =
                                self.registers
                                    .write(fixed_address(block, 0), 2, u64::from(pending))
                        {
                            *self.register_failure.lock() = Some(error);
                        }
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        *self.register_failure.lock() = Some(error)
                    }
                }
            }
        }
        let controller = GpeAccess {
            controller: &self.controller,
            registers: &self.registers,
        };
        self.controller
            .capture_asserted(&self.registers, &self.events, |event| {
                if self.queue.capture(&controller, event).is_err() {
                    self.delivery_failed.store(true, Ordering::Release);
                }
            });
        self.worker_waker.wake_from_isr();
    }
    fn disable_hotplug(&self) {
        self.controller.mask_all(&self.registers);
    }
    fn disable(&self) {
        if let Some(vector) = self.route_vector
            && let Err(error) = crate::io::interrupt_manager::mask_interrupt(vector)
        {
            log::error!("failed to mask ACPI SCI route: {error:?}");
        }
        self.disable_hotplug();
    }
}

fn capture_sci_interrupt() {
    if let Some(service) = service() {
        service.capture();
    }
}

async fn firmware_worker() {
    let service = service().expect("ACPI worker is published after its service");
    if let Err(error) = run_firmware_worker(service).await {
        service.disable();
        let mut worker = service.worker.lock();
        let task = match *worker {
            WorkerState::Running(task) => Some(task),
            _ => None,
        };
        *worker = WorkerState::Failed {
            task,
            error: error.clone(),
        };
        publish_unavailable(error.clone());
        log::error!("ACPI firmware worker stopped: {error:?}");
    }
}

async fn run_firmware_worker(service: &'static FirmwareService) -> Result<(), FirmwareError> {
    let mut environment = VmEnvironment::default();
    let mut notifications = VecDeque::new();
    if let Ok(power) = &service.power {
        enable_acpi(service, power).await?;
    }
    let mut hotplug_active = !service.events.is_empty();
    if hotplug_active {
        match reconcile_namespace(service, &mut environment, &mut notifications).await {
            Ok(()) => drain_notifications(service, &mut environment, &mut notifications).await?,
            Err(error) => {
                service.disable_hotplug();
                publish_unavailable(error);
                hotplug_active = false;
            }
        }
    } else {
        publish_unavailable(firmware_error(
            FirmwareErrorKind::Namespace,
            None,
            "ACPI namespace has no fixed GPE CPU event method",
        ));
    }
    if hotplug_active {
        let controller = GpeAccess {
            controller: &service.controller,
            registers: &service.registers,
        };
        for event in service.events.iter() {
            controller.acknowledge(event);
            controller.unmask(event.number);
        }
        crate::cpu::runtime()
            .set_physical_hotplug(PhysicalHotplugStatus::Available)
            .map_err(|cause| {
                firmware_error(
                    FirmwareErrorKind::Resource,
                    None,
                    alloc::format!("hotplug publication failed: {cause:?}"),
                )
            })?;
    }
    if let Some(vector) = service.route_vector {
        crate::io::interrupt_manager::unmask_interrupt(vector).map_err(map_interrupt_error)?;
    }
    // LOOP_PROOF: mode=event; reason=The retained firmware worker awaits coalesced power requests or bounded SCI events between finite AML evaluations.;
    loop {
        match (NextFirmwareEvent { service }).await? {
            FirmwareEvent::Power(command) => {
                let failure =
                    execute_power(service, command, &mut environment, &mut notifications).await;
                log::error!(
                    "system power command returned without completion: {command:?}: {failure:?}"
                );
                let fenced = {
                    let mut operation = service.operation.lock();
                    let fenced = matches!(
                        *operation,
                        PowerOperation::Committing(_) | PowerOperation::Published(_)
                    );
                    *operation = if fenced {
                        PowerOperation::Fenced { command, failure }
                    } else {
                        PowerOperation::Failed { command, failure }
                    };
                    fenced
                };
                if fenced {
                    service.disable();
                    publish_unavailable(firmware_error(
                        FirmwareErrorKind::OperationRegion,
                        None,
                        "firmware execution is fenced after a system power attempt",
                    ));
                    // Register and code leases remain held while the task parks.
                    // No further AML or hardware command is admitted.
                    core::future::pending::<()>().await;
                }
            }
            FirmwareEvent::Gpe(event) => {
                if hotplug_active {
                    let method = event.method_path().map_err(map_aml_error)?;
                    if let Err(error) =
                        execute_method(service, &method, &[], &mut environment, &mut notifications)
                            .await
                    {
                        service.disable_hotplug();
                        publish_unavailable(error);
                        hotplug_active = false;
                    } else {
                        drain_notifications(service, &mut environment, &mut notifications).await?;
                    }
                }
                let controller = GpeAccess {
                    controller: &service.controller,
                    registers: &service.registers,
                };
                if hotplug_active {
                    service.queue.complete(&controller, event);
                } else {
                    controller.acknowledge(event);
                }
            }
        }
    }
}

enum FirmwareEvent {
    Gpe(GpeEvent),
    Power(PowerCommand),
}
struct NextFirmwareEvent {
    service: &'static FirmwareService,
}
impl Future for NextFirmwareEvent {
    type Output = Result<FirmwareEvent, FirmwareError>;
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        // Register first, then recheck every source. Repeated notifications
        // coalesce while the authoritative request or queue entry remains held.
        self.service.worker_waker.register(context.waker());
        if let Some(error) = self.service.register_failure.lock().take() {
            return Poll::Ready(Err(map_register_error(error)));
        }
        if self.service.delivery_failed.swap(false, Ordering::AcqRel) {
            return Poll::Ready(Err(firmware_error(
                FirmwareErrorKind::EventDelivery,
                None,
                "bounded ACPI GPE queue overflowed",
            )));
        }
        let mut operation = self.service.operation.lock();
        if let PowerOperation::Requested(command) = *operation {
            *operation = PowerOperation::Running(command);
            return Poll::Ready(Ok(FirmwareEvent::Power(command)));
        }
        drop(operation);
        match self.service.queue.pop() {
            Some(event) => Poll::Ready(Ok(FirmwareEvent::Gpe(event))),
            None => Poll::Pending,
        }
    }
}

async fn execute_method(
    service: &FirmwareService,
    method: &AmlPath,
    arguments: &[AmlValue],
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<AmlValue, FirmwareError> {
    let deadline = crate::drivers::time::current_tick()
        .checked_add(AML_METHOD_DEADLINE_MS)
        .ok_or_else(|| {
            firmware_error(
                FirmwareErrorKind::TimedOut,
                Some(Arc::from(method.as_str())),
                "AML method deadline overflowed",
            )
        })?;
    let mut vm = service
        .runtime
        .invoke(method, arguments, AmlBudget::firmware_method(deadline))
        .map_err(map_aml_error)?;
    // LOOP_PROOF: mode=event; reason=Each resumable AML evaluation has instruction, loop and deadline budgets, yielding or awaiting its explicit wait between resumes.;
    loop {
        match vm
            .resume(
                crate::drivers::time::current_tick(),
                environment,
                Some(&service.registers),
            )
            .map_err(map_aml_error)?
        {
            VmProgress::Complete(value) => return Ok(value),
            VmProgress::Yielded => crate::task::yield_now().await,
            VmProgress::Notify { object, value } => {
                if let Some(event) = service.runtime.notify_event(object, value) {
                    notifications.push_back(event);
                }
            }
            VmProgress::Waiting(VmWait::Sleep { until_tick }) => {
                if until_tick > deadline {
                    return Err(firmware_error(
                        FirmwareErrorKind::TimedOut,
                        Some(Arc::from(method.as_str())),
                        "AML Sleep extends beyond the method deadline",
                    ));
                }
                let now = crate::drivers::time::current_tick();
                if until_tick > now {
                    crate::drivers::time::sleep_ms(until_tick - now)
                        .await
                        .map_err(|cause| {
                            firmware_error(
                                FirmwareErrorKind::Timer(cause),
                                Some(Arc::from(method.as_str())),
                                "AML wait could not arm its timer",
                            )
                        })?;
                }
            }
            VmProgress::Waiting(VmWait::Mutex { .. }) => {
                crate::drivers::time::sleep_ms(1).await.map_err(|cause| {
                    firmware_error(
                        FirmwareErrorKind::Timer(cause),
                        Some(Arc::from(method.as_str())),
                        "AML wait could not arm its timer",
                    )
                })?;
            }
        }
    }
}

async fn evaluate_binding(
    service: &FirmwareService,
    binding: &NamespaceBinding,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<AmlValue, FirmwareError> {
    match binding {
        NamespaceBinding::Value(value) => Ok(value.clone()),
        NamespaceBinding::Method(method) => {
            execute_method(service, method, &[], environment, notifications).await
        }
    }
}

struct EvaluatedCpu<'a> {
    binding: &'a CpuNamespaceBinding,
    identity: FirmwareCpuIdentity,
    present: bool,
}

async fn evaluate_cpu<'a>(
    service: &FirmwareService,
    binding: &'a CpuNamespaceBinding,
    static_cpus: &[acpi_driver::FirmwareCpuEntry],
    affinities: &[acpi_driver::NumaCpuAffinity],
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<EvaluatedCpu<'a>, FirmwareError> {
    let uid = match binding.uid.as_ref() {
        Some(value) => {
            let value = evaluate_binding(service, value, environment, notifications).await?;
            match acpi_driver::decode_firmware_uid(&value).map_err(map_aml_error)? {
                FirmwareUid::Integer(value) => FirmwareCpuUid::Integer(value),
                FirmwareUid::String(value) => FirmwareCpuUid::String(value),
            }
        }
        None => FirmwareCpuUid::Integer(u64::from(binding.processor_id.ok_or_else(|| {
            firmware_error(
                FirmwareErrorKind::Namespace,
                Some(Arc::from(binding.path.as_str())),
                "CPU namespace object has neither _UID nor a Processor ID",
            )
        })?)),
    };
    let mat = match binding.mat.as_ref() {
        Some(value) => Some(
            acpi_driver::decode_mat_processor(
                &evaluate_binding(service, value, environment, notifications).await?,
            )
            .map_err(map_aml_error)?,
        ),
        None => None,
    };
    let static_cpu = match &uid {
        FirmwareCpuUid::Integer(uid) => u32::try_from(*uid)
            .ok()
            .and_then(|uid| static_cpus.iter().find(|cpu| cpu.firmware_uid == uid)),
        FirmwareCpuUid::String(_) => None,
    };
    if let (Some(mat), Some(static_cpu)) = (mat, static_cpu)
        && mat.apic_id != static_cpu.apic_id
    {
        return Err(firmware_error(
            FirmwareErrorKind::Namespace,
            Some(Arc::from(binding.path.as_str())),
            "_MAT APIC ID conflicts with the static MADT identity",
        ));
    }
    let apic_id = mat
        .map(|entry| entry.apic_id)
        .or_else(|| static_cpu.map(|entry| entry.apic_id))
        .ok_or_else(|| {
            firmware_error(
                FirmwareErrorKind::Namespace,
                Some(Arc::from(binding.path.as_str())),
                "CPU namespace object cannot be matched to an APIC ID",
            )
        })?;
    let proximity_domain = match binding.proximity_domain.as_ref() {
        Some(value) => Some(
            acpi_driver::decode_proximity_domain(
                &evaluate_binding(service, value, environment, notifications).await?,
            )
            .map_err(map_aml_error)?,
        ),
        None => affinities
            .iter()
            .find(|affinity| affinity.enabled && affinity.apic_id == apic_id)
            .map(|affinity| affinity.proximity_domain),
    };
    let status = match binding.status.as_ref() {
        Some(value) => acpi_driver::decode_device_status(
            &evaluate_binding(service, value, environment, notifications).await?,
        )
        .map_err(map_aml_error)?,
        None => 0x0f,
    };
    if status & 1 != 0 && mat.is_some_and(|entry| !entry.enabled && !entry.online_capable) {
        return Err(firmware_error(
            FirmwareErrorKind::Namespace,
            Some(Arc::from(binding.path.as_str())),
            "present CPU is neither enabled nor online-capable in _MAT",
        ));
    }
    Ok(EvaluatedCpu {
        binding,
        identity: FirmwareCpuIdentity {
            uid: Some(uid),
            apic_id: ApicId::new(apic_id),
            proximity_domain,
            eject: if binding.eject_method.is_some() {
                CpuEjectCapability::FirmwareEject
            } else {
                CpuEjectCapability::Fixed
            },
        },
        present: status & 1 != 0,
    })
}

async fn reconcile_namespace(
    service: &FirmwareService,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<(), FirmwareError> {
    let bindings = service.runtime.cpu_devices().map_err(map_aml_error)?;
    let static_cpus = service
        .runtime
        .catalog()
        .firmware_cpus()
        .map_err(map_acpi_error)?;
    let affinities = service
        .runtime
        .catalog()
        .numa_cpu_affinity()
        .map_err(map_acpi_error)?;
    let placement = super::firmware::numa_placement().map_err(|error| {
        firmware_error(
            FirmwareErrorKind::InvalidTable,
            None,
            alloc::format!("NUMA placement is unavailable: {error:?}"),
        )
    })?;
    let mut online_after_provision = Vec::new();

    for binding in &bindings {
        let cpu = evaluate_cpu(
            service,
            binding,
            &static_cpus,
            &affinities,
            environment,
            notifications,
        )
        .await?;
        let located =
            crate::cpu::LocatedCpu::resolve(cpu.identity, placement).map_err(|error| {
                firmware_error(
                    FirmwareErrorKind::Namespace,
                    Some(Arc::from(cpu.binding.path.as_str())),
                    alloc::format!("CPU memory placement was rejected: {error:?}"),
                )
            })?;
        let id = crate::cpu::runtime()
            .discover_possible(located.clone())
            .map_err(map_topology_error)?;
        let prior = crate::cpu::snapshot()
            .slot(id)
            .cloned()
            .unwrap_or_else(|| panic!("newly registered CPU {id} was not published"));
        if cpu.present {
            crate::cpu::runtime()
                .discover_present(located)
                .map_err(map_topology_error)?;
            if prior.state == CpuSlotState::FirmwareAbsent {
                online_after_provision.push(id);
            }
        } else if prior.state.is_present() {
            panic!(
                "firmware removed CPU {} ({}) without the coordinated eject state machine",
                id,
                cpu.binding.path.as_str()
            );
        }
    }

    for id in online_after_provision {
        if let Err(error) = crate::cpu::online(id).await {
            log::warn!("firmware-added CPU {id} could not be brought online: {error:?}");
        }
    }
    Ok(())
}

async fn drain_notifications(
    service: &FirmwareService,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<(), FirmwareError> {
    let mut remaining = NOTIFY_CASCADE_BUDGET;
    // LOOP_PROOF: mode=condition; reason=Each notification consumes the finite cascade budget, an empty queue completes the drain and exhaustion returns a typed failure.;
    while let Some(event) = notifications.pop_front() {
        remaining = remaining.checked_sub(1).ok_or_else(|| {
            firmware_error(
                FirmwareErrorKind::BudgetExhausted,
                None,
                "ACPI Notify cascade exhausted its event budget",
            )
        })?;
        match event {
            CpuFirmwareEvent::RescanContainer { .. } | CpuFirmwareEvent::CheckDevice { .. } => {
                reconcile_namespace(service, environment, notifications).await?;
            }
            CpuFirmwareEvent::EjectRequest { object } => {
                eject_cpu(service, &object, environment, notifications).await?;
            }
        }
    }
    Ok(())
}

async fn eject_cpu(
    service: &FirmwareService,
    object: &AmlPath,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<(), FirmwareError> {
    let bindings = service.runtime.cpu_devices().map_err(map_aml_error)?;
    let binding = bindings
        .iter()
        .find(|binding| binding.path == *object)
        .ok_or_else(|| {
            firmware_error(
                FirmwareErrorKind::Namespace,
                Some(Arc::from(object.as_str())),
                "eject Notify target is not a CPU namespace object",
            )
        })?;
    let static_cpus = service
        .runtime
        .catalog()
        .firmware_cpus()
        .map_err(map_acpi_error)?;
    let affinities = service
        .runtime
        .catalog()
        .numa_cpu_affinity()
        .map_err(map_acpi_error)?;
    let evaluated = evaluate_cpu(
        service,
        binding,
        &static_cpus,
        &affinities,
        environment,
        notifications,
    )
    .await?;
    let id = crate::cpu::snapshot()
        .cpu_for_apic(evaluated.identity.apic_id)
        .ok_or_else(|| {
            firmware_error(
                FirmwareErrorKind::Namespace,
                Some(Arc::from(object.as_str())),
                "eject target has no stable CPU slot",
            )
        })?;
    let authority = match crate::cpu::prepare_eject(id).await {
        Ok(authority) => authority,
        Err(error) => {
            report_ost(
                service,
                binding,
                eject_ost_status(&error),
                environment,
                notifications,
            )
            .await?;
            log::warn!("firmware eject request for CPU {id} was rejected: {error:?}");
            return Ok(());
        }
    };
    debug_assert_eq!(authority.cpu(), id);
    let eject_method = binding
        .eject_method
        .as_ref()
        .expect("firmware-ejectable CPU lost its _EJ0 binding");
    let eject_result = execute_method(
        service,
        eject_method,
        &[AmlValue::Integer(1)],
        environment,
        notifications,
    )
    .await;
    let present = evaluate_present_status(service, binding, environment, notifications).await;
    match (eject_result, present) {
        (_, Ok(false)) => {
            crate::cpu::commit_eject(authority)
                .await
                .map_err(map_transition_error)?;
            report_ost(
                service,
                binding,
                EjectOstStatus::Success,
                environment,
                notifications,
            )
            .await
        }
        (Ok(_), Ok(true)) => {
            let error = firmware_error(
                FirmwareErrorKind::EventDelivery,
                Some(Arc::from(eject_method.as_str())),
                "_EJ0 completed but _STA still reports the CPU present",
            );
            crate::cpu::fail_eject(authority, error.clone())
                .await
                .map_err(map_transition_error)?;
            report_ost(
                service,
                binding,
                EjectOstStatus::Failure,
                environment,
                notifications,
            )
            .await?;
            log::warn!("firmware eject for CPU {id} did not remove the CPU: {error:?}");
            Ok(())
        }
        (Err(error), Ok(true)) => {
            crate::cpu::fail_eject(authority, error.clone())
                .await
                .map_err(map_transition_error)?;
            report_ost(
                service,
                binding,
                EjectOstStatus::Failure,
                environment,
                notifications,
            )
            .await?;
            log::warn!("firmware eject method for CPU {id} failed: {error:?}");
            Ok(())
        }
        (eject_result, Err(mut error)) => {
            error.detail = alloc::format!(
                "CPU {id} _STA verification failed after _EJ0; the physical outcome is unknown: {}",
                error.detail
            );
            crate::cpu::fail_eject(authority, error.clone())
                .await
                .map_err(map_transition_error)?;
            report_ost(
                service,
                binding,
                EjectOstStatus::Failure,
                environment,
                notifications,
            )
            .await?;
            log::warn!(
                "firmware eject verification for CPU {id} failed; _EJ0 result={eject_result:?}, error={error:?}"
            );
            Ok(())
        }
    }
}

async fn evaluate_present_status(
    service: &FirmwareService,
    binding: &CpuNamespaceBinding,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<bool, FirmwareError> {
    let status = match binding.status.as_ref() {
        Some(status) => acpi_driver::decode_device_status(
            &evaluate_binding(service, status, environment, notifications).await?,
        )
        .map_err(map_aml_error)?,
        None => 0x0f,
    };
    Ok(status & 1 != 0)
}

async fn report_ost(
    service: &FirmwareService,
    binding: &CpuNamespaceBinding,
    status: EjectOstStatus,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<(), FirmwareError> {
    // ACPI defines _OST as optional. Its absence removes the platform-status
    // handshake, but does not revoke the independent _EJ0 eject capability.
    let Some(method) = binding.ost_method.as_ref() else {
        log::warn!(
            "CPU firmware object {} has no _OST method; eject status was not reported",
            binding.path.as_str()
        );
        return Ok(());
    };
    execute_method(
        service,
        method,
        &[
            AmlValue::Integer(OST_EJECT_REQUEST),
            AmlValue::Integer(status.value()),
            AmlValue::Buffer(Arc::<[u8]>::from([])),
        ],
        environment,
        notifications,
    )
    .await
    .map(|_| ())
}

fn eject_ost_status(error: &CpuTransitionError) -> EjectOstStatus {
    match error {
        CpuTransitionError::Busy { .. } => EjectOstStatus::DeviceBusy,
        CpuTransitionError::UnsupportedTopology(_) | CpuTransitionError::BootstrapCpu => {
            EjectOstStatus::NotSupported
        }
        CpuTransitionError::NotPresent
        | CpuTransitionError::TimedOut { .. }
        | CpuTransitionError::MemoryCache(_)
        | CpuTransitionError::Firmware(_) => EjectOstStatus::Failure,
    }
}

struct SciRoute {
    gsi: u32,
    trigger: TriggerMode,
    polarity: Polarity,
}

impl SciRoute {
    fn resolve(
        runtime: &AcpiRuntime,
        fixed: &FixedEventDescription,
    ) -> Result<Self, FirmwareError> {
        let source = u8::try_from(fixed.sci_interrupt).map_err(|_| {
            firmware_error(
                FirmwareErrorKind::EventDelivery,
                None,
                "SCI interrupt does not fit the MADT source-IRQ domain",
            )
        })?;
        let override_entry = runtime
            .catalog()
            .interrupt_overrides()
            .map_err(map_acpi_error)?
            .into_iter()
            .find(|entry| entry.bus == 0 && entry.source == source);
        let gsi = override_entry
            .as_ref()
            .map_or(u32::from(source), |entry| entry.global_interrupt);
        let trigger = match override_entry.as_ref().map(|entry| entry.trigger_mode) {
            Some(InterruptTriggerMode::Edge) => TriggerMode::Edge,
            Some(InterruptTriggerMode::ConformsToBus | InterruptTriggerMode::Level) | None => {
                TriggerMode::Level
            }
        };
        let polarity = match override_entry.as_ref().map(|entry| entry.polarity) {
            Some(InterruptPolarity::ActiveHigh) => Polarity::ActiveHigh,
            Some(InterruptPolarity::ConformsToBus | InterruptPolarity::ActiveLow) | None => {
                Polarity::ActiveLow
            }
        };
        Ok(Self {
            gsi,
            trigger,
            polarity,
        })
    }
}

struct FixedGpeBlock {
    address: GenericAddress,
    register_bytes: u8,
    base_number: u16,
}
impl FixedGpeBlock {
    fn location(&self, number: GpeNumber) -> Option<(usize, u8)> {
        let relative = number.get().checked_sub(self.base_number)?;
        if relative >= u16::from(self.register_bytes) * 8 {
            return None;
        }
        Some((usize::from(relative / 8), 1 << (relative % 8)))
    }
    fn address(&self, offset: usize) -> GenericAddress {
        let mut address = self.address;
        address.address = address
            .address
            .checked_add(offset as u64)
            .expect("GPE byte offset was bounded at admission");
        address
    }
    fn read(&self, registers: &FirmwareRegisters, offset: usize) -> u8 {
        u8::try_from(
            registers
                .read(self.address(offset), 1)
                .expect("GPE byte register was admitted"),
        )
        .expect("GPE byte value fits u8")
    }
    fn write(&self, registers: &FirmwareRegisters, offset: usize, value: u8) {
        registers
            .write(self.address(offset), 1, u64::from(value))
            .expect("GPE byte register was admitted");
    }
    fn update_enable(
        &self,
        registers: &FirmwareRegisters,
        byte: usize,
        update: impl FnOnce(u64) -> u64,
    ) {
        registers
            .modify(
                self.address(usize::from(self.register_bytes) + byte),
                1,
                update,
            )
            .expect("GPE enable byte was admitted");
    }
}
struct FixedGpeController {
    blocks: Vec<FixedGpeBlock>,
}
impl FixedGpeController {
    fn new(
        registers: &FirmwareRegisters,
        fixed: &FixedEventDescription,
    ) -> Result<Self, FirmwareError> {
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(fixed.gpe_blocks.len())
            .map_err(|_| {
                firmware_error(
                    FirmwareErrorKind::Resource,
                    None,
                    "GPE metadata allocation failed",
                )
            })?;
        // LOOP_PROOF: mode=bounded; reason=The FADT contains at most two GPE blocks and each block's byte count is validated before publication.;
        for block in &fixed.gpe_blocks {
            if !matches!(
                block.address.access_size,
                RegisterAccessSize::Undefined | RegisterAccessSize::Byte
            ) {
                return Err(firmware_error(
                    FirmwareErrorKind::OperationRegion,
                    None,
                    "fixed GPE requires byte access",
                ));
            }
            // LOOP_PROOF: mode=bounded; reason=Every byte in the finite GPE status and enable block is validated exactly once.;
            for byte in 0..usize::from(block.register_bytes) * 2 {
                let mut address = block.address;
                address.address = address
                    .address
                    .checked_add(byte as u64)
                    .ok_or_else(|| map_register_error(RegisterError::InvalidRange))?;
                registers.validate(address, 1).map_err(map_register_error)?;
            }
            blocks.push(FixedGpeBlock {
                address: block.address,
                register_bytes: block.register_bytes,
                base_number: block.base_number,
            });
        }
        Ok(Self { blocks })
    }
    fn capture_asserted(
        &self,
        registers: &FirmwareRegisters,
        events: &GpeEventMap,
        mut capture: impl FnMut(GpeEvent),
    ) {
        // LOOP_PROOF: mode=bounded; reason=The retained controller contains at most two finite GPE blocks.;
        for block in &self.blocks {
            // LOOP_PROOF: mode=bounded; reason=Each GPE status and enable byte is sampled once within the validated block length.;
            for byte in 0..usize::from(block.register_bytes) {
                let pending = block.read(registers, byte)
                    & block.read(registers, usize::from(block.register_bytes) + byte);
                // LOOP_PROOF: mode=bounded; reason=One GPE register byte contains exactly eight event bits.;
                for bit in 0..8u8 {
                    if pending & (1 << bit) == 0 {
                        continue;
                    }
                    let number = block.base_number
                        + u16::try_from(byte).expect("validated GPE byte count fits u16") * 8
                        + u16::from(bit);
                    if let Some(event) = events.get(number) {
                        capture(event);
                    } else {
                        block
                            .update_enable(registers, byte, |value| value & !u64::from(1u8 << bit));
                    }
                }
            }
        }
    }
    fn mask_all(&self, registers: &FirmwareRegisters) {
        // LOOP_PROOF: mode=bounded; reason=The retained controller contains at most two finite GPE blocks.;
        for block in &self.blocks {
            // LOOP_PROOF: mode=bounded; reason=Each enable byte is masked exactly once within its admitted block.;
            for byte in 0..usize::from(block.register_bytes) {
                block.write(registers, usize::from(block.register_bytes) + byte, 0);
            }
        }
    }
    fn location(&self, number: GpeNumber) -> Option<(&FixedGpeBlock, usize, u8)> {
        self.blocks
            .iter()
            .find_map(|block| block.location(number).map(|(byte, bit)| (block, byte, bit)))
    }
}
/// Borrows the register owner for the external GPE queue's mask/ack protocol.
struct GpeAccess<'service> {
    controller: &'service FixedGpeController,
    registers: &'service FirmwareRegisters,
}
impl GpeController for GpeAccess<'_> {
    fn mask(&self, number: GpeNumber) {
        if let Some((block, byte, bit)) = self.controller.location(number) {
            block.update_enable(self.registers, byte, |value| value & !u64::from(bit));
        }
    }
    fn acknowledge(&self, event: GpeEvent) {
        if let Some((block, byte, bit)) = self.controller.location(event.number) {
            block.write(self.registers, byte, bit);
        }
    }
    fn unmask(&self, number: GpeNumber) {
        if let Some((block, byte, bit)) = self.controller.location(number) {
            block.update_enable(self.registers, byte, |value| value | u64::from(bit));
        }
    }
}

fn validate_fixed_width(
    register: acpi_driver::power::FixedRegister,
    expected: RegisterAccessSize,
) -> Result<(), FirmwareError> {
    if !matches!(
        register.address().access_size,
        RegisterAccessSize::Undefined
    ) && register.address().access_size != expected
    {
        return Err(firmware_error(
            FirmwareErrorKind::OperationRegion,
            None,
            "fixed power register access width is unsupported",
        ));
    }
    Ok(())
}

async fn enable_acpi(
    service: &FirmwareService,
    power: &PowerRegisterDescription,
) -> Result<(), FirmwareError> {
    if power.hardware_reduced {
        return Ok(());
    }
    let Some(control) = power.pm1a_control else {
        return Ok(());
    };
    validate_fixed_width(control, RegisterAccessSize::Word)?;
    service
        .registers
        .validate(fixed_address(control, 0), 2)
        .map_err(map_register_error)?;
    if service
        .registers
        .read(fixed_address(control, 0), 2)
        .map_err(map_register_error)?
        & 1
        == 0
    {
        let (command, value) = power.smi_enable.ok_or_else(|| {
            firmware_error(
                FirmwareErrorKind::OperationRegion,
                None,
                "firmware has not enabled ACPI mode and provides no enable command",
            )
        })?;
        validate_fixed_width(command, RegisterAccessSize::Byte)?;
        service
            .registers
            .write(fixed_address(command, 0), 1, u64::from(value))
            .map_err(map_register_error)?;
        let mut enabled = false;
        // LOOP_PROOF: mode=bounded; reason=ACPI mode transfer is observed at most one thousand times, each retry awaits a timer outside register locks.;
        for _ in 0..1_000 {
            if service
                .registers
                .read(fixed_address(control, 0), 2)
                .map_err(map_register_error)?
                & 1
                != 0
            {
                enabled = true;
                break;
            }
            crate::drivers::time::sleep_ms(1).await.map_err(|cause| {
                firmware_error(
                    FirmwareErrorKind::TimedOut,
                    None,
                    alloc::format!("ACPI enable timer failed: {cause:?}"),
                )
            })?;
        }
        if !enabled {
            return Err(firmware_error(
                FirmwareErrorKind::TimedOut,
                None,
                "ACPI mode transfer did not complete",
            ));
        }
    }
    let button_mask = (if power.fixed_power_button { 1 << 8 } else { 0 })
        | (if power.fixed_sleep_button { 1 << 9 } else { 0 });
    // LOOP_PROOF: mode=bounded; reason=The FADT has at most two PM1 event blocks.;
    for block in [power.pm1a_event, power.pm1b_event].into_iter().flatten() {
        validate_fixed_width(block, RegisterAccessSize::Word)?;
        service
            .registers
            .validate(fixed_address(block, 0), 2)
            .map_err(map_register_error)?;
        let enable = fixed_address(block, usize::from(block.bytes() / 2));
        service
            .registers
            .validate(enable, 2)
            .map_err(map_register_error)?;
        service
            .registers
            .write(fixed_address(block, 0), 2, button_mask)
            .map_err(map_register_error)?;
        service
            .registers
            .modify(enable, 2, |value| value | button_mask)
            .map_err(map_register_error)?;
    }
    Ok(())
}

enum PreparedPower {
    Reset {
        register: acpi_driver::power::FixedRegister,
        value: u8,
    },
    Sleep {
        a: acpi_driver::power::FixedRegister,
        b: Option<acpi_driver::power::FixedRegister>,
        types: [u8; 2],
        reduced: bool,
    },
}
async fn prepare_power(
    service: &FirmwareService,
    command: PowerCommand,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<PreparedPower, FirmwareError> {
    let power = service.power.as_ref().map_err(Clone::clone)?;
    if command == PowerCommand::Reset {
        let (register, value) = power.reset.ok_or_else(|| {
            firmware_error(
                FirmwareErrorKind::OperationRegion,
                None,
                "FADT provides no reset register",
            )
        })?;
        validate_fixed_width(register, RegisterAccessSize::Byte)?;
        service
            .registers
            .validate(fixed_address(register, 0), 1)
            .map_err(map_register_error)?;
        return Ok(PreparedPower::Reset { register, value });
    }
    let namespace = service.runtime.namespace().ok_or_else(|| {
        firmware_error(
            FirmwareErrorKind::Namespace,
            None,
            "S5 requires the retained AML namespace",
        )
    })?;
    let path = AmlPath::new("\\_S5_").map_err(map_aml_error)?;
    let value = match namespace.get(&path) {
        Some(AmlObject::Value(value)) => value.clone(),
        Some(AmlObject::Method(_)) => {
            execute_method(service, &path, &[], environment, notifications).await?
        }
        _ => {
            return Err(firmware_error(
                FirmwareErrorKind::InvalidObjectType,
                None,
                "S5 sleep type object is absent or invalid",
            ));
        }
    };
    let AmlValue::Package(values) = value else {
        return Err(firmware_error(
            FirmwareErrorKind::InvalidObjectType,
            None,
            "S5 requires a package",
        ));
    };
    if values.len() < 2 {
        return Err(firmware_error(
            FirmwareErrorKind::InvalidObjectType,
            None,
            "S5 package does not contain both sleep types",
        ));
    }
    let mut types = [0u8; 2];
    // LOOP_PROOF: mode=bounded; reason=The PM1a and PM1b sleep types are two three-bit integers.;
    for index in 0..2 {
        let value = values[index].as_integer().map_err(map_aml_error)?;
        types[index] = u8::try_from(value)
            .ok()
            .filter(|value| *value < 8)
            .ok_or_else(|| {
                firmware_error(
                    FirmwareErrorKind::InvalidObjectType,
                    None,
                    "S5 sleep type exceeds its three-bit field",
                )
            })?;
    }
    let a = power.sleep_control.or(power.pm1a_control).ok_or_else(|| {
        firmware_error(
            FirmwareErrorKind::OperationRegion,
            None,
            "FADT provides no sleep control register",
        )
    })?;
    let b = if power.hardware_reduced {
        None
    } else {
        power.pm1b_control
    };
    validate_fixed_width(
        a,
        if power.hardware_reduced {
            RegisterAccessSize::Byte
        } else {
            RegisterAccessSize::Word
        },
    )?;
    service
        .registers
        .validate(
            fixed_address(a, 0),
            if power.hardware_reduced { 1 } else { 2 },
        )
        .map_err(map_register_error)?;
    if let Some(b) = b {
        validate_fixed_width(b, RegisterAccessSize::Word)?;
        service
            .registers
            .validate(fixed_address(b, 0), 2)
            .map_err(map_register_error)?;
    }
    let pts = AmlPath::new("\\_PTS").map_err(map_aml_error)?;
    match namespace.get(&pts) {
        Some(AmlObject::Method(_)) => {
            execute_method(
                service,
                &pts,
                &[AmlValue::Integer(5)],
                environment,
                notifications,
            )
            .await?;
        }
        None => {}
        _ => {
            return Err(firmware_error(
                FirmwareErrorKind::InvalidObjectType,
                None,
                "PTS must be a control method",
            ));
        }
    }
    drain_notifications(service, environment, notifications).await?;
    Ok(PreparedPower::Sleep {
        a,
        b,
        types,
        reduced: power.hardware_reduced,
    })
}

async fn execute_power(
    service: &FirmwareService,
    command: PowerCommand,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> PowerFailure {
    let prepared = match prepare_power(service, command, environment, notifications).await {
        Ok(prepared) => prepared,
        Err(error) => return PowerFailure::Preparation(error),
    };
    let publication = match prepared {
        PreparedPower::Reset { register, value } => {
            *service.operation.lock() = PowerOperation::Committing(command);
            service.disable();
            service
                .registers
                .write(fixed_address(register, 0), 1, u64::from(value))
        }
        PreparedPower::Sleep {
            a,
            b,
            types,
            reduced: true,
        } => {
            debug_assert!(b.is_none());
            *service.operation.lock() = PowerOperation::Committing(command);
            service.disable();
            service
                .registers
                .write(fixed_address(a, 0), 1, u64::from(types[0]) << 2 | (1 << 5))
        }
        PreparedPower::Sleep {
            a,
            b,
            types,
            reduced: false,
        } => {
            // Both type fields are prepared before the first SLP_EN publication.
            if let Err(error) = service.registers.modify(fixed_address(a, 0), 2, |value| {
                (value & !0x3c00) | (u64::from(types[0]) << 10)
            }) {
                return PowerFailure::Preparation(map_register_error(error));
            }
            if let Some(b) = b
                && let Err(error) = service.registers.modify(fixed_address(b, 0), 2, |value| {
                    (value & !0x3c00) | (u64::from(types[1]) << 10)
                })
            {
                return PowerFailure::Preparation(map_register_error(error));
            }
            *service.operation.lock() = PowerOperation::Committing(command);
            service.disable();
            if let Err(error) = service
                .registers
                .modify(fixed_address(a, 0), 2, |value| value | (1 << 13))
            {
                return PowerFailure::Preparation(map_register_error(error));
            }
            *service.operation.lock() = PowerOperation::Published(command);
            if let Some(b) = b
                && let Err(error) = service
                    .registers
                    .modify(fixed_address(b, 0), 2, |value| value | (1 << 13))
            {
                return PowerFailure::Published {
                    cause: map_register_error(error),
                };
            }
            Ok(())
        }
    };
    // Register-access failures precede the volatile/output instruction. For PM1
    // the first successful SLP_EN is recorded before programming the second bank.
    if let Err(error) = publication {
        return PowerFailure::Preparation(map_register_error(error));
    }
    *service.operation.lock() = PowerOperation::Published(command);
    if let Err(cause) = crate::drivers::time::sleep_ms(100).await {
        return PowerFailure::Published {
            cause: firmware_error(
                FirmwareErrorKind::TimedOut,
                None,
                alloc::format!("power completion timer failed: {cause:?}"),
            ),
        };
    }
    PowerFailure::Published {
        cause: firmware_error(
            FirmwareErrorKind::TimedOut,
            None,
            "hardware power command returned, completion remains unconfirmed",
        ),
    }
}

fn map_register_error(error: RegisterError) -> FirmwareError {
    firmware_error(
        FirmwareErrorKind::OperationRegion,
        None,
        alloc::format!("firmware register admission or access failed: {error:?}"),
    )
}

struct GpeEventMap {
    events: [Option<GpeEvent>; 256],
    count: usize,
}

impl GpeEventMap {
    fn build(runtime: &AcpiRuntime, fixed: &FixedEventDescription) -> Result<Self, FirmwareError> {
        let mut events = [None; 256];
        let mut count = 0usize;
        for block in &fixed.gpe_blocks {
            for number in block.base_number..block.base_number + block.number_count() {
                let number = GpeNumber::new(number).map_err(map_acpi_error)?;
                if let Some(event) = runtime.gpe_event(number).map_err(map_aml_error)? {
                    events[usize::from(number.get())] = Some(event);
                    count += 1;
                }
            }
        }
        Ok(Self { events, count })
    }

    const fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn get(&self, number: u16) -> Option<GpeEvent> {
        self.events.get(usize::from(number)).copied().flatten()
    }

    fn iter(&self) -> impl Iterator<Item = GpeEvent> + '_ {
        self.events.iter().flatten().copied()
    }
}

fn map_acpi_error(error: AcpiError) -> FirmwareError {
    let object = error
        .table
        .map(|signature| Arc::<str>::from(core::str::from_utf8(&signature).unwrap_or("????")));
    let kind = match error.kind {
        AcpiErrorKind::CapacityExceeded => FirmwareErrorKind::Resource,
        _ => FirmwareErrorKind::InvalidTable,
    };
    FirmwareError {
        kind,
        object,
        detail: error.detail,
    }
}

fn map_aml_error(error: AmlError) -> FirmwareError {
    let kind = match error.kind {
        AmlErrorKind::MalformedEncoding => FirmwareErrorKind::InvalidTable,
        AmlErrorKind::InvalidObjectType => FirmwareErrorKind::InvalidObjectType,
        AmlErrorKind::MissingObject => FirmwareErrorKind::Namespace,
        AmlErrorKind::UnsupportedOpcode => FirmwareErrorKind::UnsupportedOpcode,
        AmlErrorKind::InstructionBudgetExhausted
        | AmlErrorKind::LoopBudgetExhausted
        | AmlErrorKind::RecursionBudgetExhausted
        | AmlErrorKind::AllocationBudgetExhausted => FirmwareErrorKind::BudgetExhausted,
        AmlErrorKind::TimedOut | AmlErrorKind::Mutex => FirmwareErrorKind::TimedOut,
        AmlErrorKind::OperationRegion => FirmwareErrorKind::OperationRegion,
    };
    FirmwareError {
        kind,
        object: error.object,
        detail: error.detail,
    }
}

fn map_topology_error(error: CpuTopologyIssue) -> FirmwareError {
    firmware_error(
        FirmwareErrorKind::Namespace,
        None,
        alloc::format!("ACPI CPU topology was rejected: {error:?}"),
    )
}

fn map_transition_error(error: CpuTransitionError) -> FirmwareError {
    match error {
        CpuTransitionError::Firmware(error) => error,
        error => firmware_error(
            FirmwareErrorKind::EventDelivery,
            None,
            alloc::format!("CPU lifecycle transition failed: {error:?}"),
        ),
    }
}

fn map_interrupt_error(error: InterruptError) -> FirmwareError {
    firmware_error(
        FirmwareErrorKind::EventDelivery,
        None,
        alloc::format!("ACPI SCI routing failed: {error:?}"),
    )
}

fn firmware_error(
    kind: FirmwareErrorKind,
    object: Option<Arc<str>>,
    detail: impl Into<String>,
) -> FirmwareError {
    FirmwareError {
        kind,
        object,
        detail: detail.into(),
    }
}

fn publish_unavailable(error: FirmwareError) {
    crate::cpu::runtime()
        .set_physical_hotplug(PhysicalHotplugStatus::Unavailable(error))
        .unwrap_or_else(|topology| panic!("ACPI hotplug failure publication failed: {topology:?}"));
}
