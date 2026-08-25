use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};

use acpi_driver::aml::{
    AmlBudget, AmlPath, AmlValue, OperationRegionHandler, OperationRegionSpace, VmEnvironment,
    VmProgress, VmWait,
};
use acpi_driver::{
    AcpiError, AcpiErrorKind, AcpiRuntime, AcpiRuntimeState, AmlError, AmlErrorKind,
    CpuFirmwareEvent, CpuNamespaceBinding, FirmwareUid, FixedEventDescription, GenericAddress,
    GenericAddressSpace, GpeController, GpeEvent, GpeNumber, GpeQueue, GpeRegisterBlock,
    InterruptPolarity, InterruptTriggerMode, NamespaceBinding, RegisterAccessSize,
};
use spin::Once;

use crate::cpu::{
    ApicId, CpuEjectCapability, CpuId, CpuSlotState, CpuTopologyIssue, CpuTransitionError,
    FirmwareCpuIdentity, FirmwareCpuUid, FirmwareError, FirmwareErrorKind, PhysicalHotplugStatus,
};
use crate::io::interrupt_manager::{InterruptError, Polarity, TriggerMode};
use crate::sync::AtomicWaker;

const GPE_QUEUE_CAPACITY: usize = 256;
const AML_METHOD_DEADLINE_MS: u64 = 5_000;
const NOTIFY_CASCADE_BUDGET: usize = 256;
const NO_WORKER_TASK: u64 = u64::MAX;
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

static HOTPLUG_SERVICE: Once<AcpiHotplugService> = Once::new();

/// Installs the SCI route and its BSP-pinned firmware worker.
///
/// Failure only disables physical hotplug. Static MADT topology and logical
/// online/offline remain available, and the typed reason is published in the
/// CPU snapshot.
pub fn initialize() {
    if HOTPLUG_SERVICE.get().is_some() {
        return;
    }
    if let Err(error) = try_initialize() {
        log::warn!("ACPI physical CPU hotplug unavailable: {error:?}");
        publish_unavailable(error);
    }
}

fn try_initialize() -> Result<(), FirmwareError> {
    let runtime = crate::platform::firmware::runtime().ok_or_else(|| {
        firmware_error(
            FirmwareErrorKind::Namespace,
            None,
            "ACPI runtime is unavailable",
        )
    })?;
    if let AcpiRuntimeState::StaticTablesOnly { aml_error } = runtime.state() {
        return Err(map_aml_error(aml_error.clone()));
    }
    let fixed = runtime.catalog().fixed_events().map_err(map_acpi_error)?;
    let controller = FixedGpeController::new(&fixed)?;
    controller.mask_all();
    let events = GpeEventMap::build(runtime, &fixed)?;
    if events.is_empty() {
        return Err(firmware_error(
            FirmwareErrorKind::EventDelivery,
            None,
            "ACPI namespace does not define a fixed GPE event method",
        ));
    }
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

    let service =
        HOTPLUG_SERVICE.call_once(|| AcpiHotplugService::new(runtime, controller, events, vector));
    if let Err(error) =
        crate::io::interrupt_manager::register_handler(vector, Box::new(capture_sci_interrupt))
    {
        crate::io::interrupt_manager::free_vector(vector);
        return Err(map_interrupt_error(error));
    }
    match crate::task::spawn(
        firmware_worker(),
        crate::task::TaskPlacement::Pinned(CpuId::BOOTSTRAP),
    ) {
        Ok(task) => {
            service.worker_task.store(task.as_u64(), Ordering::Release);
            Ok(())
        }
        Err(error) => {
            crate::io::interrupt_manager::unregister_handler(vector);
            crate::io::interrupt_manager::free_vector(vector);
            Err(firmware_error(
                FirmwareErrorKind::Resource,
                None,
                alloc::format!("ACPI firmware worker could not be spawned: {error:?}"),
            ))
        }
    }
}

struct AcpiHotplugService {
    runtime: &'static AcpiRuntime,
    controller: FixedGpeController,
    events: GpeEventMap,
    queue: GpeQueue<GPE_QUEUE_CAPACITY>,
    worker_waker: AtomicWaker,
    delivery_failed: AtomicBool,
    route_vector: u8,
    worker_task: AtomicU64,
}

impl AcpiHotplugService {
    const fn new(
        runtime: &'static AcpiRuntime,
        controller: FixedGpeController,
        events: GpeEventMap,
        route_vector: u8,
    ) -> Self {
        Self {
            runtime,
            controller,
            events,
            queue: GpeQueue::new(),
            worker_waker: AtomicWaker::new(),
            delivery_failed: AtomicBool::new(false),
            route_vector,
            worker_task: AtomicU64::new(NO_WORKER_TASK),
        }
    }

    fn capture(&self) {
        self.controller.capture_asserted(&self.events, |event| {
            if self.queue.capture(&self.controller, event).is_err() {
                self.delivery_failed.store(true, Ordering::Release);
            }
        });
        self.worker_waker.wake_from_isr();
    }

    fn disable(&self) {
        if let Err(error) = crate::io::interrupt_manager::mask_interrupt(self.route_vector) {
            log::error!("failed to mask unusable ACPI SCI route: {error:?}");
        }
        for event in self.events.iter() {
            self.controller.mask(event.number);
        }
    }
}

fn capture_sci_interrupt() {
    let Some(service) = HOTPLUG_SERVICE.get() else {
        return;
    };
    service.capture();
}

async fn firmware_worker() {
    let service = HOTPLUG_SERVICE
        .get()
        .unwrap_or_else(|| panic!("ACPI firmware worker started without its service"));
    if let Err(error) = run_firmware_worker(service).await {
        service.disable();
        publish_unavailable(error.clone());
        log::error!("ACPI physical CPU hotplug disabled: {error:?}");
    }
}

async fn run_firmware_worker(service: &'static AcpiHotplugService) -> Result<(), FirmwareError> {
    let mut environment = VmEnvironment::default();
    let mut notifications = VecDeque::new();
    reconcile_namespace(service, &mut environment, &mut notifications).await?;
    drain_notifications(service, &mut environment, &mut notifications).await?;
    for event in service.events.iter() {
        service.controller.acknowledge(event);
        service.controller.unmask(event.number);
    }
    crate::io::interrupt_manager::unmask_interrupt(service.route_vector)
        .map_err(map_interrupt_error)?;
    crate::cpu::runtime()
        .set_physical_hotplug(PhysicalHotplugStatus::Available)
        .unwrap_or_else(|error| panic!("ACPI hotplug availability publication failed: {error:?}"));

    loop {
        let event = NextGpeFuture { service }.await?;
        let method = event.method_path().map_err(map_aml_error)?;
        let _ = execute_method(service, &method, &[], &mut environment, &mut notifications).await?;
        drain_notifications(service, &mut environment, &mut notifications).await?;
        service.queue.complete(&service.controller, event);
    }
}

struct NextGpeFuture {
    service: &'static AcpiHotplugService,
}

impl Future for NextGpeFuture {
    type Output = Result<GpeEvent, FirmwareError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.service.delivery_failed.swap(false, Ordering::AcqRel) {
            return Poll::Ready(Err(firmware_error(
                FirmwareErrorKind::EventDelivery,
                None,
                "bounded ACPI GPE queue overflowed",
            )));
        }
        if let Some(event) = self.service.queue.pop() {
            return Poll::Ready(Ok(event));
        }
        self.service.worker_waker.register(context.waker());
        if self.service.delivery_failed.swap(false, Ordering::AcqRel) {
            return Poll::Ready(Err(firmware_error(
                FirmwareErrorKind::EventDelivery,
                None,
                "bounded ACPI GPE queue overflowed",
            )));
        }
        match self.service.queue.pop() {
            Some(event) => Poll::Ready(Ok(event)),
            None => Poll::Pending,
        }
    }
}

async fn execute_method(
    service: &AcpiHotplugService,
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
    loop {
        match vm
            .resume(
                crate::drivers::time::current_tick(),
                environment,
                Some(&AmlOperationRegions),
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
                    crate::drivers::time::sleep_ms(until_tick - now).await;
                }
            }
            VmProgress::Waiting(VmWait::Mutex { .. }) => {
                crate::drivers::time::sleep_ms(1).await;
            }
        }
    }
}

async fn evaluate_binding(
    service: &AcpiHotplugService,
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
    service: &AcpiHotplugService,
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
    service: &AcpiHotplugService,
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
        let id = crate::cpu::runtime()
            .discover_possible(cpu.identity.clone())
            .map_err(map_topology_error)?;
        let prior = crate::cpu::snapshot()
            .slot(id)
            .cloned()
            .unwrap_or_else(|| panic!("newly registered CPU {id} was not published"));
        if cpu.present {
            crate::cpu::runtime()
                .discover_present(cpu.identity)
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

    crate::mm::phys::frame_allocator::pmm_provision_possible_cpus().map_err(|error| {
        firmware_error(
            FirmwareErrorKind::Resource,
            None,
            alloc::format!("CPU-local PMM provisioning failed: {error:?}"),
        )
    })?;
    for id in online_after_provision {
        if let Err(error) = crate::cpu::online(id).await {
            log::warn!("firmware-added CPU {id} could not be brought online: {error:?}");
        }
    }
    Ok(())
}

async fn drain_notifications(
    service: &AcpiHotplugService,
    environment: &mut VmEnvironment,
    notifications: &mut VecDeque<CpuFirmwareEvent>,
) -> Result<(), FirmwareError> {
    let mut remaining = NOTIFY_CASCADE_BUDGET;
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
    service: &AcpiHotplugService,
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
        (_, Err(error)) => {
            panic!("CPU {id} firmware eject outcome is unknown because _STA failed: {error:?}")
        }
    }
}

async fn evaluate_present_status(
    service: &AcpiHotplugService,
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
    service: &AcpiHotplugService,
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

#[derive(Clone, Copy)]
enum GpeRegisterAccess {
    SystemIo { base: u16 },
    SystemMemory { base: usize },
}

impl GpeRegisterAccess {
    fn new(address: GenericAddress, total_bytes: u8) -> Result<Self, FirmwareError> {
        if !matches!(
            address.access_size,
            RegisterAccessSize::Undefined | RegisterAccessSize::Byte
        ) {
            return Err(firmware_error(
                FirmwareErrorKind::OperationRegion,
                None,
                "fixed GPE registers require byte access",
            ));
        }
        match address.address_space {
            GenericAddressSpace::SystemIo => {
                let base = u16::try_from(address.address).map_err(|_| {
                    firmware_error(
                        FirmwareErrorKind::OperationRegion,
                        None,
                        "fixed GPE System I/O address exceeds the x86 port range",
                    )
                })?;
                let last_offset = total_bytes
                    .checked_sub(1)
                    .expect("FADT GPE register block cannot be empty");
                base.checked_add(u16::from(last_offset)).ok_or_else(|| {
                    firmware_error(
                        FirmwareErrorKind::OperationRegion,
                        None,
                        "fixed GPE System I/O range exceeds the x86 port range",
                    )
                })?;
                Ok(Self::SystemIo { base })
            }
            GenericAddressSpace::SystemMemory => {
                let virtual_address = address
                    .address
                    .checked_add(crate::mm::virt::mapping::physical_memory_offset())
                    .and_then(|address| usize::try_from(address).ok())
                    .ok_or_else(|| {
                        firmware_error(
                            FirmwareErrorKind::OperationRegion,
                            None,
                            "fixed GPE System Memory address cannot be represented",
                        )
                    })?;
                virtual_address
                    .checked_add(usize::from(
                        total_bytes
                            .checked_sub(1)
                            .expect("FADT GPE register block cannot be empty"),
                    ))
                    .ok_or_else(|| {
                        firmware_error(
                            FirmwareErrorKind::OperationRegion,
                            None,
                            "fixed GPE System Memory range cannot be represented",
                        )
                    })?;
                Ok(Self::SystemMemory {
                    base: virtual_address,
                })
            }
            GenericAddressSpace::Other(space) => Err(firmware_error(
                FirmwareErrorKind::OperationRegion,
                None,
                alloc::format!("unsupported fixed GPE address space {space:#04x}"),
            )),
        }
    }

    fn read(self, offset: usize) -> u8 {
        match self {
            Self::SystemIo { base } => {
                let port = base
                    .checked_add(
                        u16::try_from(offset).expect("fixed GPE register byte offset exceeds u16"),
                    )
                    .expect("validated fixed GPE System I/O range overflowed");
                hal::port_io::inb(port)
            }
            Self::SystemMemory { base } => {
                // SAFETY: construction checked HHDM translation and the FADT
                // owns the fixed register range for the lifetime of the kernel.
                unsafe { core::ptr::read_volatile((base + offset) as *const u8) }
            }
        }
    }

    fn write(self, offset: usize, value: u8) {
        match self {
            Self::SystemIo { base } => {
                let port = base
                    .checked_add(
                        u16::try_from(offset).expect("fixed GPE register byte offset exceeds u16"),
                    )
                    .expect("validated fixed GPE System I/O range overflowed");
                hal::port_io::outb(port, value);
            }
            Self::SystemMemory { base } => {
                // SAFETY: same fixed-register ownership as `read`; volatile
                // byte access also avoids alignment requirements.
                unsafe { core::ptr::write_volatile((base + offset) as *mut u8, value) };
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FixedGpeBlock {
    access: GpeRegisterAccess,
    register_bytes: u8,
    base_number: u16,
}

impl FixedGpeBlock {
    fn from_description(block: GpeRegisterBlock) -> Result<Self, FirmwareError> {
        Ok(Self {
            access: GpeRegisterAccess::new(
                block.address,
                block.register_bytes.checked_mul(2).ok_or_else(|| {
                    firmware_error(
                        FirmwareErrorKind::OperationRegion,
                        None,
                        "fixed GPE register block length overflowed",
                    )
                })?,
            )?,
            register_bytes: block.register_bytes,
            base_number: block.base_number,
        })
    }

    fn location(self, number: GpeNumber) -> Option<(usize, u8)> {
        let relative = number.get().checked_sub(self.base_number)?;
        if relative >= u16::from(self.register_bytes) * 8 {
            return None;
        }
        Some((usize::from(relative / 8), 1 << (relative % 8)))
    }

    fn status(self, byte: usize) -> u8 {
        self.access.read(byte)
    }

    fn enabled(self, byte: usize) -> u8 {
        self.access.read(usize::from(self.register_bytes) + byte)
    }

    fn write_enable(self, byte: usize, value: u8) {
        self.access
            .write(usize::from(self.register_bytes) + byte, value);
    }
}

struct FixedGpeController {
    blocks: Vec<FixedGpeBlock>,
}

impl FixedGpeController {
    fn new(fixed: &FixedEventDescription) -> Result<Self, FirmwareError> {
        let blocks = fixed
            .gpe_blocks
            .iter()
            .copied()
            .map(FixedGpeBlock::from_description)
            .collect::<Result<Vec<_>, _>>()?;
        if blocks.is_empty() {
            return Err(firmware_error(
                FirmwareErrorKind::EventDelivery,
                None,
                "FADT does not describe a fixed GPE register block",
            ));
        }
        Ok(Self { blocks })
    }

    fn capture_asserted(&self, events: &GpeEventMap, mut capture: impl FnMut(GpeEvent)) {
        for block in &self.blocks {
            for byte in 0..usize::from(block.register_bytes) {
                let pending = block.status(byte) & block.enabled(byte);
                for bit in 0..8u8 {
                    if pending & (1 << bit) == 0 {
                        continue;
                    }
                    let number = block.base_number
                        + u16::try_from(byte).expect("fixed GPE register byte index exceeds u16")
                            * 8
                        + u16::from(bit);
                    if let Some(event) = events.get(number) {
                        capture(event);
                    }
                }
            }
        }
    }

    fn mask_all(&self) {
        for block in &self.blocks {
            for byte in 0..usize::from(block.register_bytes) {
                block.write_enable(byte, 0);
            }
        }
    }
}

impl GpeController for FixedGpeController {
    fn mask(&self, number: GpeNumber) {
        if let Some((block, byte, mask)) = self.blocks.iter().find_map(|block| {
            block
                .location(number)
                .map(|(byte, mask)| (*block, byte, mask))
        }) {
            block.write_enable(byte, block.enabled(byte) & !mask);
        }
    }

    fn acknowledge(&self, event: GpeEvent) {
        if let Some((block, byte, mask)) = self.blocks.iter().find_map(|block| {
            block
                .location(event.number)
                .map(|(byte, mask)| (*block, byte, mask))
        }) {
            block.access.write(byte, mask);
        }
    }

    fn unmask(&self, number: GpeNumber) {
        if let Some((block, byte, mask)) = self.blocks.iter().find_map(|block| {
            block
                .location(number)
                .map(|(byte, mask)| (*block, byte, mask))
        }) {
            block.write_enable(byte, block.enabled(byte) | mask);
        }
    }
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

struct AmlOperationRegions;

impl OperationRegionHandler for AmlOperationRegions {
    fn read(
        &self,
        space: OperationRegionSpace,
        base: u64,
        region_length: u64,
        offset: u64,
        width: u8,
    ) -> Result<u64, AmlError> {
        let (address, bytes) = checked_region_access(base, region_length, offset, width)?;
        match space {
            OperationRegionSpace::SystemIo => read_system_io(address, bytes),
            OperationRegionSpace::SystemMemory => read_system_memory(address, bytes),
            _ => Err(AmlError::operation_region(
                "AML OperationRegion address space is unsupported",
            )),
        }
    }

    fn write(
        &self,
        space: OperationRegionSpace,
        base: u64,
        region_length: u64,
        offset: u64,
        width: u8,
        value: u64,
    ) -> Result<(), AmlError> {
        let (address, bytes) = checked_region_access(base, region_length, offset, width)?;
        if bytes < core::mem::size_of::<u64>() && value >= (1u64 << (bytes * 8)) {
            return Err(AmlError::operation_region(
                "AML OperationRegion value exceeds the requested access width",
            ));
        }
        match space {
            OperationRegionSpace::SystemIo => write_system_io(address, bytes, value),
            OperationRegionSpace::SystemMemory => write_system_memory(address, bytes, value),
            _ => Err(AmlError::operation_region(
                "AML OperationRegion address space is unsupported",
            )),
        }
    }
}

fn checked_region_access(
    base: u64,
    region_length: u64,
    offset: u64,
    width: u8,
) -> Result<(u64, usize), AmlError> {
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(AmlError::operation_region(
            "AML OperationRegion access width is unsupported",
        ));
    }
    let bytes = usize::from(width / 8);
    let bytes_u64 = u64::try_from(bytes)
        .map_err(|_| AmlError::operation_region("AML access width cannot be represented"))?;
    if offset
        .checked_add(bytes_u64)
        .is_none_or(|end| end > region_length)
    {
        return Err(AmlError::operation_region(
            "AML OperationRegion access exceeds its declared range",
        ));
    }
    let address = base
        .checked_add(offset)
        .ok_or_else(|| AmlError::operation_region("AML OperationRegion address overflowed"))?;
    Ok((address, bytes))
}

fn read_system_io(address: u64, bytes: usize) -> Result<u64, AmlError> {
    let port = u16::try_from(address).map_err(|_| {
        AmlError::operation_region("AML System I/O address exceeds the x86 port range")
    })?;
    match bytes {
        1 => Ok(u64::from(hal::port_io::inb(port))),
        2 => Ok(u64::from(hal::port_io::inw(port))),
        4 => Ok(u64::from(hal::port_io::inl(port))),
        _ => Err(AmlError::operation_region(
            "64-bit AML System I/O access is unsupported",
        )),
    }
}

fn write_system_io(address: u64, bytes: usize, value: u64) -> Result<(), AmlError> {
    let port = u16::try_from(address).map_err(|_| {
        AmlError::operation_region("AML System I/O address exceeds the x86 port range")
    })?;
    match bytes {
        1 => hal::port_io::outb(
            port,
            u8::try_from(value).expect("validated AML byte access value exceeds u8"),
        ),
        2 => hal::port_io::outw(
            port,
            u16::try_from(value).expect("validated AML word access value exceeds u16"),
        ),
        4 => hal::port_io::outl(
            port,
            u32::try_from(value).expect("validated AML dword access value exceeds u32"),
        ),
        _ => {
            return Err(AmlError::operation_region(
                "64-bit AML System I/O access is unsupported",
            ));
        }
    }
    Ok(())
}

fn read_system_memory(address: u64, bytes: usize) -> Result<u64, AmlError> {
    let base = region_virtual_address(address, bytes)?;
    let mut value = 0u64;
    for index in 0..bytes {
        // SAFETY: HHDM translation and range arithmetic were checked above;
        // byte-wise volatile access has no alignment requirement.
        let byte = unsafe { core::ptr::read_volatile((base + index) as *const u8) };
        value |= u64::from(byte) << (index * 8);
    }
    Ok(value)
}

fn write_system_memory(address: u64, bytes: usize, value: u64) -> Result<(), AmlError> {
    let base = region_virtual_address(address, bytes)?;
    for index in 0..bytes {
        // SAFETY: same validated HHDM range as `read_system_memory`.
        unsafe {
            core::ptr::write_volatile(
                (base + index) as *mut u8,
                u8::try_from((value >> (index * 8)) & u64::from(u8::MAX))
                    .expect("masked AML byte cannot exceed u8"),
            )
        };
    }
    Ok(())
}

fn region_virtual_address(address: u64, bytes: usize) -> Result<usize, AmlError> {
    let bytes_u64 = u64::try_from(bytes)
        .map_err(|_| AmlError::operation_region("AML access width cannot be represented"))?;
    let end = address
        .checked_add(bytes_u64)
        .ok_or_else(|| AmlError::operation_region("AML System Memory range overflowed"))?;
    let offset = crate::mm::virt::mapping::physical_memory_offset();
    let base = address.checked_add(offset).ok_or_else(|| {
        AmlError::operation_region("AML System Memory HHDM translation overflowed")
    })?;
    let virtual_end = end
        .checked_add(offset)
        .ok_or_else(|| AmlError::operation_region("AML System Memory HHDM range overflowed"))?;
    let base = usize::try_from(base)
        .map_err(|_| AmlError::operation_region("AML System Memory address exceeds usize"))?;
    let virtual_end = usize::try_from(virtual_end)
        .map_err(|_| AmlError::operation_region("AML System Memory range exceeds usize"))?;
    if base.checked_add(bytes) != Some(virtual_end) {
        return Err(AmlError::operation_region(
            "AML System Memory range is not contiguous after translation",
        ));
    }
    Ok(base)
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
