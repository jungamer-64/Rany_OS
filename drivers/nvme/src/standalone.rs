//! Cell lifecycle and block publication. The asynchronous host owns this driver
//! through acknowledged removal. Every controller state is stored in that owner
//! before waiting, so cancellation retains published queues and mappings.
//! The staged PCI host claims and enables this function before probe; the cell
//! owns controller activation and proves CC.EN/CSTS.RDY clear before DMA close.
//! PCI decoding and bus-master policy remain with that host.

use alloc::boxed::Box;
use core::num::NonZeroU16;
use core::sync::atomic::{AtomicU64, Ordering};
use exorust_sync::Mutex;
use kernel_api::abi::driver::{
    AbiBlockCompletion, AbiBlockDeviceInfo, AbiBlockDeviceRegistration, AbiBlockQueueInfo,
    AbiBlockSubmission, AbiBlockSubmitOutcome, AbiError, AbiNvmeNamespaceInfo,
    AbiNvmeNamespaceRegistration, DriverContext, PackedPciLocation,
};
use kernel_api::dma::{CpuDmaLease, DmaAllocationRequest, DmaCloseError, DmaDirection};
use kernel_api::driver::{AsyncDriver, DriverType};
use kernel_api::{KapiError, KapiResult};

use crate::protocol::{NvmeCommand, PAGE_BYTES};
use crate::*;

const QUEUE_DEPTH: u16 = 64;
const ADMIN_TIMEOUT_MS: u64 = 30_000;
// Resource generations reserve a second value for retirement, without wrap.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

struct Waiting<T> {
    owner: T,
    deadline: u64,
}

enum Failure {
    Acquire(ControllerAcquireError),
    Disable(ControllerDisableError),
    Install(AdminQueueInstallError),
    Enable(ControllerEnableError),
    IdentifySubmit(IdentifySubmitError),
    Identify(IdentifyNamespaceError),
    Budget(QueueBudgetError),
    Create(QueueCreateError),
    ResetStart(ControllerResetStartError),
    ResetPoll(ControllerResetPollError),
    IdleClose(crate::shutdown::IdleControllerCloseError),
    Service(KapiError),
}

impl core::fmt::Debug for Failure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Acquire(cause) => formatter.debug_tuple("Acquire").field(cause).finish(),
            Self::Disable(cause) => formatter.debug_tuple("Disable").field(cause).finish(),
            Self::Install(cause) => formatter.debug_tuple("Install").field(cause).finish(),
            Self::Enable(cause) => formatter.debug_tuple("Enable").field(cause).finish(),
            Self::IdentifySubmit(cause) => formatter
                .debug_tuple("IdentifySubmit")
                .field(cause)
                .finish(),
            Self::Identify(cause) => formatter.debug_tuple("Identify").field(cause).finish(),
            Self::Budget(cause) => formatter.debug_tuple("Budget").field(cause).finish(),
            Self::Create(cause) => formatter.debug_tuple("Create").field(cause).finish(),
            Self::ResetStart(cause) => formatter.debug_tuple("ResetStart").field(cause).finish(),
            Self::ResetPoll(cause) => formatter.debug_tuple("ResetPoll").field(cause).finish(),
            Self::IdleClose(cause) => formatter.debug_tuple("IdleClose").field(cause).finish(),
            Self::Service(cause) => formatter.debug_tuple("Service").field(cause).finish(),
        }
    }
}

enum Phase {
    Acquiring,
    Disabled(ControllerDisabled),
    Disabling(Waiting<ControllerDisabling>),
    Enabling(Waiting<ControllerEnabling>),
    Admin(NvmeAdminController),
    Identifying(Waiting<IdentifyNamespaceRequest>),
    Identified(NvmeAdminController, NamespaceInfo),
    Budget(Waiting<QueueBudgetRequest>, NamespaceInfo),
    Provisioning(IoQueueProvisioner, NamespaceInfo),
    Creating(Waiting<IoQueueCreation>, NamespaceInfo),
    Ready(NvmeController, NamespaceInfo),
    Resetting(Waiting<ControllerResetting>),
    Reset(ControllerReset),
    Closed,
    Failed(Failure),
    CompletionFault {
        controller: NvmeController,
        namespace: NamespaceInfo,
        command: CompletedCommand,
    },
    Transitioning,
}

struct OwnedState {
    phase: Phase,
    depth: u16,
    controller_timeout_ms: u64,
    // Only an allocation rollback or the Identify buffer can enter this slot.
    // Either failure terminates bootstrap before another close is attempted.
    retained_close: Option<DmaCloseError>,
}

struct Runtime {
    device: PackedPciLocation,
    generation: u64,
    state: Mutex<OwnedState>,
}

struct NvmeCell {
    runtime: Option<Box<Runtime>>,
    block_handle: Option<u64>,
    namespace_handle: Option<u64>,
}

impl NvmeCell {
    fn new() -> Self {
        Self {
            runtime: None,
            block_handle: None,
            namespace_handle: None,
        }
    }
}

impl OwnedState {
    fn fail(&mut self, cause: Failure) -> KapiError {
        log::error!("NVMe controller retained after failure: {cause:?}");
        self.phase = Phase::Failed(cause);
        KapiError::IoError
    }

    fn close_cpu(&mut self, lease: CpuDmaLease) -> KapiResult<()> {
        match lease.close() {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.retained_close = Some(cause);
                Err(KapiError::IoError)
            }
        }
    }

    fn allocate_pair(&mut self, device: PackedPciLocation) -> KapiResult<QueueMemory> {
        let submission = allocate(device, usize::from(self.depth) * 64, DmaDirection::ToDevice)?;
        match allocate(
            device,
            usize::from(self.depth) * 16,
            DmaDirection::FromDevice,
        ) {
            Ok(completion) => Ok(QueueMemory {
                submission,
                completion,
            }),
            Err(cause) => {
                // The allocation error remains the operation's cause. A failed
                // rollback retains its separate finalization owner.
                let _closed = self.close_cpu(submission);
                Err(cause)
            }
        }
    }

    fn advance_boot(&mut self, device: PackedPciLocation, now: u64) -> KapiResult<bool> {
        if self.retained_close.is_some() {
            return Err(KapiError::Busy);
        }
        let admin_deadline = now.checked_add(ADMIN_TIMEOUT_MS).ok_or(KapiError::Timer(
            kernel_api::service::time::TimerError::ClockExhausted,
        ))?;
        let controller_deadline =
            now.checked_add(self.controller_timeout_ms)
                .ok_or(KapiError::Timer(
                    kernel_api::service::time::TimerError::ClockExhausted,
                ))?;
        let phase = core::mem::replace(&mut self.phase, Phase::Transitioning);
        self.phase = match phase {
            Phase::Disabling(wait) => {
                if now >= wait.deadline {
                    self.phase = Phase::Disabling(wait);
                    return Err(KapiError::Timeout);
                }
                match wait.owner.poll() {
                    Ok(ControllerDisablePoll::Waiting(owner)) => Phase::Disabling(Waiting {
                        owner,
                        deadline: wait.deadline,
                    }),
                    Ok(ControllerDisablePoll::Disabled(owner)) => Phase::Disabled(owner),
                    Err(cause) => return Err(self.fail(Failure::Disable(cause))),
                }
            }
            Phase::Disabled(owner) => {
                let memory = match self.allocate_pair(device) {
                    Ok(memory) => memory,
                    Err(cause) => {
                        self.phase = Phase::Disabled(owner);
                        return Err(cause);
                    }
                };
                match owner.install_admin_queue(self.depth, memory) {
                    Ok(owner) => Phase::Enabling(Waiting {
                        owner,
                        deadline: controller_deadline,
                    }),
                    Err(cause) => return Err(self.fail(Failure::Install(cause))),
                }
            }
            Phase::Enabling(wait) => {
                if now >= wait.deadline {
                    self.phase = Phase::Enabling(wait);
                    return Err(KapiError::Timeout);
                }
                match wait.owner.poll() {
                    Ok(ControllerEnablePoll::Waiting(owner)) => Phase::Enabling(Waiting {
                        owner,
                        deadline: wait.deadline,
                    }),
                    Ok(ControllerEnablePoll::Ready(owner)) => Phase::Admin(owner),
                    Err(cause) => return Err(self.fail(Failure::Enable(cause))),
                }
            }
            Phase::Admin(owner) => {
                let memory = match allocate(device, PAGE_BYTES, DmaDirection::FromDevice) {
                    Ok(memory) => memory,
                    Err(cause) => {
                        self.phase = Phase::Admin(owner);
                        return Err(cause);
                    }
                };
                match owner.identify_namespace(1, memory) {
                    Ok(owner) => Phase::Identifying(Waiting {
                        owner,
                        deadline: admin_deadline,
                    }),
                    Err(cause) => return Err(self.fail(Failure::IdentifySubmit(cause))),
                }
            }
            Phase::Identifying(wait) => {
                if now >= wait.deadline {
                    self.phase = Phase::Identifying(wait);
                    return Err(KapiError::Timeout);
                }
                match wait.owner.poll() {
                    Ok(IdentifyNamespacePoll::Waiting(owner)) => Phase::Identifying(Waiting {
                        owner,
                        deadline: wait.deadline,
                    }),
                    Ok(IdentifyNamespacePoll::Ready(result)) => {
                        let (owner, namespace, memory) = result.into_parts();
                        self.phase = Phase::Identified(owner, namespace);
                        self.close_cpu(memory)?;
                        return Ok(false);
                    }
                    Err(cause) => return Err(self.fail(Failure::Identify(cause))),
                }
            }
            Phase::Identified(owner, namespace) => match owner.request_io_queues(NonZeroU16::MIN) {
                Ok(owner) => Phase::Budget(
                    Waiting {
                        owner,
                        deadline: admin_deadline,
                    },
                    namespace,
                ),
                Err(cause) => return Err(self.fail(Failure::Budget(cause))),
            },
            Phase::Budget(wait, namespace) => {
                if now >= wait.deadline {
                    self.phase = Phase::Budget(wait, namespace);
                    return Err(KapiError::Timeout);
                }
                match wait.owner.poll() {
                    Ok(QueueBudgetPoll::Waiting(owner)) => Phase::Budget(
                        Waiting {
                            owner,
                            deadline: wait.deadline,
                        },
                        namespace,
                    ),
                    Ok(QueueBudgetPoll::Ready(owner)) => Phase::Provisioning(owner, namespace),
                    Err(cause) => return Err(self.fail(Failure::Budget(cause))),
                }
            }
            Phase::Provisioning(owner, namespace) => {
                let memory = match self.allocate_pair(device) {
                    Ok(memory) => memory,
                    Err(cause) => {
                        self.phase = Phase::Provisioning(owner, namespace);
                        return Err(cause);
                    }
                };
                match owner.begin_next_queue(self.depth, memory) {
                    Ok(owner) => Phase::Creating(
                        Waiting {
                            owner,
                            deadline: admin_deadline,
                        },
                        namespace,
                    ),
                    Err(cause) => return Err(self.fail(Failure::Create(cause))),
                }
            }
            Phase::Creating(wait, namespace) => {
                if now >= wait.deadline {
                    self.phase = Phase::Creating(wait, namespace);
                    return Err(KapiError::Timeout);
                }
                match wait.owner.poll() {
                    Ok(IoQueueCreatePoll::Waiting(owner)) => Phase::Creating(
                        Waiting {
                            owner,
                            deadline: wait.deadline,
                        },
                        namespace,
                    ),
                    Ok(IoQueueCreatePoll::Ready(owner)) => match owner.finish() {
                        Ok(owner) => Phase::Ready(owner, namespace),
                        Err(owner) => {
                            self.phase = Phase::Provisioning(*owner, namespace);
                            return Err(KapiError::Busy);
                        }
                    },
                    Err(cause) => return Err(self.fail(Failure::Create(cause))),
                }
            }
            Phase::Ready(owner, namespace) => {
                self.phase = Phase::Ready(owner, namespace);
                return Ok(true);
            }
            Phase::Failed(cause) => {
                self.phase = Phase::Failed(cause);
                return Err(KapiError::Busy);
            }
            other => {
                self.phase = other;
                return Err(KapiError::Busy);
            }
        };
        Ok(false)
    }
}

fn allocate(
    device: PackedPciLocation,
    bytes: usize,
    direction: DmaDirection,
) -> KapiResult<CpuDmaLease> {
    let request = DmaAllocationRequest::new(bytes, direction).ok_or(KapiError::InvalidHandle)?;
    kernel_api::service::kernel::instance().alloc_dma_for_device(request, device)
}

impl AsyncDriver for NvmeCell {
    fn name(&self) -> &str {
        "nvme"
    }
    fn driver_type(&self) -> DriverType {
        DriverType::Block
    }

    async fn probe(&mut self, context: &mut DriverContext) -> KapiResult<()> {
        if self.runtime.is_some() {
            return Err(KapiError::AlreadyExists);
        }
        let device = context.pci_location();
        if device.is_null() || device.segment() != 0 {
            return Err(KapiError::NotSupported);
        }
        let generation = NEXT_GENERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(2)
            })
            .map_err(|_| KapiError::ResourceExhausted)?;
        let timer = kernel_api::service::time::try_instance().ok_or(KapiError::Timer(
            kernel_api::service::time::TimerError::ServiceUnavailable,
        ))?;
        // Stable callback storage is admitted before mapping or DMA effects.
        self.runtime = Some(
            Box::try_new(Runtime {
                device,
                generation,
                state: Mutex::new(OwnedState {
                    phase: Phase::Acquiring,
                    depth: QUEUE_DEPTH,
                    controller_timeout_ms: 500,
                    retained_close: None,
                }),
            })
            .map_err(|_| KapiError::OutOfMemory)?,
        );
        let runtime = self.runtime.as_ref().ok_or(KapiError::NotFound)?;
        let begin = (|| {
            let request =
                kernel_api::mmio::PciMmioRequest::whole_bar(device, 0).map_err(|cause| {
                    KapiError::Mmio(kernel_api::mmio::MmioAcquireError::Request(cause))
                })?;
            let mapping = kernel_api::service::kernel::instance()
                .acquire_pci_mmio(request)
                .map_err(KapiError::Mmio)?;
            let mut state = runtime.state.lock();
            let acquire = match ControllerAcquire::begin(mapping, device, generation) {
                Ok(owner) => owner,
                Err(cause) => return Err(state.fail(Failure::Acquire(cause))),
            };
            let caps = acquire.capabilities();
            // The selected depth is bounded by QUEUE_DEPTH, which fits u16.
            state.depth = caps.max_queue_entries().min(u32::from(QUEUE_DEPTH)) as u16;
            state.controller_timeout_ms = u64::from(caps.timeout_units().max(1)) * 500;
            let deadline = timer
                .current_tick_ms()
                .checked_add(state.controller_timeout_ms);
            state.phase = match acquire {
                ControllerAcquire::Disabled(owner) => Phase::Disabled(owner),
                ControllerAcquire::Disabling(owner) => Phase::Disabling(Waiting {
                    owner,
                    deadline: deadline.unwrap_or(u64::MAX),
                }),
            };
            if deadline.is_none() {
                return Err(KapiError::Timer(
                    kernel_api::service::time::TimerError::ClockExhausted,
                ));
            }
            Ok(())
        })();
        if let Err(cause) = begin {
            let mut state = runtime.state.lock();
            if matches!(state.phase, Phase::Acquiring) {
                state.phase = Phase::Failed(Failure::Service(cause));
            }
            return Err(cause);
        }
        // LOOP_PROOF: mode=event; reason=Each bounded observation stores its controller owner before a timer wait, and readiness, failure or the retained deadline ends bootstrap.;
        loop {
            if runtime
                .state
                .lock()
                .advance_boot(device, timer.current_tick_ms())?
            {
                return Ok(());
            }
            kernel_api::service::time::SleepFuture::new(timer, 1)
                .await
                .map_err(KapiError::Timer)?;
        }
    }

    async fn start(&mut self) -> KapiResult<()> {
        let runtime = self.runtime.as_ref().ok_or(KapiError::NotFound)?;
        let (registration, namespace_registration) = {
            let state = runtime.state.lock();
            let Phase::Ready(controller, namespace) = &state.phase else {
                return Err(KapiError::Busy);
            };
            let queue = controller.queue(1).ok_or(KapiError::NotFound)?;
            let max_blocks = u32::try_from(PAGE_BYTES).map_err(|_| KapiError::InvalidHandle)?
                / namespace.block_size();
            if max_blocks == 0 {
                return Err(KapiError::NotSupported);
            }
            let info = AbiBlockDeviceInfo {
                device_id: runtime.device.0,
                namespace_id: namespace.namespace(),
                block_size: namespace.block_size(),
                block_count: namespace.block_count(),
                max_transfer_blocks: max_blocks,
                transport: 1,
                flags: 0,
                controller_id: 0,
                port_id: 0,
            };
            let registration = AbiBlockDeviceRegistration {
                abi_size: core::mem::size_of::<AbiBlockDeviceRegistration>() as u64,
                info,
                queue: AbiBlockQueueInfo {
                    device: runtime.device,
                    index: 1,
                    capacity: queue.depth() - 1,
                    generation: runtime.generation,
                },
                opaque: core::ptr::from_ref(runtime.as_ref()).expose_provenance() as u64,
                submit,
                poll,
                is_ready,
                stop,
            };
            let namespace_registration = AbiNvmeNamespaceRegistration::new(AbiNvmeNamespaceInfo {
                device_id: info.device_id,
                namespace_id: info.namespace_id,
                block_size: info.block_size,
                max_transfer_blocks: info.max_transfer_blocks,
                max_sgl_entries: 1,
                total_blocks: info.block_count,
                controller_id: info.controller_id,
                flags: 0,
            });
            (registration, namespace_registration)
        };
        let kernel = kernel_api::service::kernel::instance();
        if self.block_handle.is_none() {
            self.block_handle = Some(kernel.register_block_device(&registration)?);
        }
        if self.namespace_handle.is_none() {
            self.namespace_handle = Some(kernel.register_nvme_namespace(&namespace_registration)?);
        }
        Ok(())
    }

    async fn stop(&mut self) -> KapiResult<()> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(());
        };
        let kernel = kernel_api::service::kernel::instance();
        if let Some(handle) = self.namespace_handle {
            kernel.unregister_nvme_namespace(handle)?;
            self.namespace_handle = None;
        }
        let timer = kernel_api::service::time::try_instance().ok_or(KapiError::Timer(
            kernel_api::service::time::TimerError::ServiceUnavailable,
        ))?;
        let deadline = timer
            .current_tick_ms()
            .checked_add(ADMIN_TIMEOUT_MS)
            .ok_or(KapiError::Timer(
                kernel_api::service::time::TimerError::ClockExhausted,
            ))?;
        // LOOP_PROOF: mode=event; reason=Shutdown advances one owned retirement step per timer wait, and completion, retained failure or the bounded deadline ends the operation.;
        loop {
            let outcome = match self.block_handle {
                Some(handle) => kernel.unregister_block_device(handle),
                None => runtime.advance_stop(timer.current_tick_ms()),
            };
            match outcome {
                Ok(()) => {
                    self.block_handle = None;
                    return Ok(());
                }
                Err(KapiError::Busy) if timer.current_tick_ms() < deadline => {}
                Err(cause) => return Err(cause),
            }
            kernel_api::service::time::SleepFuture::new(timer, 1)
                .await
                .map_err(KapiError::Timer)?;
        }
    }

    async fn remove(&mut self) -> KapiResult<()> {
        self.stop().await?;
        self.runtime = None;
        Ok(())
    }
}

impl Runtime {
    fn advance_stop(&self, now: u64) -> KapiResult<()> {
        let mut state = self.state.lock();
        if state.retained_close.is_some() {
            return Err(KapiError::Busy);
        }
        let deadline = now
            .checked_add(state.controller_timeout_ms)
            .ok_or(KapiError::Timer(
                kernel_api::service::time::TimerError::ClockExhausted,
            ))?;
        let phase = core::mem::replace(&mut state.phase, Phase::Transitioning);
        state.phase = match phase {
            Phase::Ready(controller, namespace) => {
                if controller.admin_queue.outstanding() != 0
                    || controller
                        .io_queues
                        .iter()
                        .any(|queue| queue.outstanding() != 0)
                {
                    state.phase = Phase::Ready(controller, namespace);
                    return Err(KapiError::Busy);
                }
                match controller.begin_reset(self.generation + 1) {
                    Ok(owner) => Phase::Resetting(Waiting { owner, deadline }),
                    Err(cause) => return Err(state.fail(Failure::ResetStart(cause))),
                }
            }
            Phase::Resetting(wait) => {
                if now >= wait.deadline {
                    state.phase = Phase::Resetting(wait);
                    return Err(KapiError::Timeout);
                }
                match wait.owner.poll() {
                    Ok(ControllerResetPoll::Waiting(owner)) => Phase::Resetting(Waiting {
                        owner,
                        deadline: wait.deadline,
                    }),
                    Ok(ControllerResetPoll::Reset(owner)) => Phase::Reset(owner),
                    Err(cause) => return Err(state.fail(Failure::ResetPoll(cause))),
                }
            }
            Phase::Reset(owner) => match owner.close_idle() {
                Ok(()) => Phase::Closed,
                Err(cause) => return Err(state.fail(Failure::IdleClose(cause))),
            },
            Phase::Closed => {
                state.phase = Phase::Closed;
                return Ok(());
            }
            Phase::CompletionFault {
                controller,
                namespace,
                command,
            } => {
                log::error!(
                    "NVMe {} namespace {} retained unexpected completion: {:?}",
                    controller.device().raw(),
                    namespace.namespace(),
                    command
                );
                state.phase = Phase::CompletionFault {
                    controller,
                    namespace,
                    command,
                };
                return Err(KapiError::IoError);
            }
            other => {
                state.phase = other;
                return Err(KapiError::Busy);
            }
        };
        Err(KapiError::Busy)
    }
}

// Foreign callbacks borrow a stable Runtime retained by NvmeCell until both
// registrations acknowledge retirement. The block host serializes operations.
#[expect(
    unsafe_code,
    reason = "the block ABI lends the registered runtime for the synchronous callback"
)]
unsafe fn runtime<'a>(opaque: u64) -> &'a Runtime {
    // SAFETY: callbacks use the original Box address while its registered host
    // and driver lifecycle owner keep the Box alive through acknowledged stop.
    unsafe { &*core::ptr::with_exposed_provenance::<Runtime>(opaque as usize) }
}

#[expect(
    unsafe_code,
    reason = "borrows ABI publication data and invokes its one-use activation before the doorbell"
)]
unsafe extern "C" fn submit(
    opaque: u64,
    input: *const AbiBlockSubmission,
) -> AbiBlockSubmitOutcome {
    if opaque == 0 || input.is_null() {
        return AbiBlockSubmitOutcome::rejected(AbiError::InvalidParam);
    }
    // SAFETY: both borrows last only for this serialized synchronous callback.
    let runtime = unsafe { runtime(opaque) };
    // SAFETY: the host lends one initialized submission until this call returns.
    let input = unsafe { &*input };
    let state = runtime.state.lock();
    let Phase::Ready(controller, namespace) = &state.phase else {
        return AbiBlockSubmitOutcome::rejected(AbiError::DeviceBusy);
    };
    let Some(queue) = controller.queue(1) else {
        return AbiBlockSubmitOutcome::rejected(AbiError::DeviceNotFound);
    };
    let command = match namespace.admit_submission(input) {
        Ok(command) => command,
        Err(cause) => return AbiBlockSubmitOutcome::rejected(cause),
    };
    let notification = CompletionNotification {
        request_id: input.request_id,
        lease_id: input.lease_id,
        generation: input.generation,
        bytes: input.bytes,
    };
    let mut activation_status = AbiError::Success as i32;
    let outcome = queue.submit_notified(
        &controller.registers,
        |cid| match command {
            crate::identify::BlockCommand::Transfer {
                transfer,
                address,
                prp2,
            } => Some(NvmeCommand::transfer(cid, transfer, address, prp2)),
            crate::identify::BlockCommand::Flush => NvmeCommand::flush(cid, namespace.namespace()),
        },
        notification,
        || {
            // SAFETY: all descriptor/CID storage is reserved, no hardware has been
            // notified, and this unique cookie is invoked once before return.
            activation_status = unsafe { (input.activate)(input.activation) };
            if activation_status == AbiError::Success as i32 {
                Ok(())
            } else {
                Err(SubmitFailure::QueueFault)
            }
        },
    );
    match outcome {
        Ok(_) => AbiBlockSubmitOutcome::accepted(),
        Err(cause) => {
            AbiBlockSubmitOutcome::rejected(if activation_status != AbiError::Success as i32 {
                AbiError::from_raw(activation_status)
            } else {
                submission_error(cause)
            })
        }
    }
}

fn submission_error(cause: SubmitFailure) -> AbiError {
    match cause {
        SubmitFailure::QueueFull => AbiError::DeviceBusy,
        SubmitFailure::InvalidQueue | SubmitFailure::InvalidTransfer => AbiError::InvalidParam,
        SubmitFailure::QueueFault | SubmitFailure::Register(_) | SubmitFailure::Dma(_) => {
            AbiError::IoError
        }
    }
}

#[expect(
    unsafe_code,
    reason = "writes only the validated completion prefix into the host's borrowed output buffer"
)]
unsafe extern "C" fn poll(
    opaque: u64,
    output: *mut AbiBlockCompletion,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if opaque == 0 || written.is_null() || (capacity != 0 && output.is_null()) {
        return AbiError::InvalidParam as i32;
    }
    // SAFETY: the ABI lends one writable count for this call.
    unsafe {
        written.write(0);
    }
    // SAFETY: the registration retains the runtime through this callback.
    let runtime = unsafe { runtime(opaque) };
    let mut state = runtime.state.lock();
    for index in 0..capacity.min(usize::from(state.depth - 1)) {
        let Phase::Ready(controller, _) = &state.phase else {
            return AbiError::DeviceBusy as i32;
        };
        let completed = match controller.poll_completion(1) {
            Ok(Some(completed)) => completed,
            Ok(None) => break,
            Err(cause) => {
                log::error!("NVMe completion retained after queue fault: {cause:?}");
                return AbiError::IoError as i32;
            }
        };
        let CompletedCommand::Notification {
            completion,
            notification,
        } = completed
        else {
            // No native submissions enter this runtime. Retain an unexpected
            // consumed owner instead of manufacturing a host notification.
            let phase = core::mem::replace(&mut state.phase, Phase::Transitioning);
            let Phase::Ready(controller, namespace) = phase else {
                unreachable!("the state lock retains the Ready phase through CQ consumption");
            };
            state.phase = Phase::CompletionFault {
                controller,
                namespace,
                command: completed,
            };
            return AbiError::IoError as i32;
        };
        let result = AbiBlockCompletion {
            request_id: notification.request_id,
            lease_id: notification.lease_id,
            generation: notification.generation,
            status: if completion.status().is_success() {
                AbiError::Success
            } else {
                AbiError::IoError
            } as i32,
            bytes: if completion.status().is_success() {
                notification.bytes
            } else {
                0
            },
        };
        // SAFETY: index is within the borrowed capacity, and each initialized
        // entry is reported before another completion can be consumed.
        unsafe {
            output.add(index).write(result);
        }
        // SAFETY: the same unique output count remains valid through the call.
        unsafe {
            written.write(index + 1);
        }
    }
    AbiError::Success as i32
}

#[expect(
    unsafe_code,
    reason = "observes readiness while the registration retains its runtime"
)]
extern "C" fn is_ready(opaque: u64) -> bool {
    if opaque == 0 {
        return false;
    }
    // SAFETY: the block host retains the registered opaque and driver code.
    let runtime = unsafe { runtime(opaque) };
    let state = runtime.state.lock();
    matches!(&state.phase, Phase::Ready(controller, _) if controller.queue(1).is_some_and(|queue| queue.outstanding() != 0))
}

#[expect(
    unsafe_code,
    reason = "advances one retirement observation for the host-owned runtime"
)]
unsafe extern "C" fn stop(opaque: u64) -> i32 {
    if opaque == 0 {
        return AbiError::InvalidParam as i32;
    }
    // SAFETY: the host retains its registration until this stop succeeds.
    let runtime = unsafe { runtime(opaque) };
    let Some(timer) = kernel_api::service::time::try_instance() else {
        return AbiError::IoError as i32;
    };
    match runtime.advance_stop(timer.current_tick_ms()) {
        Ok(()) => AbiError::Success as i32,
        Err(KapiError::Busy) => AbiError::DeviceBusy as i32,
        Err(KapiError::Timeout) => AbiError::Timeout as i32,
        Err(_) => AbiError::IoError as i32,
    }
}

#[allow(
    unsafe_code,
    reason = "export_async_driver generates the permanent foreign lifecycle callbacks and vtable symbols"
)]
mod exports {
    use super::*;
    kernel_api::export_async_driver! {
        type: NvmeCell,
        constructor: NvmeCell::new(),
        name: || b"nvme",
        driver_type: DriverType::Block,
        version: kernel_api::abi::driver::pack_version(0, 1, 0)
    }
}
pub use exports::standalone_driver_vtable;
