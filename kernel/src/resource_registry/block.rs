//! The block ABI borrows descriptors while this host retains transfer ownership.
//! A queue callback owns a nonblocking gate, never a kernel lock across driver
//! code. Closing admission retains pending routes, DMA owners, and callback code
//! until terminal completions and the driver's explicit stop have finished.

use super::{AbiErrorCode, CallbackOwner, DomainId, PoisonLock, map_io_status};
use crate::domain::registry::ResourceInvocation;
use crate::io::io_scheduler::{
    BlockGeometry, DeviceCompletion, DeviceOps, IoCommand, IoCompletion, IoCompletionRoute,
    IoError, IoOperationType, IoResult, IoSubmission, IoSubmitOutcome, PollHandler,
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU8, Ordering};
use kernel_api::abi::driver::{
    AbiBlockCommandKind, AbiBlockCompletion, AbiBlockDeviceRegistration, AbiBlockDisposition,
    AbiBlockSubmission, AbiDmaStatus,
};
use kernel_api::dma::{
    CompletedDmaLease, CpuDmaLease, DmaAllocationRequest, DmaCompletionWitness, DmaDirection,
    DmaQueueIdentity, InFlightDmaLease, PreparedDmaLease,
};

const OPEN: u8 = 0;
const CALLING: u8 = 1;
const CLOSING: u8 = 2;
const CLOSING_CALLING: u8 = 3;
const STOPPED: u8 = 4;
const COMPLETION_BATCH: usize = 32;

/// Publication is serialized per hardware queue; preempted callbacks retain
/// the gate and another task receives Busy instead of spinning on that task.
struct CallbackGate<'a>(&'a AtomicU8);

impl Drop for CallbackGate<'_> {
    fn drop(&mut self) {
        let result = self
            .0
            .try_update(Ordering::Release, Ordering::Relaxed, |phase| match phase {
                CALLING => Some(OPEN),
                CLOSING_CALLING => Some(CLOSING),
                _ => None,
            });
        // STOPPED is terminal and needs no release transition.
        if let Err(phase) = result {
            debug_assert_eq!(phase, STOPPED);
        }
    }
}

enum TransferOwner {
    Prepared(PreparedDmaLease),
    InFlight(InFlightDmaLease),
    Completed {
        lease: CompletedDmaLease,
        result: Result<usize, IoError>,
    },
    /// The hardware proof was consumed by a failed authority transition. This
    /// owner blocks runtime destruction until explicit reset reconciliation.
    CompletionUnrestored {
        _lease: InFlightDmaLease,
    },
}

enum CompletionRoute {
    Waiting(IoCompletionRoute),
    /// An uncertain outcome has already consumed the sole notification route.
    /// A later hardware completion can retire the buffer but cannot report twice.
    Reported,
}

struct PendingBlock {
    request_id: u64,
    route: CompletionRoute,
    operation: IoOperationType,
    transfer: Option<TransferOwner>,
    bytes: usize,
}

enum Slot {
    Empty,
    Reserved,
    Pending(PendingBlock),
}

/// Only the synchronous activation callback can cross Prepared -> InFlight.
/// Its cookie is a borrow of this stack frame, retained by neither driver nor ISR.
enum Activation {
    ControlPrepared,
    ControlActive,
    Prepared(PreparedDmaLease),
    Active(InFlightDmaLease),
    /// Storage while moving the linear capability through an authority call.
    Transitioning,
}

/// # Safety
/// The enclosing submission owns an exclusive live Activation at `cookie`.
/// The driver may call once synchronously after reserving publication resources.
unsafe extern "C" fn activate(cookie: *mut c_void) -> i32 {
    // SAFETY: submit supplies one exclusive Activation for this synchronous
    // callback, and the ABI forbids retaining or concurrently using the cookie.
    let activation = unsafe { &mut *cookie.cast::<Activation>() };
    match core::mem::replace(activation, Activation::Transitioning) {
        Activation::ControlPrepared => {
            *activation = Activation::ControlActive;
            AbiDmaStatus::Success as i32
        }
        Activation::Prepared(lease) => match lease.arm() {
            Ok(lease) => {
                *activation = Activation::Active(lease);
                AbiDmaStatus::Success as i32
            }
            Err(error) => {
                let (cause, lease) = error.into_parts();
                *activation = Activation::Prepared(lease);
                AbiDmaStatus::from_result(Err(cause)) as i32
            }
        },
        other => {
            *activation = other;
            AbiDmaStatus::InvalidState as i32
        }
    }
}

pub(super) struct BlockDeviceAdapter {
    registration: AbiBlockDeviceRegistration,
    callbacks: CallbackOwner,
    queue: DmaQueueIdentity,
    geometry: BlockGeometry,
    phase: AtomicU8,
    slots: PoisonLock<Box<[Slot]>>,
}

impl BlockDeviceAdapter {
    /// A hardware queue cannot have two independent completion consumers,
    /// including while an older generation remains retained during shutdown.
    pub(super) fn claims_queue(&self, queue: DmaQueueIdentity) -> bool {
        self.queue.device() == queue.device() && self.queue.index() == queue.index()
    }

    pub(super) fn prepare(
        owner: DomainId,
        registration: AbiBlockDeviceRegistration,
    ) -> Result<Self, AbiErrorCode> {
        if registration.abi_size != core::mem::size_of::<AbiBlockDeviceRegistration>() as u64 {
            return Err(AbiErrorCode::InvalidSize);
        }
        let queue = registration.queue.identity()?;
        let max_blocks = u16::try_from(registration.info.max_transfer_blocks)
            .map_err(|_| AbiErrorCode::InvalidSize)?;
        let geometry = BlockGeometry::new(
            registration.info.block_size,
            registration.info.block_count,
            max_blocks,
        )
        .ok_or(AbiErrorCode::InvalidParam)?;
        let mut slots = Vec::new();
        let capacity = usize::from(registration.queue.capacity);
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| AbiErrorCode::OutOfMemory)?;
        slots.resize_with(capacity, || Slot::Empty);
        Ok(Self {
            registration,
            callbacks: CallbackOwner::acquire(owner).map_err(|_| AbiErrorCode::DeviceBusy)?,
            queue,
            geometry,
            phase: AtomicU8::new(OPEN),
            slots: PoisonLock::new(slots.into_boxed_slice()),
        })
    }

    fn enter(&self, invocation: ResourceInvocation) -> Result<CallbackGate<'_>, IoError> {
        let result =
            self.phase
                .try_update(Ordering::Acquire, Ordering::Relaxed, |phase| match phase {
                    OPEN => Some(CALLING),
                    CLOSING if matches!(invocation, ResourceInvocation::Finalize) => {
                        Some(CLOSING_CALLING)
                    }
                    _ => None,
                });
        result
            .map(|_| CallbackGate(&self.phase))
            .map_err(|phase| match phase {
                CLOSING | CLOSING_CALLING | STOPPED => IoError::Cancelled,
                _ => IoError::Busy,
            })
    }

    fn reserve(&self) -> Option<usize> {
        let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
        let index = slots.iter().position(|slot| matches!(slot, Slot::Empty))?;
        slots[index] = Slot::Reserved;
        Some(index)
    }

    fn store(&self, index: usize, pending: Option<PendingBlock>) {
        let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
        slots[index] = pending.map_or(Slot::Empty, Slot::Pending);
    }

    fn validate(&self, command: &IoCommand) -> Result<(IoOperationType, u64, u16, usize), IoError> {
        let (operation, lba, blocks, buffer) = match command {
            IoCommand::BlockRead {
                lba,
                blocks,
                buffer,
            } => (IoOperationType::Read, *lba, *blocks, buffer),
            IoCommand::BlockWrite {
                lba,
                blocks,
                buffer,
            } => (IoOperationType::Write, *lba, *blocks, buffer),
            IoCommand::Flush => return Ok((IoOperationType::Flush, 0, 0, 0)),
            IoCommand::Discard { .. } => return Err(IoError::NotSupported),
        };
        let direction = buffer.direction();
        let allowed_direction = match operation {
            IoOperationType::Read => matches!(
                direction,
                DmaDirection::FromDevice | DmaDirection::Bidirectional
            ),
            IoOperationType::Write => matches!(
                direction,
                DmaDirection::ToDevice | DmaDirection::Bidirectional
            ),
            _ => false,
        };
        let bytes = usize::from(blocks)
            .checked_mul(self.geometry.block_size.get() as usize)
            .ok_or(IoError::InvalidParameter)?;
        if !allowed_direction
            || blocks == 0
            || blocks > self.geometry.max_transfer_blocks.get()
            || lba
                .checked_add(u64::from(blocks))
                .is_none_or(|end| end > self.geometry.block_count.get())
            || bytes != buffer.byte_count().get()
        {
            return Err(IoError::InvalidParameter);
        }
        Ok((operation, lba, blocks, bytes))
    }

    /// Close admission first. Busy retains the registration, code, and every
    /// accepted request; finalization polling remains permitted while closing.
    pub(super) fn stop(&self) -> Result<(), AbiErrorCode> {
        let result =
            self.phase
                .try_update(Ordering::AcqRel, Ordering::Acquire, |phase| match phase {
                    OPEN => Some(CLOSING),
                    CALLING => Some(CLOSING_CALLING),
                    _ => None,
                });
        if matches!(result, Err(STOPPED)) {
            return Ok(());
        }
        let _gate = self
            .enter(ResourceInvocation::Finalize)
            .map_err(|_| AbiErrorCode::DeviceBusy)?;
        if self
            .slots
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .any(|slot| !matches!(slot, Slot::Empty))
        {
            return Err(AbiErrorCode::DeviceBusy);
        }
        let _execution = self
            .callbacks
            .enter(ResourceInvocation::Finalize)
            .map_err(|_| AbiErrorCode::DeviceBusy)?;
        // SAFETY: no submission or poll callback can race the gate. The retained
        // callback owner keeps the runtime/code live through explicit stop.
        let status = unsafe { (self.registration.stop)(self.registration.opaque) };
        AbiErrorCode::from_raw(status)
            .into_result()
            .map_err(|_| AbiErrorCode::from_raw(status))?;
        self.phase.store(STOPPED, Ordering::Release);
        Ok(())
    }

    fn finish_cpu(
        pending: PendingBlock,
        buffer: Option<CpuDmaLease>,
        result: Result<usize, IoError>,
    ) -> Option<DeviceCompletion> {
        match pending.route {
            CompletionRoute::Waiting(route) => Some(route.finish(match buffer {
                Some(buffer) => IoCompletion::transfer_returned(result, buffer),
                None => IoCompletion::control(result),
            })),
            CompletionRoute::Reported => {
                if let Some(buffer) = buffer {
                    if let Err(error) = buffer.close() {
                        // The authoritative registry retains its reserved unmap
                        // retirement owner; domain cleanup observes that lease.
                        log::warn!(
                            "block transfer retirement remains pending: {:?}",
                            error.cause()
                        );
                        drop(error);
                    }
                }
                None
            }
        }
    }

    /// A proved completion or a failed pre-publication abort needs no additional
    /// device entry. Retry the retained software transition on later polls.
    fn progress_retirement(&self, output: &mut Vec<DeviceCompletion>) {
        let capacity = self.registration.queue.capacity;
        // LOOP_PROOF: mode=bounded; reason=Registration fixes the finite slot capacity and output is bounded by COMPLETION_BATCH;
        for index in 0..usize::from(capacity) {
            if output.len() == COMPLETION_BATCH {
                break;
            }
            let mut pending = {
                let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
                if !matches!(&slots[index], Slot::Pending(pending) if matches!(&pending.transfer, Some(TransferOwner::Prepared(_) | TransferOwner::Completed { .. })))
                {
                    continue;
                }
                let Slot::Pending(pending) = core::mem::replace(&mut slots[index], Slot::Reserved)
                else {
                    unreachable!()
                };
                pending
            };
            let (buffer, result) = match pending.transfer.take() {
                Some(TransferOwner::Prepared(lease)) => match lease.abort() {
                    Ok(buffer) => (buffer, Err(IoError::DeviceError)),
                    Err(error) => {
                        let (_, lease) = error.into_parts();
                        pending.transfer = Some(TransferOwner::Prepared(lease));
                        self.store(index, Some(pending));
                        continue;
                    }
                },
                Some(TransferOwner::Completed { lease, result }) => match lease.return_to_cpu() {
                    Ok(buffer) => (buffer, result),
                    Err(error) => {
                        let (_, lease) = error.into_parts();
                        pending.transfer = Some(TransferOwner::Completed { lease, result });
                        self.store(index, Some(pending));
                        continue;
                    }
                },
                _ => unreachable!("the slot was selected and moved under one gate"),
            };
            self.store(index, None);
            if let Some(completion) = Self::finish_cpu(pending, Some(buffer), result) {
                output.push(completion);
            }
        }
    }

    fn complete(&self, entry: AbiBlockCompletion) -> Option<DeviceCompletion> {
        let (index, mut pending) = {
            let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
            let index = slots.iter().position(|slot| matches!(slot, Slot::Pending(pending) if pending.request_id == entry.request_id))?;
            let Slot::Pending(pending) = core::mem::replace(&mut slots[index], Slot::Reserved)
            else {
                unreachable!()
            };
            (index, pending)
        };
        if entry.generation != self.queue.generation()
            || entry.bytes > pending.bytes
            || match &pending.transfer {
                Some(TransferOwner::InFlight(lease)) => {
                    entry.lease_id != lease.lease_id().into_abi()
                }
                None => entry.lease_id != 0,
                _ => true,
            }
        {
            self.store(index, Some(pending));
            return None;
        }
        let result = match map_io_status(entry.status) {
            IoResult::Success(_) => Ok(entry.bytes),
            IoResult::Error(cause) => Err(cause),
            IoResult::AuthorityQuarantined(cause) | IoResult::OutcomeUnknown(cause) => Err(cause),
        };
        let buffer = match pending.transfer.take() {
            Some(TransferOwner::InFlight(lease)) => {
                // SAFETY: the registered driver parser reported a terminal
                // entry. Its tag, queue generation, lease and length were
                // matched to the exclusively retained current submission above.
                let witness = unsafe {
                    DmaCompletionWitness::from_validated_queue_entry(self.queue, lease.lease_id())
                };
                let completed = match lease.complete(witness) {
                    Ok(lease) => lease,
                    Err(error) => {
                        let (_, lease) = error.into_parts();
                        pending.transfer =
                            Some(TransferOwner::CompletionUnrestored { _lease: lease });
                        let pending_operation = pending.operation;
                        let route =
                            core::mem::replace(&mut pending.route, CompletionRoute::Reported);
                        self.store(index, Some(pending));
                        return match route {
                            CompletionRoute::Waiting(route) => {
                                Some(route.finish(IoCompletion::authority_quarantined(
                                    pending_operation,
                                    IoError::DeviceError,
                                )))
                            }
                            CompletionRoute::Reported => None,
                        };
                    }
                };
                match completed.return_to_cpu() {
                    Ok(buffer) => Some(buffer),
                    Err(error) => {
                        let (_, lease) = error.into_parts();
                        pending.transfer = Some(TransferOwner::Completed { lease, result });
                        self.store(index, Some(pending));
                        return None;
                    }
                }
            }
            None => None,
            _ => unreachable!(),
        };
        self.store(index, None);
        Self::finish_cpu(pending, buffer, result)
    }
}

impl DeviceOps for BlockDeviceAdapter {
    fn submit(&self, submission: IoSubmission, _cpu: crate::cpu::CpuId) -> IoSubmitOutcome {
        let fail = |submission, cause| IoSubmitOutcome::Rejected { cause, submission };
        let _gate = match self.enter(ResourceInvocation::Operation) {
            Ok(gate) => gate,
            Err(cause) => return fail(submission, cause),
        };
        let _execution = match self.callbacks.enter(ResourceInvocation::Operation) {
            Ok(execution) => execution,
            Err(_) => return fail(submission, IoError::Busy),
        };
        let (operation, lba, blocks, bytes) = match self.validate(submission.command()) {
            Ok(layout) => layout,
            Err(cause) => return fail(submission, cause),
        };
        let Some(index) = self.reserve() else {
            return fail(submission, IoError::Busy);
        };
        let request_id = submission.request_id().0;
        let (route, command) = submission.into_parts();
        let mut activation = match command {
            IoCommand::BlockRead { buffer, .. } | IoCommand::BlockWrite { buffer, .. } => {
                match buffer.prepare(self.queue) {
                    Ok(lease) => Activation::Prepared(lease),
                    Err(error) => {
                        let (_, buffer) = error.into_parts();
                        self.store(index, None);
                        return route.reject(
                            transfer_command(operation, lba, blocks, buffer),
                            IoError::DeviceError,
                        );
                    }
                }
            }
            IoCommand::Flush => Activation::ControlPrepared,
            IoCommand::Discard { .. } => unreachable!(),
        };
        let descriptor = match &activation {
            Activation::Prepared(lease) => lease.descriptor().map(|descriptor| {
                (
                    descriptor.device_address().get(),
                    descriptor.lease_id().into_abi(),
                )
            }),
            _ => Ok((0, 0)),
        };
        let outcome = match descriptor {
            Ok((iova, lease_id)) => {
                let input = AbiBlockSubmission {
                    request_id,
                    command: match operation {
                        IoOperationType::Read => AbiBlockCommandKind::Read as u32,
                        IoOperationType::Write => AbiBlockCommandKind::Write as u32,
                        IoOperationType::Flush => AbiBlockCommandKind::Flush as u32,
                        IoOperationType::Discard => unreachable!(),
                    },
                    lba,
                    blocks,
                    bytes,
                    iova,
                    lease_id,
                    generation: self.queue.generation(),
                    activation: core::ptr::from_mut(&mut activation).cast(),
                    activate,
                };
                // SAFETY: input and its exclusive activation frame outlive the
                // synchronous call. No host lock is held; the queue gate keeps
                // submission/completion and shutdown from racing the callback.
                unsafe { (self.registration.submit)(self.registration.opaque, &input) }
            }
            Err(_) => {
                kernel_api::abi::driver::AbiBlockSubmitOutcome::rejected(AbiErrorCode::IoError)
            }
        };
        let accepted = matches!(outcome.disposition(), Ok(AbiBlockDisposition::Accepted))
            && AbiErrorCode::from_raw(outcome.status).is_success();
        let cause = match map_io_status(outcome.status) {
            IoResult::Error(cause) => cause,
            _ => IoError::DeviceError,
        };
        let transfer = match activation {
            Activation::ControlPrepared => {
                self.store(index, None);
                return route.reject(IoCommand::Flush, cause);
            }
            Activation::Prepared(lease) => match lease.abort() {
                Ok(buffer) => {
                    self.store(index, None);
                    return route.reject(transfer_command(operation, lba, blocks, buffer), cause);
                }
                Err(error) => {
                    let (_, lease) = error.into_parts();
                    self.store(
                        index,
                        Some(PendingBlock {
                            request_id,
                            route: CompletionRoute::Reported,
                            operation,
                            transfer: Some(TransferOwner::Prepared(lease)),
                            bytes,
                        }),
                    );
                    return IoSubmitOutcome::Finished(route.finish(
                        IoCompletion::authority_quarantined(operation, IoError::DeviceError),
                    ));
                }
            },
            Activation::Active(lease) => Some(TransferOwner::InFlight(lease)),
            Activation::ControlActive => None,
            Activation::Transitioning => {
                unreachable!("activation always restores a linear state before returning")
            }
        };
        if accepted {
            self.store(
                index,
                Some(PendingBlock {
                    request_id,
                    route: CompletionRoute::Waiting(route),
                    operation,
                    transfer,
                    bytes,
                }),
            );
            IoSubmitOutcome::Accepted
        } else {
            self.store(
                index,
                Some(PendingBlock {
                    request_id,
                    route: CompletionRoute::Reported,
                    operation,
                    transfer,
                    bytes,
                }),
            );
            IoSubmitOutcome::Finished(route.finish(IoCompletion::outcome_unknown(operation, cause)))
        }
    }

    fn is_ready(&self) -> bool {
        let Ok(_gate) = self.enter(ResourceInvocation::Operation) else {
            return false;
        };
        let Ok(_execution) = self.callbacks.enter(ResourceInvocation::Operation) else {
            return false;
        };
        // SAFETY: the callback gate and retained registration keep this exact
        // runtime/code live and exclude lifecycle mutation for the observation.
        unsafe { (self.registration.is_ready)(self.registration.opaque) }
    }

    fn allocate_transfer(&self, request: DmaAllocationRequest) -> Result<CpuDmaLease, IoError> {
        let _gate = self.enter(ResourceInvocation::Operation)?;
        // Allocation authority belongs to the retained device owner. The
        // returned capability stores that owner and does not depend on the
        // caller retaining this execution scope or ambient PCI authority.
        let _execution = self
            .callbacks
            .enter(ResourceInvocation::Operation)
            .map_err(|_| IoError::Busy)?;
        let device = self.queue.device();
        super::dma::allocate(
            self.callbacks.domain,
            device,
            crate::io::iommu::types::DeviceId::new(
                device.segment(),
                device.bus(),
                device.device(),
                device.function(),
            ),
            request,
        )
        .map_err(|cause| match cause {
            super::dma::DmaAllocationError::AllocationFailed
            | super::dma::DmaAllocationError::MetadataAllocationFailed
            | super::dma::DmaAllocationError::RegistryExhausted => IoError::NoResources,
            super::dma::DmaAllocationError::OwnerAdmission(_) => IoError::Cancelled,
            super::dma::DmaAllocationError::InvalidSize => IoError::InvalidParameter,
            _ => IoError::DeviceError,
        })
    }

    fn block_geometry(&self) -> Option<BlockGeometry> {
        (self.phase.load(Ordering::Acquire) < CLOSING).then_some(self.geometry)
    }
}

impl PollHandler for BlockDeviceAdapter {
    fn poll_completions(&self) -> Vec<DeviceCompletion> {
        let mut output = Vec::new();
        // Acquire output storage before consuming any driver notification.
        if output.try_reserve_exact(COMPLETION_BATCH).is_err() {
            return output;
        }
        let Ok(_gate) = self.enter(ResourceInvocation::Finalize) else {
            return output;
        };
        let Ok(_execution) = self.callbacks.enter(ResourceInvocation::Finalize) else {
            return output;
        };
        self.progress_retirement(&mut output);
        let mut entries = [AbiBlockCompletion::default(); COMPLETION_BATCH];
        let capacity = COMPLETION_BATCH - output.len();
        if capacity == 0 {
            return output;
        }
        let mut written = 0;
        // SAFETY: the fixed output array/count are exclusively borrowed for
        // this call, and the retained code/runtime owns the registered parser.
        let status = unsafe {
            (self.registration.poll)(
                self.registration.opaque,
                entries.as_mut_ptr(),
                capacity,
                &mut written,
            )
        };
        if !AbiErrorCode::from_raw(status).is_success() {
            log::warn!("block completion poll failed after {written} notifications: {status}");
        }
        // LOOP_PROOF: mode=bounded; reason=The fixed output array bounds driver notifications to COMPLETION_BATCH;
        for entry in entries.into_iter().take(written.min(capacity)) {
            if let Some(completion) = self.complete(entry) {
                output.push(completion);
            }
        }
        output
    }

    fn is_ready(&self) -> bool {
        self.phase.load(Ordering::Acquire) != STOPPED
    }
}

fn transfer_command(
    operation: IoOperationType,
    lba: u64,
    blocks: u16,
    buffer: CpuDmaLease,
) -> IoCommand {
    match operation {
        IoOperationType::Read => IoCommand::BlockRead {
            lba,
            blocks,
            buffer,
        },
        IoOperationType::Write => IoCommand::BlockWrite {
            lba,
            blocks,
            buffer,
        },
        _ => unreachable!("only transfer commands carry a DMA owner"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_api::abi::driver::{
        AbiBlockDeviceInfo, AbiBlockQueueInfo, AbiBlockSubmitOutcome, AbiBlockTransport,
        PackedPciLocation,
    };

    unsafe extern "C" fn submit(
        _cookie: u64,
        _input: *const AbiBlockSubmission,
    ) -> AbiBlockSubmitOutcome {
        AbiBlockSubmitOutcome::rejected(AbiErrorCode::NotSupported)
    }

    /// # Safety
    /// The host provides exclusive output storage and a live count pointer.
    unsafe extern "C" fn poll(
        _cookie: u64,
        _out: *mut AbiBlockCompletion,
        _capacity: usize,
        written: *mut usize,
    ) -> i32 {
        // SAFETY: this callback's host-owned count remains writable for the call.
        unsafe { written.write(0) };
        0
    }

    extern "C" fn ready(_cookie: u64) -> bool {
        true
    }
    unsafe extern "C" fn stop(_cookie: u64) -> i32 {
        0
    }

    fn adapter(capacity: u16) -> BlockDeviceAdapter {
        BlockDeviceAdapter::prepare(
            DomainId::KERNEL,
            AbiBlockDeviceRegistration {
                abi_size: core::mem::size_of::<AbiBlockDeviceRegistration>() as u64,
                info: AbiBlockDeviceInfo {
                    device_id: 1,
                    block_size: 512,
                    block_count: 2048,
                    max_transfer_blocks: 128,
                    transport: AbiBlockTransport::Other as u32,
                    ..AbiBlockDeviceInfo::default()
                },
                queue: AbiBlockQueueInfo {
                    device: PackedPciLocation::new(0, 0, 4, 0),
                    index: 0,
                    capacity,
                    generation: 5,
                },
                opaque: 0,
                submit,
                poll,
                is_ready: ready,
                stop,
            },
        )
        .expect("fixture defines a valid bounded queue with kernel-owned callbacks")
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn a_retained_callback_closes_admission_without_waiting() {
        let adapter = adapter(2);
        let callback = adapter
            .enter(ResourceInvocation::Operation)
            .expect("open queue");
        assert_eq!(adapter.stop(), Err(AbiErrorCode::DeviceBusy));
        assert!(adapter.enter(ResourceInvocation::Operation).is_err());
        assert!(adapter.enter(ResourceInvocation::Finalize).is_err());
        drop(callback);
        assert!(adapter.enter(ResourceInvocation::Operation).is_err());
        assert!(adapter.enter(ResourceInvocation::Finalize).is_ok());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn closing_retains_finite_request_reservations() {
        let adapter = adapter(2);
        let first = adapter.reserve().expect("first finite slot");
        let second = adapter.reserve().expect("second finite slot");
        assert!(adapter.reserve().is_none());
        assert_eq!(adapter.stop(), Err(AbiErrorCode::DeviceBusy));
        assert!(matches!(
            adapter
                .slots
                .lock()
                .unwrap_or_else(|_| panic!("fixture slots poisoned"))[first],
            Slot::Reserved
        ));
        assert!(matches!(
            adapter
                .slots
                .lock()
                .unwrap_or_else(|_| panic!("fixture slots poisoned"))[second],
            Slot::Reserved
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn retained_queue_generations_share_one_completion_consumer() {
        let adapter = adapter(1);
        let next =
            DmaQueueIdentity::new(adapter.queue.device(), 0, 6).expect("next queue generation");
        assert!(adapter.claims_queue(next));
        assert!(!adapter.claims_queue(next.with_index(1)));
    }
}
