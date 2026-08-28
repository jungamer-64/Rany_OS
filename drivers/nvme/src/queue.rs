use alloc::vec::Vec;
use hal::mmio::sfence;
use kernel_api::dma::{
    CompletedDmaLease, CpuDmaLease, DmaCompletionWitness, DmaDescriptor, DmaDeviceAddress,
    DmaDirection, DmaLeaseError, DmaQueueIdentity, InFlightDmaLease, PreparedDmaLease,
    PreparedSharedDmaLease, SharedDmaLease,
};
use spin::Mutex;

use crate::protocol::{AdminCommand, IoTransfer, NvmeCommand, NvmeCompletion, TransferDirection};
use crate::registers::{NvmeRegisterError, NvmeRegisters};

const PAGE_SIZE: usize = 4096;
const SUBMISSION_BYTES: usize = 64;
const COMPLETION_BYTES: usize = 16;

/// CPU-owned allocations selected for one submission/completion queue pair.
#[derive(Debug)]
pub struct QueueMemory {
    /// Host-written submission queue allocation.
    pub submission: CpuDmaLease,
    /// Controller-written completion queue allocation.
    pub completion: CpuDmaLease,
}

/// Failure before both queue allocations enter the prepared-shared state.
#[derive(Debug)]
pub enum QueuePrepareError {
    /// Queue geometry or DMA direction is incompatible with NVMe.
    InvalidMemory(QueueMemory),
    /// CPU initialization of one queue allocation failed.
    Initialize {
        cause: DmaLeaseError,
        memory: QueueMemory,
    },
    /// Submission queue preparation failed; both CPU owners are returned.
    Submission {
        cause: DmaLeaseError,
        memory: QueueMemory,
    },
    /// Completion queue preparation failed after submission preparation.
    CompletionPrepare {
        cause: DmaLeaseError,
        submission: PreparedSharedDmaLease,
        completion: CpuDmaLease,
    },
    /// Descriptor validation failed after both allocations were prepared.
    CompletionDescriptor {
        cause: DmaLeaseError,
        submission: PreparedSharedDmaLease,
        completion: PreparedSharedDmaLease,
    },
    /// Queue bases are not page aligned as required for host queue memory.
    InvalidAlignment {
        submission: PreparedSharedDmaLease,
        completion: PreparedSharedDmaLease,
    },
}

/// Prepared queue pair; no device register contains its addresses yet.
pub struct PreparedQueuePair {
    identity: DmaQueueIdentity,
    depth: u16,
    submission_address: DmaDeviceAddress,
    completion_address: DmaDeviceAddress,
    submission: PreparedSharedDmaLease,
    completion: PreparedSharedDmaLease,
}

impl PreparedQueuePair {
    /// Initialize and prepare two registry allocations as queue RAM.
    ///
    /// # Errors
    /// Invalid sizes/directions and every registry failure retain all owners in
    /// the returned error. No device register is changed by this operation.
    pub fn prepare(
        identity: DmaQueueIdentity,
        depth: u16,
        mut memory: QueueMemory,
    ) -> Result<Self, QueuePrepareError> {
        let submission_bytes = usize::from(depth).checked_mul(SUBMISSION_BYTES);
        let completion_bytes = usize::from(depth).checked_mul(COMPLETION_BYTES);
        let directions_valid = matches!(
            memory.submission.direction(),
            DmaDirection::ToDevice | DmaDirection::Bidirectional
        ) && matches!(
            memory.completion.direction(),
            DmaDirection::FromDevice | DmaDirection::Bidirectional
        );
        let Some(submission_bytes) = submission_bytes else {
            return Err(QueuePrepareError::InvalidMemory(memory));
        };
        let Some(completion_bytes) = completion_bytes else {
            return Err(QueuePrepareError::InvalidMemory(memory));
        };
        if depth < 2
            || !directions_valid
            || memory.submission.byte_count().get() < submission_bytes
            || memory.completion.byte_count().get() < completion_bytes
        {
            return Err(QueuePrepareError::InvalidMemory(memory));
        }
        if let Err(cause) = memory.submission.write(|bytes| bytes.fill(0)) {
            return Err(QueuePrepareError::Initialize { cause, memory });
        }
        if let Err(cause) = memory.completion.write(|bytes| bytes.fill(0)) {
            return Err(QueuePrepareError::Initialize { cause, memory });
        }

        let submission = match memory.submission.prepare_shared(identity) {
            Ok(submission) => submission,
            Err(error) => {
                let (cause, submission) = error.into_parts();
                return Err(QueuePrepareError::Submission {
                    cause,
                    memory: QueueMemory {
                        submission,
                        completion: memory.completion,
                    },
                });
            }
        };
        let submission_address = match submission.descriptor() {
            Ok(descriptor) => descriptor.device_address(),
            Err(cause) => {
                return Err(QueuePrepareError::CompletionPrepare {
                    cause,
                    submission,
                    completion: memory.completion,
                });
            }
        };
        let completion = match memory.completion.prepare_shared(identity) {
            Ok(completion) => completion,
            Err(error) => {
                let (cause, completion) = error.into_parts();
                return Err(QueuePrepareError::CompletionPrepare {
                    cause,
                    submission,
                    completion,
                });
            }
        };
        let completion_address = match completion.descriptor() {
            Ok(descriptor) => descriptor.device_address(),
            Err(cause) => {
                return Err(QueuePrepareError::CompletionDescriptor {
                    cause,
                    submission,
                    completion,
                });
            }
        };
        if submission_address.get() % PAGE_SIZE as u64 != 0
            || completion_address.get() % PAGE_SIZE as u64 != 0
        {
            return Err(QueuePrepareError::InvalidAlignment {
                submission,
                completion,
            });
        }
        Ok(Self {
            identity,
            depth,
            submission_address,
            completion_address,
            submission,
            completion,
        })
    }

    /// Device-visible submission queue base.
    pub const fn submission_address(&self) -> DmaDeviceAddress {
        self.submission_address
    }

    /// Device-visible completion queue base.
    pub const fn completion_address(&self) -> DmaDeviceAddress {
        self.completion_address
    }

    /// Enter the active shared-memory state before hardware publication.
    ///
    /// # Errors
    /// A partial activation retains both owners and cannot be treated as CPU
    /// memory until controller quiescence or reset is established.
    pub fn activate(self) -> Result<NvmeQueue, QueueActivationError> {
        let submission = match self.submission.activate() {
            Ok(submission) => submission,
            Err(error) => {
                let (cause, submission) = error.into_parts();
                return Err(QueueActivationError::Submission {
                    cause,
                    submission,
                    completion: self.completion,
                });
            }
        };
        let completion = match self.completion.activate() {
            Ok(completion) => completion,
            Err(error) => {
                let (cause, completion) = error.into_parts();
                return Err(QueueActivationError::Completion {
                    cause,
                    submission,
                    completion,
                });
            }
        };
        Ok(NvmeQueue::new(
            self.identity,
            self.depth,
            self.submission_address,
            self.completion_address,
            submission,
            completion,
        ))
    }
}

/// Activation failure retaining every queue-memory owner.
pub enum QueueActivationError {
    /// Submission allocation did not activate; both allocations remain prepared.
    Submission {
        cause: DmaLeaseError,
        submission: PreparedSharedDmaLease,
        completion: PreparedSharedDmaLease,
    },
    /// Submission activated but completion did not.
    Completion {
        cause: DmaLeaseError,
        submission: SharedDmaLease,
        completion: PreparedSharedDmaLease,
    },
}

impl core::fmt::Debug for QueueActivationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Submission { cause, .. } => formatter
                .debug_struct("Submission")
                .field("cause", cause)
                .finish_non_exhaustive(),
            Self::Completion { cause, .. } => formatter
                .debug_struct("Completion")
                .field("cause", cause)
                .finish_non_exhaustive(),
        }
    }
}

/// Reason a transfer did not cross the device-acceptance boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitFailure {
    /// The requested I/O queue is not owned by this controller.
    InvalidQueue,
    /// Queue doorbell geometry is invalid.
    Register(NvmeRegisterError),
    /// The queue has entered a reset-required state.
    QueueFault,
    /// No command slot is currently available.
    QueueFull,
    /// Direction, logical length, or PRP geometry is invalid.
    InvalidTransfer,
    /// Registry transition or shared-memory access failed.
    Dma(DmaLeaseError),
}

/// Pre-acceptance transfer failure retaining the exact DMA state.
pub enum SubmitError {
    /// CPU ownership was never relinquished.
    Cpu {
        cause: SubmitFailure,
        lease: CpuDmaLease,
    },
    /// Preparation succeeded but arming/queue publication did not.
    Prepared {
        cause: SubmitFailure,
        lease: PreparedDmaLease,
    },
}

impl core::fmt::Debug for SubmitError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cpu { cause, lease } => formatter
                .debug_struct("Cpu")
                .field("cause", cause)
                .field("lease", &lease.lease_id())
                .finish(),
            Self::Prepared { cause, lease } => formatter
                .debug_struct("Prepared")
                .field("cause", cause)
                .field("lease", &lease.lease_id())
                .finish(),
        }
    }
}

/// Successful hardware publication identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueSubmission {
    command_id: u16,
}

impl QueueSubmission {
    /// Command identifier recorded in the SQ entry.
    pub const fn command_id(self) -> u16 {
        self.command_id
    }
}

enum PendingCommand {
    Transfer(InFlightDmaLease),
    Control,
}

#[derive(Clone, Copy)]
enum QueueFault {
    SharedMemory,
    InvalidCompletion,
    Ownership,
}

struct QueueState {
    tail: u16,
    completion_head: u16,
    phase: bool,
    outstanding: u16,
    fault: Option<QueueFault>,
    pending: Vec<Option<PendingCommand>>,
    command_ids: CommandIdPool,
}

struct CommandIdPool {
    free: Vec<u16>,
}

impl CommandIdPool {
    fn new(depth: u16) -> Self {
        let mut free = Vec::with_capacity(usize::from(depth));
        for command_id in (0..depth).rev() {
            free.push(command_id);
        }
        Self { free }
    }

    fn acquire(&mut self) -> Option<u16> {
        self.free.pop()
    }

    fn release(&mut self, command_id: u16) {
        self.free.push(command_id);
    }
}

/// One active NVMe submission/completion queue pair.
pub struct NvmeQueue {
    identity: DmaQueueIdentity,
    depth: u16,
    submission_address: DmaDeviceAddress,
    completion_address: DmaDeviceAddress,
    submission: Mutex<SharedDmaLease>,
    completion: Mutex<SharedDmaLease>,
    state: Mutex<QueueState>,
}

impl NvmeQueue {
    fn new(
        identity: DmaQueueIdentity,
        depth: u16,
        submission_address: DmaDeviceAddress,
        completion_address: DmaDeviceAddress,
        submission: SharedDmaLease,
        completion: SharedDmaLease,
    ) -> Self {
        let mut pending = Vec::with_capacity(usize::from(depth));
        pending.resize_with(usize::from(depth), || None);
        Self {
            identity,
            depth,
            submission_address,
            completion_address,
            submission: Mutex::new(submission),
            completion: Mutex::new(completion),
            state: Mutex::new(QueueState {
                tail: 0,
                completion_head: 0,
                phase: true,
                outstanding: 0,
                fault: None,
                pending,
                command_ids: CommandIdPool::new(depth),
            }),
        }
    }

    /// Queue generation bound into DMA preparation and completion validation.
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.identity
    }

    pub(crate) const fn depth(&self) -> u16 {
        self.depth
    }

    /// Device-visible queue bases for controller setup commands.
    pub const fn device_addresses(&self) -> (DmaDeviceAddress, DmaDeviceAddress) {
        (self.submission_address, self.completion_address)
    }

    /// Prepare, arm, and publish one read/write transfer without copying data.
    ///
    /// # Errors
    /// Every error occurs before the SQ tail doorbell write and returns either
    /// CPU or prepared ownership. After success, ownership remains in this queue
    /// until validated completion or reset reconciliation.
    pub fn submit_transfer(
        &self,
        registers: &NvmeRegisters,
        transfer: IoTransfer,
        lease: CpuDmaLease,
    ) -> Result<QueueSubmission, SubmitError> {
        self.submit_dma(
            registers,
            transfer.direction(),
            transfer.logical_bytes().get(),
            lease,
            |command_id, descriptor, prp2| {
                Some(NvmeCommand::transfer(
                    command_id,
                    transfer,
                    descriptor.device_address(),
                    prp2,
                ))
            },
        )
    }

    pub(crate) fn submit_identify_namespace(
        &self,
        registers: &NvmeRegisters,
        namespace: u32,
        lease: CpuDmaLease,
    ) -> Result<QueueSubmission, SubmitError> {
        if namespace == 0 {
            return Err(SubmitError::Cpu {
                cause: SubmitFailure::InvalidTransfer,
                lease,
            });
        }
        self.submit_dma(
            registers,
            TransferDirection::Read,
            PAGE_SIZE,
            lease,
            |command_id, descriptor, prp2| {
                if prp2.is_some() {
                    return None;
                }
                NvmeCommand::identify_namespace(command_id, namespace, descriptor.device_address())
            },
        )
    }

    fn submit_dma(
        &self,
        registers: &NvmeRegisters,
        direction: TransferDirection,
        logical_bytes: usize,
        lease: CpuDmaLease,
        command: impl FnOnce(u16, &DmaDescriptor<'_>, Option<DmaDeviceAddress>) -> Option<NvmeCommand>,
    ) -> Result<QueueSubmission, SubmitError> {
        let mut doorbell = match registers.submission_doorbell(self.identity.index()) {
            Ok(doorbell) => doorbell,
            Err(cause) => {
                return Err(SubmitError::Cpu {
                    cause: SubmitFailure::Register(cause),
                    lease,
                });
            }
        };
        if !direction_matches(direction, lease.direction())
            || logical_bytes == 0
            || logical_bytes > lease.byte_count().get()
        {
            return Err(SubmitError::Cpu {
                cause: SubmitFailure::InvalidTransfer,
                lease,
            });
        }
        {
            let state = self.state.lock();
            if state.fault.is_some() {
                return Err(SubmitError::Cpu {
                    cause: SubmitFailure::QueueFault,
                    lease,
                });
            }
            if state.outstanding >= self.depth - 1 {
                return Err(SubmitError::Cpu {
                    cause: SubmitFailure::QueueFull,
                    lease,
                });
            }
        }

        let prepared = match lease.prepare(self.identity) {
            Ok(prepared) => prepared,
            Err(error) => {
                let (cause, lease) = error.into_parts();
                return Err(SubmitError::Cpu {
                    cause: SubmitFailure::Dma(cause),
                    lease,
                });
            }
        };
        let descriptor = match prepared.descriptor() {
            Ok(descriptor) => descriptor,
            Err(cause) => {
                return Err(SubmitError::Prepared {
                    cause: SubmitFailure::Dma(cause),
                    lease: prepared,
                });
            }
        };
        let prp2 = match inline_prp2(&descriptor, logical_bytes) {
            Ok(prp2) => prp2,
            Err(cause) => {
                return Err(SubmitError::Prepared {
                    cause,
                    lease: prepared,
                });
            }
        };

        let mut state = self.state.lock();
        if state.fault.is_some() {
            return Err(SubmitError::Prepared {
                cause: SubmitFailure::QueueFault,
                lease: prepared,
            });
        }
        if state.outstanding >= self.depth - 1 {
            return Err(SubmitError::Prepared {
                cause: SubmitFailure::QueueFull,
                lease: prepared,
            });
        }
        let Some(command_id) = state.command_ids.acquire() else {
            return Err(SubmitError::Prepared {
                cause: SubmitFailure::QueueFull,
                lease: prepared,
            });
        };
        if state.pending[usize::from(command_id)].is_some() {
            state.fault = Some(QueueFault::Ownership);
            return Err(SubmitError::Prepared {
                cause: SubmitFailure::QueueFault,
                lease: prepared,
            });
        }
        let Some(command) = command(command_id, &descriptor, prp2) else {
            state.command_ids.release(command_id);
            return Err(SubmitError::Prepared {
                cause: SubmitFailure::InvalidTransfer,
                lease: prepared,
            });
        };
        if let Err(cause) = write_submission(&mut self.submission.lock(), state.tail, &command) {
            state.command_ids.release(command_id);
            state.fault = Some(QueueFault::SharedMemory);
            return Err(SubmitError::Prepared {
                cause: SubmitFailure::Dma(cause),
                lease: prepared,
            });
        }
        let inflight = match prepared.arm() {
            Ok(inflight) => inflight,
            Err(error) => {
                state.command_ids.release(command_id);
                let (cause, prepared) = error.into_parts();
                return Err(SubmitError::Prepared {
                    cause: SubmitFailure::Dma(cause),
                    lease: prepared,
                });
            }
        };
        state.pending[usize::from(command_id)] = Some(PendingCommand::Transfer(inflight));
        state.tail = (state.tail + 1) % self.depth;
        state.outstanding += 1;
        sfence();
        doorbell.write(u32::from(state.tail));
        Ok(QueueSubmission { command_id })
    }

    /// Publish one flush command with no DMA transfer owner.
    ///
    /// # Errors
    /// Returns a pre-publication failure; no completion can follow an error.
    pub fn submit_flush(
        &self,
        registers: &NvmeRegisters,
        namespace: u32,
    ) -> Result<QueueSubmission, SubmitFailure> {
        self.submit_control(registers, |command_id| {
            NvmeCommand::flush(command_id, namespace)
        })
    }

    pub(crate) fn submit_admin(
        &self,
        registers: &NvmeRegisters,
        command: AdminCommand,
    ) -> Result<QueueSubmission, SubmitFailure> {
        self.submit_control(registers, |command_id| {
            Some(command.with_command_id(command_id))
        })
    }

    fn submit_control(
        &self,
        registers: &NvmeRegisters,
        command: impl FnOnce(u16) -> Option<NvmeCommand>,
    ) -> Result<QueueSubmission, SubmitFailure> {
        let mut doorbell = registers
            .submission_doorbell(self.identity.index())
            .map_err(SubmitFailure::Register)?;
        let mut state = self.state.lock();
        if state.fault.is_some() {
            return Err(SubmitFailure::QueueFault);
        }
        if state.outstanding >= self.depth - 1 {
            return Err(SubmitFailure::QueueFull);
        }
        let Some(command_id) = state.command_ids.acquire() else {
            return Err(SubmitFailure::QueueFull);
        };
        let Some(command) = command(command_id) else {
            state.command_ids.release(command_id);
            return Err(SubmitFailure::InvalidTransfer);
        };
        if state.pending[usize::from(command_id)].is_some() {
            state.fault = Some(QueueFault::Ownership);
            return Err(SubmitFailure::QueueFault);
        }
        write_submission(&mut self.submission.lock(), state.tail, &command).map_err(|cause| {
            state.command_ids.release(command_id);
            state.fault = Some(QueueFault::SharedMemory);
            SubmitFailure::Dma(cause)
        })?;
        state.pending[usize::from(command_id)] = Some(PendingCommand::Control);
        state.tail = (state.tail + 1) % self.depth;
        state.outstanding += 1;
        sfence();
        doorbell.write(u32::from(state.tail));
        Ok(QueueSubmission { command_id })
    }

    /// Parse at most one completion and consume its unique pending owner.
    ///
    /// # Errors
    /// Invalid device tags fault the queue without granting CPU access. DMA
    /// transition failures restore the in-flight owner to the pending slot.
    pub fn poll_completion(
        &self,
        registers: &NvmeRegisters,
    ) -> Result<Option<CompletedCommand>, PollError> {
        let mut doorbell = registers
            .completion_doorbell(self.identity.index())
            .map_err(PollError::Register)?;
        let mut state = self.state.lock();
        if state.fault.is_some() {
            return Err(PollError::QueueFault);
        }
        let completion = read_completion(
            &mut self.completion.lock(),
            state.completion_head,
            state.phase,
        )?;
        let Some(completion) = completion else {
            return Ok(None);
        };
        let cid = completion.command_id();
        let pending_exists = cid < self.depth && state.pending[usize::from(cid)].is_some();
        if !completion_tags_valid(completion, self.identity, self.depth, pending_exists) {
            state.fault = Some(QueueFault::InvalidCompletion);
            return Err(PollError::InvalidCompletion(completion));
        }
        let Some(pending) = state.pending[usize::from(cid)].take() else {
            state.fault = Some(QueueFault::InvalidCompletion);
            return Err(PollError::InvalidCompletion(completion));
        };
        let completed = match pending {
            PendingCommand::Control => CompletedCommand::Control(completion),
            PendingCommand::Transfer(inflight) => {
                let lease_id = inflight.lease_id();
                let completed = match complete_transfer(inflight, self.identity, lease_id) {
                    Ok(completed) => completed,
                    Err((cause, inflight)) => {
                        state.pending[usize::from(cid)] = Some(PendingCommand::Transfer(inflight));
                        state.fault = Some(QueueFault::Ownership);
                        return Err(PollError::Ownership(cause));
                    }
                };
                let ownership = match completed.return_to_cpu() {
                    Ok(cpu) => CompletedOwnership::Cpu(cpu),
                    Err(error) => {
                        let (cause, completed) = error.into_parts();
                        CompletedOwnership::Blocked { cause, completed }
                    }
                };
                CompletedCommand::Transfer {
                    completion,
                    ownership,
                }
            }
        };
        state.outstanding -= 1;
        state.command_ids.release(cid);
        state.completion_head = (state.completion_head + 1) % self.depth;
        if state.completion_head == 0 {
            state.phase = !state.phase;
        }
        sfence();
        doorbell.write(u32::from(state.completion_head));
        Ok(Some(completed))
    }
}

fn direction_matches(transfer: TransferDirection, mapping: DmaDirection) -> bool {
    matches!(
        (transfer, mapping),
        (TransferDirection::Read, DmaDirection::FromDevice)
            | (TransferDirection::Read, DmaDirection::Bidirectional)
            | (TransferDirection::Write, DmaDirection::ToDevice)
            | (TransferDirection::Write, DmaDirection::Bidirectional)
    )
}

fn completion_tags_valid(
    completion: NvmeCompletion,
    identity: DmaQueueIdentity,
    depth: u16,
    pending_exists: bool,
) -> bool {
    completion.submission_queue() == identity.index()
        && completion.submission_head() < depth
        && completion.command_id() < depth
        && pending_exists
}

fn inline_prp2(
    descriptor: &DmaDescriptor<'_>,
    logical_bytes: usize,
) -> Result<Option<DmaDeviceAddress>, SubmitFailure> {
    if logical_bytes == 0 || logical_bytes > descriptor.byte_count().get() {
        return Err(SubmitFailure::InvalidTransfer);
    }
    let address = descriptor.device_address().get();
    let first_page_remaining = PAGE_SIZE - (address as usize & (PAGE_SIZE - 1));
    if logical_bytes <= first_page_remaining {
        return Ok(None);
    }
    if logical_bytes - first_page_remaining > PAGE_SIZE {
        return Err(SubmitFailure::InvalidTransfer);
    }
    descriptor
        .device_address()
        .checked_add(first_page_remaining)
        .map(Some)
        .ok_or(SubmitFailure::InvalidTransfer)
}

fn write_submission(
    lease: &mut SharedDmaLease,
    slot: u16,
    command: &NvmeCommand,
) -> Result<(), DmaLeaseError> {
    let offset = usize::from(slot)
        .checked_mul(SUBMISSION_BYTES)
        .ok_or(DmaLeaseError::InvalidRange)?;
    let mut window = lease.window(offset, SUBMISSION_BYTES)?;
    for (index, dword) in command.dwords().iter().copied().enumerate() {
        window.write_u32(index * 4, dword)?;
    }
    Ok(())
}

fn read_completion(
    lease: &mut SharedDmaLease,
    slot: u16,
    expected_phase: bool,
) -> Result<Option<NvmeCompletion>, PollError> {
    let offset = usize::from(slot)
        .checked_mul(COMPLETION_BYTES)
        .ok_or(PollError::Shared(DmaLeaseError::InvalidRange))?;
    let window = lease
        .window(offset, COMPLETION_BYTES)
        .map_err(PollError::Shared)?;
    let status_dword = window.read_u32(12).map_err(PollError::Shared)?;
    let status = (status_dword >> 16) as u16;
    if (status & 1 != 0) != expected_phase {
        return Ok(None);
    }
    let dwords = [
        window.read_u32(0).map_err(PollError::Shared)?,
        window.read_u32(4).map_err(PollError::Shared)?,
        window.read_u32(8).map_err(PollError::Shared)?,
        status_dword,
    ];
    Ok(Some(NvmeCompletion::from_dwords(dwords)))
}

#[expect(
    unsafe_code,
    reason = "validated NVMe phase, SQID, CID, and unique pending lease establish completion"
)]
fn complete_transfer(
    inflight: InFlightDmaLease,
    queue: DmaQueueIdentity,
    lease_id: kernel_api::dma::DmaLeaseId,
) -> Result<CompletedDmaLease, (DmaLeaseError, InFlightDmaLease)> {
    // SAFETY: `poll_completion` observed the current phase, checked the SQID
    // and CID against this queue generation, and removed exactly one pending
    // in-flight owner before invoking this boundary.
    let witness = unsafe { DmaCompletionWitness::from_validated_queue_entry(queue, lease_id) };
    inflight.complete(witness).map_err(|error| {
        let (cause, inflight) = error.into_parts();
        (cause, inflight)
    })
}

/// CPU recovery state after a valid transfer completion.
pub enum CompletedOwnership {
    /// Completion-side synchronization restored CPU ownership.
    Cpu(CpuDmaLease),
    /// Hardware completion is proven, but CPU ownership is still unavailable.
    Blocked {
        cause: DmaLeaseError,
        completed: CompletedDmaLease,
    },
}

impl core::fmt::Debug for CompletedOwnership {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cpu(lease) => formatter
                .debug_tuple("Cpu")
                .field(&lease.lease_id())
                .finish(),
            Self::Blocked {
                cause, completed, ..
            } => formatter
                .debug_struct("Blocked")
                .field("cause", cause)
                .field("lease", &completed.lease_id())
                .finish(),
        }
    }
}

/// One validated hardware completion and any recovered transfer owner.
#[derive(Debug)]
pub enum CompletedCommand {
    /// Read/write command completion.
    Transfer {
        completion: NvmeCompletion,
        ownership: CompletedOwnership,
    },
    /// Command with no transfer allocation.
    Control(NvmeCompletion),
}

/// Completion parsing or ownership failure.
#[derive(Debug)]
pub enum PollError {
    /// The requested I/O queue is not owned by this controller.
    InvalidQueue,
    /// Doorbell register geometry is invalid.
    Register(NvmeRegisterError),
    /// Shared completion memory could not be read.
    Shared(DmaLeaseError),
    /// Device tags do not identify a unique pending command.
    InvalidCompletion(NvmeCompletion),
    /// Registry rejected a validated completion transition.
    Ownership(DmaLeaseError),
    /// A prior fault requires controller reset.
    QueueFault,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_api::abi::driver::PackedPciLocation;

    fn queue() -> DmaQueueIdentity {
        DmaQueueIdentity::new(PackedPciLocation::new(0, 0, 1, 0), 4, 7)
            .expect("non-null device and generation")
    }

    fn completion(submission_head: u16, submission_queue: u16, command_id: u16) -> NvmeCompletion {
        NvmeCompletion::from_dwords([
            0,
            0,
            u32::from(submission_head) | (u32::from(submission_queue) << 16),
            u32::from(command_id) | (1 << 16),
        ])
    }

    #[test]
    fn completion_tags_require_queue_slot_and_pending_owner() {
        assert!(completion_tags_valid(completion(1, 4, 2), queue(), 8, true));
        assert!(!completion_tags_valid(
            completion(1, 3, 2),
            queue(),
            8,
            true
        ));
        assert!(!completion_tags_valid(
            completion(8, 4, 2),
            queue(),
            8,
            true
        ));
        assert!(!completion_tags_valid(
            completion(1, 4, 8),
            queue(),
            8,
            true
        ));
        assert!(!completion_tags_valid(
            completion(1, 4, 2),
            queue(),
            8,
            false
        ));
    }

    #[test]
    fn command_ids_are_recycled_independently_of_submission_order() {
        let mut pool = CommandIdPool::new(4);
        let first = pool.acquire().expect("first command id");
        let second = pool.acquire().expect("second command id");
        assert_ne!(first, second);

        // A later SQ entry may complete first. Its CID becomes reusable even
        // though the earlier command remains outstanding.
        pool.release(second);
        assert_eq!(pool.acquire(), Some(second));
        assert_ne!(pool.acquire(), Some(first));

        pool.release(first);
        assert_eq!(pool.acquire(), Some(first));
    }
}
