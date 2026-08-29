use alloc::boxed::Box;
use alloc::vec::Vec;
use core::num::NonZeroU16;

use kernel_api::dma::{CpuDmaLease, DmaQueueIdentity};

use crate::controller::NvmeAdminController;
use crate::protocol::{AdminCommand, CompletionStatus, IoTransfer};
use crate::queue::{
    CompletedCommand, NvmeQueue, PollError, PreparedQueuePair, QueueActivationError, QueueMemory,
    QueuePrepareError, QueueSubmission, SubmitError, SubmitFailure,
};

/// Failure while requesting the controller's I/O queue allocation budget.
#[derive(Debug)]
pub enum QueueBudgetCause {
    /// The Set Features command did not cross the Admin doorbell boundary.
    Submit(SubmitFailure),
    /// Admin completion parsing or ownership validation failed.
    Poll(PollError),
    /// The Admin queue returned a completion for a different command shape.
    UnexpectedCompletion,
    /// The controller rejected the Number of Queues feature request.
    ControllerRejected(CompletionStatus),
    /// Completion DW0 could not represent a valid non-zero queue count.
    InvalidAllocatedCount,
}

/// Queue-budget failure retaining the ready Admin controller owner.
pub struct QueueBudgetError {
    /// Machine-readable failure reason.
    pub cause: QueueBudgetCause,
    /// Controller owner; an accepted command failure may require reset policy.
    pub controller: NvmeAdminController,
}

impl core::fmt::Debug for QueueBudgetError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("QueueBudgetError")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

/// One accepted Number of Queues request awaiting its unique completion.
pub struct QueueBudgetRequest {
    controller: NvmeAdminController,
    requested: NonZeroU16,
    command_id: u16,
}

/// Result of one queue-budget completion observation.
pub enum QueueBudgetPoll {
    /// No completion with the current Admin phase was visible.
    Waiting(QueueBudgetRequest),
    /// The controller returned a validated queue allocation budget.
    Ready(IoQueueProvisioner),
}

impl NvmeAdminController {
    /// Request up to `requested` I/O submission/completion queue pairs.
    ///
    /// # Errors
    /// Returns the complete controller if publication fails before acceptance.
    pub fn request_io_queues(
        self,
        requested: NonZeroU16,
    ) -> Result<QueueBudgetRequest, QueueBudgetError> {
        let command = AdminCommand::request_io_queues(requested);
        let submission = match self.admin_queue.submit_admin(&self.registers, command) {
            Ok(submission) => submission,
            Err(cause) => {
                return Err(QueueBudgetError {
                    cause: QueueBudgetCause::Submit(cause),
                    controller: self,
                });
            }
        };
        Ok(QueueBudgetRequest {
            controller: self,
            requested,
            command_id: submission.command_id(),
        })
    }
}

impl QueueBudgetRequest {
    /// Observe the Admin queue once without imposing a wait policy.
    ///
    /// # Errors
    /// Returns the controller owner if completion parsing, command identity, or
    /// the allocated count is invalid. An accepted request is never retried
    /// merely because this method reports an error.
    pub fn poll(self) -> Result<QueueBudgetPoll, QueueBudgetError> {
        let completed = match self
            .controller
            .admin_queue
            .poll_completion(&self.controller.registers)
        {
            Ok(completed) => completed,
            Err(cause) => {
                return Err(QueueBudgetError {
                    cause: QueueBudgetCause::Poll(cause),
                    controller: self.controller,
                });
            }
        };
        let Some(completed) = completed else {
            return Ok(QueueBudgetPoll::Waiting(self));
        };
        let CompletedCommand::Control(completion) = completed else {
            return Err(QueueBudgetError {
                cause: QueueBudgetCause::UnexpectedCompletion,
                controller: self.controller,
            });
        };
        if completion.command_id() != self.command_id {
            return Err(QueueBudgetError {
                cause: QueueBudgetCause::UnexpectedCompletion,
                controller: self.controller,
            });
        }
        if !completion.status().is_success() {
            return Err(QueueBudgetError {
                cause: QueueBudgetCause::ControllerRejected(completion.status()),
                controller: self.controller,
            });
        }
        let Some(queue_limit) = allocated_queue_limit(completion.result(), self.requested) else {
            return Err(QueueBudgetError {
                cause: QueueBudgetCause::InvalidAllocatedCount,
                controller: self.controller,
            });
        };
        Ok(QueueBudgetPoll::Ready(IoQueueProvisioner {
            controller: self.controller,
            queue_limit,
            io_queues: Vec::new(),
        }))
    }
}

fn allocated_queue_limit(result: u32, requested: NonZeroU16) -> Option<NonZeroU16> {
    let submission = (result as u16).checked_add(1)?;
    let completion = ((result >> 16) as u16).checked_add(1)?;
    NonZeroU16::new(requested.get().min(submission).min(completion))
}

/// Invalid input rejected before any I/O queue memory becomes device-active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueInputError {
    /// The controller's allocated queue budget is exhausted.
    QueueLimit,
    /// Queue depth is unsupported by the controller or cannot hold work.
    InvalidDepth,
    /// A non-zero queue generation could not be established.
    InvalidGeneration,
    /// Runtime metadata could not be reserved before hardware publication.
    MetadataAllocation,
}

/// Stage of the two-command I/O queue creation protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueCreationStage {
    /// Create I/O Completion Queue has been published.
    Completion,
    /// The completion queue exists and Create I/O Submission Queue is pending.
    Submission,
}

/// Failure after queue RAM became device-active.
#[derive(Debug)]
pub enum ActiveQueueCreateCause {
    /// A validated Admin command could not be constructed from the queue state.
    InvalidCommand,
    /// Admin command publication failed before that command was accepted.
    Publish(SubmitFailure),
    /// Admin completion did not identify the sole provisioning command.
    UnexpectedCompletion,
    /// The controller completed a creation command with an error status.
    ControllerRejected {
        /// Command stage rejected by the controller.
        stage: QueueCreationStage,
        /// Raw validated completion status.
        status: CompletionStatus,
    },
}

/// I/O queue creation failure retaining every DMA/controller owner.
pub enum QueueCreateError {
    /// Input was rejected while both allocations remained CPU-owned.
    Input {
        cause: QueueInputError,
        provisioner: Box<IoQueueProvisioner>,
        memory: QueueMemory,
    },
    /// Shared preparation failed; the nested error retains both allocations.
    Prepare {
        provisioner: Box<IoQueueProvisioner>,
        cause: QueuePrepareError,
    },
    /// Shared activation failed; the nested error retains both allocations.
    Activate {
        provisioner: Box<IoQueueProvisioner>,
        cause: QueueActivationError,
    },
    /// Queue RAM is active and must remain retained until deletion or reset.
    Active {
        cause: ActiveQueueCreateCause,
        provisioner: Box<IoQueueProvisioner>,
        queue: Box<NvmeQueue>,
    },
    /// Completion parsing failed while an Admin creation command is accepted.
    Poll {
        cause: PollError,
        creation: IoQueueCreation,
    },
}

impl core::fmt::Debug for QueueCreateError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Input { cause, .. } => formatter.debug_tuple("Input").field(cause).finish(),
            Self::Prepare { cause, .. } => formatter.debug_tuple("Prepare").field(cause).finish(),
            Self::Activate { cause, .. } => formatter.debug_tuple("Activate").field(cause).finish(),
            Self::Active { cause, .. } => formatter.debug_tuple("Active").field(cause).finish(),
            Self::Poll { cause, .. } => formatter.debug_tuple("Poll").field(cause).finish(),
        }
    }
}

/// Controller owner with a validated allocation budget and zero or more I/O queues.
pub struct IoQueueProvisioner {
    controller: NvmeAdminController,
    queue_limit: NonZeroU16,
    io_queues: Vec<NvmeQueue>,
}

impl IoQueueProvisioner {
    /// Maximum number of queue pairs admitted by the current controller generation.
    pub const fn queue_limit(&self) -> NonZeroU16 {
        self.queue_limit
    }

    /// Number of queue pairs whose CQ and SQ commands completed successfully.
    pub fn queue_count(&self) -> usize {
        self.io_queues.len()
    }

    /// Prepare and publish the completion half of the next sequential I/O queue.
    ///
    /// Metadata capacity is reserved before either DMA allocation becomes
    /// shared. Queue identifiers are assigned sequentially from one, so a Vec
    /// index cannot become an independent queue-identity authority.
    ///
    /// # Errors
    /// Every failure retains the provisioner and every queue-memory state.
    pub fn begin_next_queue(
        mut self,
        depth: u16,
        generation: u64,
        memory: QueueMemory,
    ) -> Result<IoQueueCreation, QueueCreateError> {
        let next = self.io_queues.len().checked_add(1);
        let Some(queue_id) = next.and_then(|value| u16::try_from(value).ok()) else {
            return Err(input_error(QueueInputError::QueueLimit, self, memory));
        };
        if queue_id > self.queue_limit.get() {
            return Err(input_error(QueueInputError::QueueLimit, self, memory));
        }
        if depth < 2
            || u32::from(depth) > self.controller.registers.capabilities().max_queue_entries()
        {
            return Err(input_error(QueueInputError::InvalidDepth, self, memory));
        }
        if self.io_queues.try_reserve(1).is_err() {
            return Err(input_error(
                QueueInputError::MetadataAllocation,
                self,
                memory,
            ));
        }
        let device = self.controller.admin_queue.identity().device();
        let Some(identity) = DmaQueueIdentity::new(device, queue_id, generation) else {
            return Err(input_error(
                QueueInputError::InvalidGeneration,
                self,
                memory,
            ));
        };
        let prepared = match PreparedQueuePair::prepare(identity, depth, memory) {
            Ok(prepared) => prepared,
            Err(cause) => {
                return Err(QueueCreateError::Prepare {
                    provisioner: Box::new(self),
                    cause,
                });
            }
        };
        let queue = match prepared.activate() {
            Ok(queue) => Box::new(queue),
            Err(cause) => {
                return Err(QueueCreateError::Activate {
                    provisioner: Box::new(self),
                    cause,
                });
            }
        };
        let (_, completion_address) = queue.device_addresses();
        let Some(command) =
            AdminCommand::create_io_completion_queue(queue_id, depth, completion_address)
        else {
            return Err(active_error(
                ActiveQueueCreateCause::InvalidCommand,
                self,
                queue,
            ));
        };
        let submission = match self
            .controller
            .admin_queue
            .submit_admin(&self.controller.registers, command)
        {
            Ok(submission) => submission,
            Err(cause) => {
                return Err(active_error(
                    ActiveQueueCreateCause::Publish(cause),
                    self,
                    queue,
                ));
            }
        };
        Ok(IoQueueCreation {
            provisioner: Box::new(self),
            queue,
            stage: QueueCreationStage::Completion,
            command_id: submission.command_id(),
        })
    }

    /// Finish provisioning after at least one queue pair exists.
    ///
    /// # Errors
    /// Returns the unconsumed provisioner if no usable I/O queue was created.
    pub fn finish(self) -> Result<NvmeController, Box<Self>> {
        if self.io_queues.is_empty() {
            return Err(Box::new(self));
        }
        let NvmeAdminController {
            registers,
            admin_queue,
        } = self.controller;
        Ok(NvmeController {
            registers,
            admin_queue,
            io_queues: self.io_queues,
        })
    }
}

fn input_error(
    cause: QueueInputError,
    provisioner: IoQueueProvisioner,
    memory: QueueMemory,
) -> QueueCreateError {
    QueueCreateError::Input {
        cause,
        provisioner: Box::new(provisioner),
        memory,
    }
}

fn active_error(
    cause: ActiveQueueCreateCause,
    provisioner: IoQueueProvisioner,
    queue: Box<NvmeQueue>,
) -> QueueCreateError {
    QueueCreateError::Active {
        cause,
        provisioner: Box::new(provisioner),
        queue,
    }
}

/// Two-command I/O queue creation owner.
pub struct IoQueueCreation {
    provisioner: Box<IoQueueProvisioner>,
    queue: Box<NvmeQueue>,
    stage: QueueCreationStage,
    command_id: u16,
}

/// Result of observing one creation completion.
pub enum IoQueueCreatePoll {
    /// The current Admin command has not completed, or the next stage was just published.
    Waiting(IoQueueCreation),
    /// Both queue creation commands completed and the queue joined the controller.
    Ready(IoQueueProvisioner),
}

impl IoQueueCreation {
    /// Current accepted command stage.
    pub const fn stage(&self) -> QueueCreationStage {
        self.stage
    }

    /// Observe one Admin completion and advance CQ creation before SQ creation.
    ///
    /// # Errors
    /// Parsing failures retain the exact in-progress state. Rejected or
    /// publication failures retain active queue RAM and the provisioner.
    pub fn poll(mut self) -> Result<IoQueueCreatePoll, QueueCreateError> {
        let completion = match self
            .provisioner
            .controller
            .admin_queue
            .poll_completion(&self.provisioner.controller.registers)
        {
            Ok(completion) => completion,
            Err(cause) => {
                return Err(QueueCreateError::Poll {
                    cause,
                    creation: self,
                });
            }
        };
        let Some(completion) = completion else {
            return Ok(IoQueueCreatePoll::Waiting(self));
        };
        let CompletedCommand::Control(completion) = completion else {
            return Err(self.into_active_error(ActiveQueueCreateCause::UnexpectedCompletion));
        };
        if completion.command_id() != self.command_id {
            return Err(self.into_active_error(ActiveQueueCreateCause::UnexpectedCompletion));
        }
        if !completion.status().is_success() {
            let cause = ActiveQueueCreateCause::ControllerRejected {
                stage: self.stage,
                status: completion.status(),
            };
            return Err(self.into_active_error(cause));
        }
        match self.stage {
            QueueCreationStage::Completion => {
                let queue_id = self.queue.identity().index();
                let depth = self.queue_depth();
                let (submission_address, _) = self.queue.device_addresses();
                let Some(command) = AdminCommand::create_io_submission_queue(
                    queue_id,
                    depth,
                    queue_id,
                    submission_address,
                ) else {
                    return Err(self.into_active_error(ActiveQueueCreateCause::InvalidCommand));
                };
                let submission = match self
                    .provisioner
                    .controller
                    .admin_queue
                    .submit_admin(&self.provisioner.controller.registers, command)
                {
                    Ok(submission) => submission,
                    Err(cause) => {
                        return Err(self.into_active_error(ActiveQueueCreateCause::Publish(cause)));
                    }
                };
                self.stage = QueueCreationStage::Submission;
                self.command_id = submission.command_id();
                Ok(IoQueueCreatePoll::Waiting(self))
            }
            QueueCreationStage::Submission => {
                self.provisioner.io_queues.push(*self.queue);
                Ok(IoQueueCreatePoll::Ready(*self.provisioner))
            }
        }
    }

    fn queue_depth(&self) -> u16 {
        self.queue.depth()
    }

    fn into_active_error(self, cause: ActiveQueueCreateCause) -> QueueCreateError {
        QueueCreateError::Active {
            cause,
            provisioner: self.provisioner,
            queue: self.queue,
        }
    }
}

/// Ready controller with one or more sequential I/O queue pairs.
pub struct NvmeController {
    registers: crate::NvmeRegisters,
    admin_queue: Box<NvmeQueue>,
    io_queues: Vec<NvmeQueue>,
}

impl NvmeController {
    /// Whether the geometry was identified by this controller generation.
    pub fn owns_namespace(&self, namespace: crate::NamespaceInfo) -> bool {
        namespace.controller_identity() == self.admin_queue.identity()
    }

    /// PCI function that owns this controller generation.
    pub fn device(&self) -> kernel_api::abi::driver::PackedPciLocation {
        self.admin_queue.identity().device()
    }

    /// Number of active I/O queue pairs.
    pub fn queue_count(&self) -> usize {
        self.io_queues.len()
    }

    /// Depth of one active sequential I/O queue.
    pub fn queue_depth(&self, queue_id: u16) -> Option<u16> {
        self.queue(queue_id).map(NvmeQueue::depth)
    }

    /// Submit one transfer to a sequential one-based I/O queue identifier.
    ///
    /// # Errors
    /// An invalid queue returns the unchanged CPU lease. Other failures retain
    /// the precise pre-acceptance DMA state described by [`SubmitError`].
    pub fn submit_transfer(
        &self,
        queue_id: u16,
        transfer: IoTransfer,
        lease: CpuDmaLease,
    ) -> Result<QueueSubmission, SubmitError> {
        if !transfer.belongs_to(self.admin_queue.identity()) {
            return Err(SubmitError::Cpu {
                cause: SubmitFailure::InvalidTransfer,
                lease,
            });
        }
        let Some(queue) = self.queue(queue_id) else {
            return Err(SubmitError::Cpu {
                cause: SubmitFailure::InvalidQueue,
                lease,
            });
        };
        queue.submit_transfer(&self.registers, transfer, lease)
    }

    /// Submit a flush to one active I/O queue.
    ///
    /// # Errors
    /// Returns a pre-acceptance queue, register, or command failure.
    pub fn submit_flush(
        &self,
        queue_id: u16,
        namespace: u32,
    ) -> Result<QueueSubmission, SubmitFailure> {
        self.queue(queue_id)
            .ok_or(SubmitFailure::InvalidQueue)?
            .submit_flush(&self.registers, namespace)
    }

    /// Parse at most one completion from an active I/O queue.
    ///
    /// # Errors
    /// Returns a queue identity, device tag, register, or DMA ownership failure.
    pub fn poll_completion(&self, queue_id: u16) -> Result<Option<CompletedCommand>, PollError> {
        self.queue(queue_id)
            .ok_or(PollError::InvalidQueue)?
            .poll_completion(&self.registers)
    }

    fn queue(&self, queue_id: u16) -> Option<&NvmeQueue> {
        let index = usize::from(queue_id.checked_sub(1)?);
        let queue = self.io_queues.get(index)?;
        (queue.identity().index() == queue_id).then_some(queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocated_queue_count_is_non_zero_checked_and_request_bounded() {
        let requested = NonZeroU16::new(8).expect("non-zero request");
        assert_eq!(
            allocated_queue_limit(3 | (5 << 16), requested),
            NonZeroU16::new(4)
        );
        assert_eq!(
            allocated_queue_limit(15 | (15 << 16), requested),
            Some(requested)
        );
        assert_eq!(allocated_queue_limit(u32::MAX, requested), None);
    }
}
