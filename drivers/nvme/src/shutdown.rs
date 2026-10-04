//! One-way controller reset and DMA reconciliation ownership.

use alloc::vec::Vec;

use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{DmaLeaseError, DmaQueueIdentity};

use crate::queue::{QueueResetError, ReconciledResetCommand, ResetDmaPhase, ResetNvmeQueue};
use crate::{NvmeController, NvmeRegisterError, NvmeRegisters};

/// Reset admission failure retaining the operational controller owner.
pub enum ControllerResetStartError {
    /// The requested generation does not supersede the active generation.
    InvalidGeneration {
        requested: u64,
        controller: NvmeController,
    },
    /// Metadata for the one-way reset owner could not be reserved.
    MetadataAllocation { controller: NvmeController },
    /// CC.EN could not be cleared; the controller remains operationally owned.
    Register {
        cause: NvmeRegisterError,
        controller: NvmeController,
    },
}

impl core::fmt::Debug for ControllerResetStartError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidGeneration { requested, .. } => formatter
                .debug_struct("InvalidGeneration")
                .field("requested", requested)
                .finish_non_exhaustive(),
            Self::MetadataAllocation { .. } => {
                formatter.write_str("MetadataAllocation { controller: .. }")
            }
            Self::Register { cause, .. } => formatter
                .debug_struct("Register")
                .field("cause", cause)
                .finish_non_exhaustive(),
        }
    }
}

/// Controller owner after queue submission authority is gone and CC.EN is clear.
pub struct ControllerResetting {
    registers: NvmeRegisters,
    device: PackedPciLocation,
    generation: u64,
    admin_queue: ResetNvmeQueue,
    io_queues: Vec<ResetNvmeQueue>,
}

/// One hardware reset observation.
pub enum ControllerResetPoll {
    /// CSTS.RDY remains set.
    Waiting(ControllerResetting),
    /// CSTS.RDY is clear, so old queue generations are unreachable.
    Reset(ControllerReset),
}

/// Failed reset observation retaining the one-way controller owner.
pub struct ControllerResetPollError {
    /// Register access failure.
    pub cause: NvmeRegisterError,
    /// Owner that must remain in reset handling.
    pub controller: ControllerResetting,
}

impl core::fmt::Debug for ControllerResetPollError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ControllerResetPollError")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

/// Controller reset fact plus every old-generation DMA owner.
pub struct ControllerReset {
    registers: NvmeRegisters,
    device: PackedPciLocation,
    generation: u64,
    admin_queue: ResetNvmeQueue,
    io_queues: Vec<ResetNvmeQueue>,
}

/// Which queue allocation could not advance through reset or reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerDmaLocation {
    /// Old queue generation owning the allocation.
    pub queue: DmaQueueIdentity,
    /// Allocation role within that queue.
    pub phase: ControllerDmaPhase,
}

/// Allocation role retained by a partial DMA transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerDmaPhase {
    /// Host-written submission queue RAM.
    Submission,
    /// Controller-written completion queue RAM.
    Completion,
    /// One accepted transfer command.
    Transfer { command_id: u16 },
}

/// Partial reset revocation retaining every controller/DMA owner.
pub struct ControllerDmaResetError {
    /// Registry transition failure.
    pub cause: DmaLeaseError,
    /// Exact old-generation allocation that remains blocked.
    pub location: ControllerDmaLocation,
    /// One-way owner containing both completed and incomplete revocations.
    pub controller: ControllerReset,
}

impl core::fmt::Debug for ControllerDmaResetError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ControllerDmaResetError")
            .field("cause", &self.cause)
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

/// Reset-revoked controller waiting for synchronous IOTLB invalidation.
pub struct ControllerDmaRevoked {
    reset: ControllerReset,
}

/// Controller owner whose reset and IOTLB facts permit CPU reconciliation.
pub struct ControllerDmaReconciliation {
    reset: ControllerReset,
}

/// Partial reconciliation retaining every revoked or recovered allocation.
pub struct ControllerDmaReconcileError {
    /// Registry transition failure.
    pub cause: DmaLeaseError,
    /// Exact allocation that remains inaccessible to the CPU.
    pub location: ControllerDmaLocation,
    /// Owner that can retry without repeating the IOTLB proof boundary.
    pub controller: ControllerDmaReconciliation,
}

impl core::fmt::Debug for ControllerDmaReconcileError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ControllerDmaReconcileError")
            .field("cause", &self.cause)
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

/// Controller whose old queue and transfer allocations are CPU-owned again.
pub struct ReconciledNvmeController {
    reset: ControllerReset,
}

/// One reset-aborted I/O command and its queue identity.
pub struct ReconciledIoCommand {
    /// One-based I/O queue identifier.
    pub queue_id: u16,
    /// Command identifier within that queue generation.
    pub command_id: u16,
    /// Recovered control or transfer owner.
    pub command: ReconciledResetCommand,
}

/// Fallible final close retaining all unreleased queue-memory owners.
pub struct ControllerCloseError {
    /// Unmap or phase failure.
    pub cause: DmaLeaseError,
    /// Exact queue allocation or undrained command blocking close.
    pub location: ControllerDmaLocation,
    /// Owner that can drain commands or retry an unmap failure.
    pub controller: ReconciledNvmeController,
}

impl core::fmt::Debug for ControllerCloseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ControllerCloseError")
            .field("cause", &self.cause)
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

impl NvmeController {
    /// Irreversibly close queue submission authority and request controller reset.
    ///
    /// # Errors
    /// Invalid generation, metadata reservation, and register failures return
    /// the complete still-operational controller owner. Success consumes the
    /// controller into a state that can only advance toward reset/reclamation.
    pub fn begin_reset(
        self,
        generation: u64,
    ) -> Result<ControllerResetting, ControllerResetStartError> {
        let active_generation = self.admin_queue.identity().generation();
        if generation <= active_generation {
            return Err(ControllerResetStartError::InvalidGeneration {
                requested: generation,
                controller: self,
            });
        }
        let mut reset_io_queues = Vec::new();
        if reset_io_queues
            .try_reserve_exact(self.io_queues.len())
            .is_err()
        {
            return Err(ControllerResetStartError::MetadataAllocation { controller: self });
        }
        if let Err(cause) = self.registers.request_disable() {
            return Err(ControllerResetStartError::Register {
                cause,
                controller: self,
            });
        }
        let Self {
            registers,
            admin_queue,
            io_queues,
        } = self;
        let device = admin_queue.identity().device();
        for queue in io_queues {
            reset_io_queues.push(queue.into_reset());
        }
        Ok(ControllerResetting {
            registers,
            device,
            generation,
            admin_queue: (*admin_queue).into_reset(),
            io_queues: reset_io_queues,
        })
    }
}

impl ControllerResetting {
    /// Observe one controller-reset progress step.
    ///
    /// # Errors
    /// A CSTS access failure returns the unchanged one-way reset owner.
    #[expect(
        clippy::result_large_err,
        reason = "a register failure must return the complete reset owner without allocating during failure handling"
    )]
    pub fn poll(self) -> Result<ControllerResetPoll, ControllerResetPollError> {
        let status = match self.registers.status() {
            Ok(status) => status,
            Err(cause) => {
                return Err(ControllerResetPollError {
                    cause,
                    controller: self,
                });
            }
        };
        if status.ready() {
            Ok(ControllerResetPoll::Waiting(self))
        } else {
            Ok(ControllerResetPoll::Reset(ControllerReset {
                registers: self.registers,
                device: self.device,
                generation: self.generation,
                admin_queue: self.admin_queue,
                io_queues: self.io_queues,
            }))
        }
    }
}

impl ControllerReset {
    /// Close a stopped controller's idle queues. This path does not recover
    /// aborted transfers. Each unmap completes its own translation barrier
    /// before freeing backing RAM; a failed close retains the full owner.
    ///
    /// # Errors
    /// A pending command, registry failure or unmap failure returns the exact
    /// partial retirement state. No transfer notification is fabricated.
    #[expect(
        clippy::result_large_err,
        reason = "partial retirement returns every unreleased owner without allocating on failure"
    )]
    #[expect(
        unsafe_code,
        reason = "this reset typestate proves controller quiescence for all owned queue allocations"
    )]
    pub fn close_idle(mut self) -> Result<(), IdleControllerCloseError> {
        let identity = self.admin_queue.identity();
        // SAFETY: this typestate is created only after CC.EN is cleared and
        // CSTS.RDY is observed clear. The queue rejects pending commands.
        let result = unsafe { self.admin_queue.close_idle_metadata() };
        if let Err(error) = result {
            return Err(self.idle_close_error(error, identity));
        }
        for index in 0..self.io_queues.len() {
            let queue = &mut self.io_queues[index];
            let identity = queue.identity();
            // SAFETY: the same reset observation covers this controller's
            // unique I/O queue pair, and the pending table is checked first.
            let result = unsafe { queue.close_idle_metadata() };
            if let Err(error) = result {
                return Err(self.idle_close_error(error, identity));
            }
        }
        Ok(())
    }

    fn idle_close_error(
        self,
        error: QueueResetError,
        queue: DmaQueueIdentity,
    ) -> IdleControllerCloseError {
        IdleControllerCloseError {
            cause: error.cause,
            location: ControllerDmaLocation {
                queue,
                phase: map_phase(error.phase),
            },
            controller: self,
        }
    }

    /// Record reset revocation for all shared queue RAM and accepted transfers.
    ///
    /// # Errors
    /// The first registry failure returns this owner with exact partial progress.
    #[expect(
        clippy::result_large_err,
        reason = "partial DMA revocation must retain every queue owner without allocating on the error path"
    )]
    pub fn revoke_dma(mut self) -> Result<ControllerDmaRevoked, ControllerDmaResetError> {
        let admin_identity = self.admin_queue.identity();
        if let Err(error) = self.admin_queue.revoke_all(self.device, self.generation) {
            return Err(self.reset_error(error, admin_identity));
        }
        for index in 0..self.io_queues.len() {
            let Some(queue) = self.io_queues.get_mut(index) else {
                continue;
            };
            if let Err(error) = queue.revoke_all(self.device, self.generation) {
                let identity = queue.identity();
                return Err(self.reset_error(error, identity));
            }
        }
        Ok(ControllerDmaRevoked { reset: self })
    }

    fn reset_error(
        self,
        error: QueueResetError,
        queue: DmaQueueIdentity,
    ) -> ControllerDmaResetError {
        ControllerDmaResetError {
            cause: error.cause,
            location: ControllerDmaLocation {
                queue,
                phase: map_phase(error.phase),
            },
            controller: self,
        }
    }
}

/// Partial idle retirement retaining stopped hardware and all unreleased RAM.
pub struct IdleControllerCloseError {
    pub cause: DmaLeaseError,
    pub location: ControllerDmaLocation,
    pub controller: ControllerReset,
}

impl core::fmt::Debug for IdleControllerCloseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IdleControllerCloseError")
            .field("cause", &self.cause)
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

impl ControllerDmaRevoked {
    /// Enter reconciliation after synchronous IOTLB and Device-TLB invalidation.
    ///
    /// # Safety
    ///
    /// Every stale IOVA translation for `self.device()` must have been removed,
    /// including ATS Device-TLB entries, and hardware completion of that
    /// invalidation must have been observed.
    #[expect(
        unsafe_code,
        reason = "the caller must establish hardware IOTLB and Device-TLB invalidation"
    )]
    pub unsafe fn after_iotlb_invalidation(self) -> ControllerDmaReconciliation {
        ControllerDmaReconciliation { reset: self.reset }
    }

    /// PCI function whose stale translations remain quarantined.
    pub const fn device(&self) -> PackedPciLocation {
        self.reset.device
    }

    /// Reset generation that revoked all old queue identities.
    pub const fn generation(&self) -> u64 {
        self.reset.generation
    }
}

impl ControllerDmaReconciliation {
    /// Restore CPU ownership for every reset-revoked allocation.
    ///
    /// # Errors
    /// The first registry failure returns this owner with exact partial progress.
    #[expect(
        clippy::result_large_err,
        reason = "failed reconciliation returns all recovered and unreconciled DMA owners without an allocation"
    )]
    pub fn advance(mut self) -> Result<ReconciledNvmeController, ControllerDmaReconcileError> {
        if let Err(error) = self
            .reset
            .admin_queue
            .reconcile_all(self.reset.device, self.reset.generation)
        {
            let queue = self.reset.admin_queue.identity();
            return Err(self.reconcile_error(error, queue));
        }
        for index in 0..self.reset.io_queues.len() {
            let Some(queue) = self.reset.io_queues.get_mut(index) else {
                continue;
            };
            if let Err(error) = queue.reconcile_all(self.reset.device, self.reset.generation) {
                let identity = queue.identity();
                return Err(self.reconcile_error(error, identity));
            }
        }
        Ok(ReconciledNvmeController { reset: self.reset })
    }

    fn reconcile_error(
        self,
        error: QueueResetError,
        queue: DmaQueueIdentity,
    ) -> ControllerDmaReconcileError {
        ControllerDmaReconcileError {
            cause: error.cause,
            location: ControllerDmaLocation {
                queue,
                phase: map_phase(error.phase),
            },
            controller: self,
        }
    }
}

impl ReconciledNvmeController {
    /// PCI function whose old-generation DMA authority has been reconciled.
    pub const fn device(&self) -> PackedPciLocation {
        self.reset.device
    }

    /// Reset generation used for reconciliation.
    pub const fn generation(&self) -> u64 {
        self.reset.generation
    }

    /// Number of one-based I/O queues retained by this reset owner.
    pub fn io_queue_count(&self) -> usize {
        self.reset.io_queues.len()
    }

    /// Consume one reset-aborted I/O command exactly once.
    pub fn take_io_command(
        &mut self,
        queue_id: u16,
        command_id: u16,
    ) -> Option<ReconciledResetCommand> {
        let index = usize::from(queue_id.checked_sub(1)?);
        let queue = self.reset.io_queues.get_mut(index)?;
        (queue.identity().index() == queue_id)
            .then(|| queue.take_reconciled_command(command_id))
            .flatten()
    }

    /// Consume the next reset-aborted I/O command without allocating.
    pub fn take_next_io_command(&mut self) -> Option<ReconciledIoCommand> {
        for queue in &mut self.reset.io_queues {
            let Some((command_id, command)) = queue.take_next_reconciled_command() else {
                continue;
            };
            return Some(ReconciledIoCommand {
                queue_id: queue.identity().index(),
                command_id,
                command,
            });
        }
        None
    }

    /// Consume the next reset-aborted Admin command, if startup left one active.
    pub fn take_next_admin_command(&mut self) -> Option<(u16, ReconciledResetCommand)> {
        self.reset.admin_queue.take_next_reconciled_command()
    }

    /// Explicitly close every queue-memory allocation.
    ///
    /// # Errors
    /// Pending commands, unmap failures, and reconciliation-state errors retain
    /// the complete owner. Repeated calls retry only the first incomplete close.
    #[expect(
        clippy::result_large_err,
        reason = "unmap failure must preserve the remaining controller resources without requiring new memory"
    )]
    pub fn close(mut self) -> Result<(), ControllerCloseError> {
        let admin_identity = self.reset.admin_queue.identity();
        if let Err(error) = self
            .reset
            .admin_queue
            .close_metadata(self.reset.device, self.reset.generation)
        {
            return Err(self.close_error(error, admin_identity));
        }
        for index in 0..self.reset.io_queues.len() {
            let Some(queue) = self.reset.io_queues.get_mut(index) else {
                continue;
            };
            if let Err(error) = queue.close_metadata(self.reset.device, self.reset.generation) {
                let identity = queue.identity();
                return Err(self.close_error(error, identity));
            }
        }
        if !self.reset.admin_queue.is_closed()
            || self.reset.io_queues.iter().any(|queue| !queue.is_closed())
        {
            return Err(ControllerCloseError {
                cause: DmaLeaseError::InvalidState,
                location: ControllerDmaLocation {
                    queue: admin_identity,
                    phase: ControllerDmaPhase::Submission,
                },
                controller: self,
            });
        }
        let ControllerReset {
            registers,
            admin_queue,
            io_queues,
            ..
        } = self.reset;
        drop((registers, admin_queue, io_queues));
        Ok(())
    }

    fn close_error(self, error: QueueResetError, queue: DmaQueueIdentity) -> ControllerCloseError {
        ControllerCloseError {
            cause: error.cause,
            location: ControllerDmaLocation {
                queue,
                phase: map_phase(error.phase),
            },
            controller: self,
        }
    }
}

const fn map_phase(phase: ResetDmaPhase) -> ControllerDmaPhase {
    match phase {
        ResetDmaPhase::Submission => ControllerDmaPhase::Submission,
        ResetDmaPhase::Completion => ControllerDmaPhase::Completion,
        ResetDmaPhase::Transfer { command_id } => ControllerDmaPhase::Transfer { command_id },
    }
}
