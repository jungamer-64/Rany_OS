//! One AHCI port owns its register aperture and every submitted DMA lease.
//!
//! Non-NCQ commands are serialized in slot zero. Submission has one hardware
//! acceptance boundary (PxCI); neither a timeout nor a task-file error is a
//! completion proof. Dropping an active port leaves its registry allocations
//! quarantined. Normal release requires the explicit, fallible `close` path.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use core::num::NonZeroUsize;
use core::sync::atomic::{Ordering, fence};
use hal::{MappedMmio, MmioAccessError};
use kernel_api::dma::{
    CompletedDmaLease, CpuDmaLease, DmaCloseError, DmaCompletionWitness, DmaDeviceAddress,
    DmaDirection, DmaLeaseError, DmaQueueIdentity, DmaQuiesceWitness, DmaTransitionError,
    InFlightDmaLease, PreparedDmaLease, PreparedSharedDmaLease, QuarantinedDmaLease,
    SharedDmaLease,
};

use crate::command::{
    AtaCommand, COMMAND_TABLE_OFFSET, CommandError, DmaAddressWidth, PORT_DMA_BYTES,
    RECEIVED_FIS_OFFSET,
};
use crate::types::DeviceType;

mod protocol;
mod registers;

pub use protocol::PortFault;
use protocol::{CompletionStatus, validate_transferred};
use registers::PortRegisters;

#[derive(Debug)]
pub enum OpenCause {
    Registers(MmioAccessError),
    QueueIndex,
    Memory(CommandError),
    Dma(DmaLeaseError),
    StopDeadline,
    DeviceType,
    Port(PortFault),
}

/// Initialization may fail at different DMA transitions, but never loses the
/// mapping or allocation capability. Prepared/shared owners cannot lend bytes.
#[derive(Debug)]
pub enum InitializationMemory {
    Cpu(CpuDmaLease),
    Prepared(PreparedSharedDmaLease),
    Shared(SharedDmaLease),
}

#[derive(Debug)]
pub struct PortOpenError {
    pub cause: OpenCause,
    pub registers: MappedMmio,
    pub memory: InitializationMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitCause {
    Busy,
    Quarantined(PortFault),
    Command(CommandError),
    Dma(DmaLeaseError),
    Port(PortFault),
}

/// A pre-doorbell failure returns the original CPU owner. If reverting the
/// preparation itself fails, the unchanged prepared capability is retained
/// instead, together with that distinct registry failure.
#[derive(Debug)]
pub enum RejectedBuffer {
    Cpu(CpuDmaLease),
    AbortFailed(DmaTransitionError<PreparedDmaLease>),
}

#[derive(Debug)]
pub struct SubmitError {
    pub cause: SubmitCause,
    pub buffer: RejectedBuffer,
}

#[derive(Debug)]
pub enum RetainedTransfer {
    Quarantined(QuarantinedDmaLease),
    InFlight(DmaTransitionError<InFlightDmaLease>),
    Completed(DmaTransitionError<CompletedDmaLease>),
}

#[derive(Debug)]
enum CommandState {
    Idle,
    Submitted {
        expected_bytes: usize,
        buffer: InFlightDmaLease,
    },
    Quarantined {
        cause: PortFault,
        transfer: Option<RetainedTransfer>,
    },
}

/// A completed transfer is returned as a CPU capability, never as a pointer or
/// independently retained slice. The caller still owns fallible final close.
#[derive(Debug)]
pub struct CommandCompletion {
    pub buffer: CpuDmaLease,
    pub transferred: usize,
}

#[derive(Debug)]
pub enum CommandPoll {
    Idle,
    Pending,
    Completed(CommandCompletion),
}

/// Shutdown preserves partial progress: a live port differs from an already
/// stopped engine whose DMA registry transition or final unmap failed.
#[derive(Debug)]
pub enum PortCloseError {
    CommandActive(AhciPort),
    Quarantined {
        cause: PortFault,
        registers: MappedMmio,
        queue: DmaQueueIdentity,
        memory: SharedDmaLease,
        transfer: Option<RetainedTransfer>,
    },
    StopDeadline(AhciPort),
    Quiesce {
        registers: MappedMmio,
        queue: DmaQueueIdentity,
        failure: DmaTransitionError<SharedDmaLease>,
    },
    Unmap(DmaCloseError),
}

#[derive(Debug)]
pub struct AhciPort {
    registers: PortRegisters,
    queue: DmaQueueIdentity,
    address_width: DmaAddressWidth,
    memory: SharedDmaLease,
    table_address: DmaDeviceAddress,
    state: CommandState,
}

impl AhciPort {
    /// Acquire one port using a reserved mapping and registry-owned metadata.
    /// `poll_budget` counts register samples for each engine stop phase.
    ///
    /// # Safety
    /// The resource boundary must establish that this is the AHCI aperture for
    /// exactly `queue.device()` and port `queue.index()`, with CAP.S64A matching
    /// `address_width`. The queue generation must be fresh for this acquisition.
    /// Firmware/other drivers must no longer issue commands or access these
    /// registers; any prior DMA allocations must remain live until engine stop.
    /// The platform must implement coherent DMA and ordered UC register access.
    ///
    /// # Errors
    /// Validation, engine-stop, and DMA failures return every acquired resource.
    /// No new DMA address is programmed until shared activation has succeeded.
    #[expect(
        unsafe_code,
        reason = "PCI identity and firmware handoff are external resource facts"
    )]
    pub unsafe fn attach(
        mapping: MappedMmio,
        queue: DmaQueueIdentity,
        address_width: DmaAddressWidth,
        mut memory: CpuDmaLease,
        poll_budget: NonZeroUsize,
    ) -> Result<Self, PortOpenError> {
        if queue.index() >= 32 {
            return Err(PortOpenError {
                cause: OpenCause::QueueIndex,
                registers: mapping,
                memory: InitializationMemory::Cpu(memory),
            });
        }
        if memory.byte_count().get() < PORT_DMA_BYTES {
            return Err(PortOpenError {
                cause: OpenCause::Memory(CommandError::BufferTooSmall),
                registers: mapping,
                memory: InitializationMemory::Cpu(memory),
            });
        }
        if memory.direction() != DmaDirection::Bidirectional {
            return Err(PortOpenError {
                cause: OpenCause::Memory(CommandError::Direction),
                registers: mapping,
                memory: InitializationMemory::Cpu(memory),
            });
        }
        let mut registers = match PortRegisters::new(mapping) {
            Ok(registers) => registers,
            Err((cause, mapping)) => {
                return Err(PortOpenError {
                    cause: OpenCause::Registers(cause),
                    registers: mapping,
                    memory: InitializationMemory::Cpu(memory),
                });
            }
        };
        if registers.stop(poll_budget).is_err() {
            return Err(PortOpenError {
                cause: OpenCause::StopDeadline,
                registers: registers.into_mapping(),
                memory: InitializationMemory::Cpu(memory),
            });
        }
        if registers.device_type() != DeviceType::Sata {
            return Err(PortOpenError {
                cause: OpenCause::DeviceType,
                registers: registers.into_mapping(),
                memory: InitializationMemory::Cpu(memory),
            });
        }
        if let Err(cause) = memory.write(|bytes| bytes.fill(0)) {
            return Err(PortOpenError {
                cause: OpenCause::Dma(cause),
                registers: registers.into_mapping(),
                memory: InitializationMemory::Cpu(memory),
            });
        }
        let prepared = match memory.prepare_shared(queue) {
            Ok(prepared) => prepared,
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                return Err(PortOpenError {
                    cause: OpenCause::Dma(cause),
                    registers: registers.into_mapping(),
                    memory: InitializationMemory::Cpu(memory),
                });
            }
        };
        let addresses = (|| {
            let descriptor = prepared.descriptor().map_err(OpenCause::Dma)?;
            let list = descriptor.device_address();
            address_width
                .validate(list, PORT_DMA_BYTES, 1024)
                .map_err(OpenCause::Memory)?;
            let received_fis = list
                .checked_add(RECEIVED_FIS_OFFSET)
                .ok_or(OpenCause::Memory(CommandError::AddressOverflow))?;
            let table = list
                .checked_add(COMMAND_TABLE_OFFSET)
                .ok_or(OpenCause::Memory(CommandError::AddressOverflow))?;
            Ok((list, received_fis, table))
        })();
        let (list, received_fis, table_address) = match addresses {
            Ok(addresses) => addresses,
            Err(cause) => {
                return Err(PortOpenError {
                    cause,
                    registers: registers.into_mapping(),
                    memory: InitializationMemory::Prepared(prepared),
                });
            }
        };
        let memory = match prepared.activate() {
            Ok(memory) => memory,
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                return Err(PortOpenError {
                    cause: OpenCause::Dma(cause),
                    registers: registers.into_mapping(),
                    memory: InitializationMemory::Prepared(memory),
                });
            }
        };
        fence(Ordering::SeqCst);
        registers.start(list, received_fis);
        if let Err(cause) = registers.observe().admission() {
            return Err(PortOpenError {
                cause: OpenCause::Port(cause),
                registers: registers.into_mapping(),
                memory: InitializationMemory::Shared(memory),
            });
        }
        Ok(Self {
            registers,
            queue,
            address_width,
            memory,
            table_address,
            state: CommandState::Idle,
        })
    }

    /// Consume a CPU buffer and submit exactly one validated non-NCQ command.
    /// No allocation or fallible operation follows the successful `arm` step.
    ///
    /// # Errors
    /// Rejection occurs before PxCI and returns ownership in `SubmitError`.
    pub fn submit(&mut self, command: AtaCommand, buffer: CpuDmaLease) -> Result<(), SubmitError> {
        let validation = match &self.state {
            CommandState::Idle => command
                .validate_buffer(buffer.byte_count().get(), buffer.direction())
                .map_err(SubmitCause::Command),
            CommandState::Submitted { .. } => Err(SubmitCause::Busy),
            CommandState::Quarantined { cause, .. } => Err(SubmitCause::Quarantined(*cause)),
        };
        if let Err(cause) = validation {
            return Err(SubmitError {
                cause,
                buffer: RejectedBuffer::Cpu(buffer),
            });
        }
        if let Err(cause) = self.registers.observe().admission() {
            self.state = CommandState::Quarantined {
                cause,
                transfer: None,
            };
            return Err(SubmitError {
                cause: SubmitCause::Port(cause),
                buffer: RejectedBuffer::Cpu(buffer),
            });
        }
        let prepared = match buffer.prepare(self.queue) {
            Ok(prepared) => prepared,
            Err(failure) => {
                let (cause, buffer) = failure.into_parts();
                return Err(SubmitError {
                    cause: SubmitCause::Dma(cause),
                    buffer: RejectedBuffer::Cpu(buffer),
                });
            }
        };
        let encoded = prepared
            .descriptor()
            .map_err(SubmitCause::Dma)
            .and_then(|descriptor| {
                command
                    .encode(&descriptor, self.table_address, self.address_width)
                    .map_err(SubmitCause::Command)
            });
        let encoded = match encoded {
            Ok(encoded) => encoded,
            Err(cause) => return Err(reject_prepared(cause, prepared)),
        };
        let publication = (|| {
            let mut window = self.memory.window(0, PORT_DMA_BYTES)?;
            for (index, value) in encoded.table.into_iter().enumerate() {
                window.write_u32(COMMAND_TABLE_OFFSET + index * 4, value.to_le())?;
            }
            for (index, value) in encoded.header.into_iter().enumerate() {
                window.write_u32(index * 4, value.to_le())?;
            }
            Ok(())
        })();
        if let Err(cause) = publication {
            return Err(reject_prepared(SubmitCause::Dma(cause), prepared));
        }
        let buffer = match prepared.arm() {
            Ok(buffer) => buffer,
            Err(failure) => {
                let (cause, buffer) = failure.into_parts();
                return Err(reject_prepared(SubmitCause::Dma(cause), buffer));
            }
        };
        self.state = CommandState::Submitted {
            expected_bytes: command.byte_count(),
            buffer,
        };
        fence(Ordering::SeqCst);
        self.registers.issue();
        Ok(())
    }

    /// Observe completion for the currently owned submission exactly once.
    ///
    /// # Errors
    /// A hardware/registry inconsistency quarantines the transfer and metadata;
    /// CPU access and further submissions remain disabled until recovery.
    pub fn poll(&mut self) -> Result<CommandPoll, PortFault> {
        match &self.state {
            CommandState::Idle => return Ok(CommandPoll::Idle),
            CommandState::Quarantined { cause, .. } => return Err(*cause),
            CommandState::Submitted { .. } => {}
        }
        match self.registers.observe().completion() {
            CompletionStatus::Pending => return Ok(CommandPoll::Pending),
            CompletionStatus::Unknown(cause) => {
                self.quarantine(cause);
                return Err(cause);
            }
            CompletionStatus::Finished => {}
        }
        fence(Ordering::SeqCst);
        let transferred = match self
            .memory
            .window(4, 4)
            .and_then(|window| window.read_u32(0))
        {
            Ok(bytes) => u32::from_le(bytes),
            Err(cause) => {
                let fault = PortFault::Dma(cause);
                self.quarantine(fault);
                return Err(fault);
            }
        };
        let CommandState::Submitted {
            expected_bytes,
            buffer,
        } = core::mem::replace(
            &mut self.state,
            CommandState::Quarantined {
                cause: PortFault::DriverInterrupted,
                transfer: None,
            },
        )
        else {
            unreachable!("submission was checked under exclusive port ownership");
        };
        if let Err(cause) = validate_transferred(expected_bytes, transferred) {
            self.state = CommandState::Submitted {
                expected_bytes,
                buffer,
            };
            self.quarantine(cause);
            return Err(cause);
        }
        #[expect(
            unsafe_code,
            reason = "hardware completion is established by the AHCI parser"
        )]
        // SAFETY: the exclusive port has one non-NCQ submission in slot zero.
        // Its running engines, link, CI/SACT, status, and PRDBC were read using
        // ordered volatile accesses. No error/reset is accepted as completion.
        // Taking the submitted owner makes this event non-replayable; the
        // witness identifies that allocation and the port's acquisition epoch.
        let witness = unsafe {
            DmaCompletionWitness::from_validated_queue_entry(self.queue, buffer.lease_id())
        };
        let completed = match buffer.complete(witness) {
            Ok(completed) => completed,
            Err(failure) => {
                let cause = PortFault::Dma(failure.cause());
                self.state = CommandState::Quarantined {
                    cause,
                    transfer: Some(RetainedTransfer::InFlight(failure)),
                };
                return Err(cause);
            }
        };
        let buffer = match completed.return_to_cpu() {
            Ok(buffer) => buffer,
            Err(failure) => {
                let cause = PortFault::Dma(failure.cause());
                self.state = CommandState::Quarantined {
                    cause,
                    transfer: Some(RetainedTransfer::Completed(failure)),
                };
                return Err(cause);
            }
        };
        self.registers.acknowledge_completion();
        self.state = CommandState::Idle;
        Ok(CommandPoll::Completed(CommandCompletion {
            buffer,
            transferred: transferred as usize,
        }))
    }

    /// A caller's deadline revokes further submission, never device access.
    /// The port retains the unknown transfer; `close` reports recovery resources.
    pub fn expire_pending(&mut self) {
        if matches!(self.state, CommandState::Submitted { .. }) {
            self.quarantine(PortFault::DeadlineExpired);
        }
    }

    fn quarantine(&mut self, cause: PortFault) {
        let state = core::mem::replace(
            &mut self.state,
            CommandState::Quarantined {
                cause,
                transfer: None,
            },
        );
        if let CommandState::Submitted { buffer, .. } = state {
            let transfer = match buffer.mark_outcome_unknown() {
                Ok(buffer) => RetainedTransfer::Quarantined(buffer),
                Err(failure) => RetainedTransfer::InFlight(failure),
            };
            self.state = CommandState::Quarantined {
                cause,
                transfer: Some(transfer),
            };
        }
    }

    /// Stop an idle port, prove both DMA engines stopped, then unmap its RAM.
    /// `poll_budget` bounds samples independently for CR and FR.
    ///
    /// # Errors
    /// Active/unknown commands return the live resources for their recovery
    /// owner. Stop, quiescence, and unmap failure retain their distinct states.
    #[expect(
        clippy::result_large_err,
        reason = "returning a live port on failed shutdown must not require a new heap allocation"
    )]
    pub fn close(mut self, poll_budget: NonZeroUsize) -> Result<(), PortCloseError> {
        match self.state {
            CommandState::Submitted { .. } => return Err(PortCloseError::CommandActive(self)),
            CommandState::Quarantined { cause, transfer } => {
                return Err(PortCloseError::Quarantined {
                    cause,
                    registers: self.registers.into_mapping(),
                    queue: self.queue,
                    memory: self.memory,
                    transfer,
                });
            }
            CommandState::Idle => {}
        }
        if self.registers.stop(poll_budget).is_err() {
            return Err(PortCloseError::StopDeadline(self));
        }
        fence(Ordering::SeqCst);
        #[expect(
            unsafe_code,
            reason = "the AHCI engine stop establishes shared-RAM quiescence"
        )]
        // SAFETY: no submitted transfer remains, ST/CR and FRE/FR were all
        // observed clear, and this exclusive port is the only queue that was
        // given the metadata address. Consuming self prevents witness replay.
        let witness =
            unsafe { DmaQuiesceWitness::after_queue_quiesced(self.queue, self.memory.lease_id()) };
        let memory = match self.memory.quiesce(witness) {
            Ok(memory) => memory,
            Err(failure) => {
                return Err(PortCloseError::Quiesce {
                    registers: self.registers.into_mapping(),
                    queue: self.queue,
                    failure,
                });
            }
        };
        memory.close().map_err(PortCloseError::Unmap)
    }
}

fn reject_prepared(cause: SubmitCause, prepared: PreparedDmaLease) -> SubmitError {
    let buffer = match prepared.abort() {
        Ok(buffer) => RejectedBuffer::Cpu(buffer),
        Err(failure) => RejectedBuffer::AbortFailed(failure),
    };
    SubmitError { cause, buffer }
}
