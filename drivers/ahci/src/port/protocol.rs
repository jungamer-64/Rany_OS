//! Pure interpretation of one serialized, non-NCQ command's hardware status.

#![forbid(unsafe_code)]

use crate::types::{PX_CMD_FRE, PX_CMD_ST, PX_IS_TFES};

const REQUIRED_ENGINE_BITS: u32 = PX_CMD_ST | PX_CMD_FRE;
const TASK_BUSY_OR_DRQ: u32 = 0x88;
// Host bus fatal/data errors, interface fatal/non-fatal errors, overflow,
// unknown FIS, and link changes all require recovery, not buffer publication.
const TRANSPORT_ERRORS: u32 =
    (1 << 29) | (1 << 28) | (1 << 27) | (1 << 26) | (1 << 24) | (1 << 4) | (1 << 6) | (1 << 22);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortFault {
    DeadlineExpired,
    DriverInterrupted,
    EngineStopped,
    LinkChanged,
    UnexpectedActiveSlots,
    Transport(u32),
    TaskFile(u8),
    ByteCount { expected: usize, observed: u32 },
    Dma(kernel_api::dma::DmaLeaseError),
}

/// Only integers are read from device memory; no device bit pattern is cast
/// into a Rust enum or treated as an independently replayable completion.
pub(super) struct PortObservation {
    pub(super) command: u32,
    pub(super) issued: u32,
    pub(super) sata_active: u32,
    pub(super) sata_status: u32,
    pub(super) interrupt_status: u32,
    pub(super) task_file: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CompletionStatus {
    Pending,
    Finished,
    Unknown(PortFault),
}

impl PortObservation {
    pub(super) fn completion(&self) -> CompletionStatus {
        // CI also clears on stop/reset. It is not sufficient evidence alone.
        if self.command & REQUIRED_ENGINE_BITS != REQUIRED_ENGINE_BITS {
            return CompletionStatus::Unknown(PortFault::EngineStopped);
        }
        if self.sata_status & 0xf != 3 {
            return CompletionStatus::Unknown(PortFault::LinkChanged);
        }
        if self.sata_active != 0 || self.issued & !1 != 0 {
            return CompletionStatus::Unknown(PortFault::UnexpectedActiveSlots);
        }
        let transport = self.interrupt_status & TRANSPORT_ERRORS;
        if transport != 0 {
            return CompletionStatus::Unknown(PortFault::Transport(transport));
        }
        if self.interrupt_status & PX_IS_TFES != 0 || self.task_file & 1 != 0 {
            return CompletionStatus::Unknown(PortFault::TaskFile((self.task_file >> 8) as u8));
        }
        if self.issued != 0 || self.task_file & TASK_BUSY_OR_DRQ != 0 {
            return CompletionStatus::Pending;
        }
        CompletionStatus::Finished
    }

    pub(super) fn admission(&self) -> Result<(), PortFault> {
        match self.completion() {
            CompletionStatus::Finished => Ok(()),
            CompletionStatus::Pending => Err(PortFault::UnexpectedActiveSlots),
            CompletionStatus::Unknown(reason) => Err(reason),
        }
    }
}

pub(super) fn validate_transferred(expected: usize, observed: u32) -> Result<(), PortFault> {
    if observed as usize != expected {
        return Err(PortFault::ByteCount { expected, observed });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finished() -> PortObservation {
        PortObservation {
            command: REQUIRED_ENGINE_BITS,
            issued: 0,
            sata_active: 0,
            sata_status: 0x123,
            interrupt_status: 1,
            task_file: 0x50,
        }
    }

    #[test]
    fn cleared_ci_after_stop_or_link_loss_is_not_completion() {
        let mut status = finished();
        assert_eq!(status.completion(), CompletionStatus::Finished);
        status.command &= !PX_CMD_ST;
        assert_eq!(
            status.completion(),
            CompletionStatus::Unknown(PortFault::EngineStopped)
        );
        status = finished();
        status.sata_status = 0;
        assert_eq!(
            status.completion(),
            CompletionStatus::Unknown(PortFault::LinkChanged)
        );
    }

    #[test]
    fn command_issue_and_task_busy_both_block_publication() {
        let mut status = finished();
        status.issued = 1;
        assert_eq!(status.completion(), CompletionStatus::Pending);
        status.issued = 0;
        status.task_file |= 0x80;
        assert_eq!(status.completion(), CompletionStatus::Pending);
        status.task_file = 0x58;
        assert_eq!(status.completion(), CompletionStatus::Pending);
    }

    #[test]
    fn error_and_foreign_slot_are_unknown_outcomes() {
        let mut status = finished();
        status.interrupt_status = PX_IS_TFES;
        status.task_file = 0x0451;
        assert_eq!(
            status.completion(),
            CompletionStatus::Unknown(PortFault::TaskFile(4))
        );
        status = finished();
        status.issued = 2;
        assert_eq!(
            status.completion(),
            CompletionStatus::Unknown(PortFault::UnexpectedActiveSlots)
        );
        status = finished();
        status.sata_active = 1;
        assert_eq!(
            status.completion(),
            CompletionStatus::Unknown(PortFault::UnexpectedActiveSlots)
        );
        status = finished();
        status.interrupt_status = 1 << 29;
        assert_eq!(
            status.completion(),
            CompletionStatus::Unknown(PortFault::Transport(1 << 29))
        );
    }

    #[test]
    fn byte_count_is_checked_without_masking_or_truncation() {
        assert_eq!(validate_transferred(512, 512), Ok(()));
        for observed in [0, 511, 513, u32::MAX] {
            assert_eq!(
                validate_transferred(512, observed),
                Err(PortFault::ByteCount {
                    expected: 512,
                    observed
                })
            );
        }
    }
}
