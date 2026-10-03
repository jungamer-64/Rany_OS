//! Block queue publication and completion across the driver ABI.
//!
//! The host retains DMA ownership and the one-use completion route. The driver
//! reserves all descriptor and notification storage before calling `activate`,
//! then publishes the descriptor. No borrowed submission or activation cookie
//! may escape `submit`. Polling reports only validated terminal hardware entries
//! and retains entries that do not fit the caller's output buffer.

use super::{AbiBlockDeviceInfo, AbiError, PackedPciLocation};
use crate::dma::DmaQueueIdentity;
use core::ffi::c_void;

/// Queue identity established by the driver, including its admission bound.
/// A replacement queue must use a fresh, nonzero generation.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AbiBlockQueueInfo {
    pub device: PackedPciLocation,
    pub index: u16,
    pub capacity: u16,
    pub generation: u64,
}

impl AbiBlockQueueInfo {
    /// Decode observations into a valid hardware queue identity.
    ///
    /// # Errors
    /// Returns `InvalidParam` for a missing device, generation, or queue capacity.
    pub fn identity(self) -> Result<DmaQueueIdentity, AbiError> {
        if self.capacity == 0 {
            return Err(AbiError::InvalidParam);
        }
        DmaQueueIdentity::new(self.device, self.index, self.generation)
            .ok_or(AbiError::InvalidParam)
    }
}

/// Borrowed publication data. Addresses identify an admitted mapping; they do
/// not confer CPU access or independent authority to reuse that mapping.
#[repr(C)]
pub struct AbiBlockSubmission {
    pub request_id: u64,
    pub command: u32,
    pub lba: u64,
    pub blocks: u16,
    pub bytes: usize,
    pub iova: u64,
    pub lease_id: u64,
    pub generation: u64,
    pub activation: *mut c_void,
    /// Called exactly once, after reservation and before descriptor publication.
    /// Failure authorizes no hardware effect. The cookie is valid only during
    /// the enclosing `submit`; concurrent or deferred calls are forbidden.
    pub activate: unsafe extern "C" fn(*mut c_void) -> i32,
}

/// Acceptance is independent of the operation's error code.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiBlockDisposition {
    /// No descriptor was published and activation did not succeed.
    Rejected = 1,
    /// Activation succeeded and exactly one terminal notification is owed.
    Accepted = 2,
    /// Activation succeeded but publication or device outcome is uncertain.
    /// The host retains the lease until completion or reset reconciliation.
    OutcomeUnknown = 3,
}

/// Untrusted wire result; decode the disposition before interpreting `status`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AbiBlockSubmitOutcome {
    pub disposition: u32,
    pub status: i32,
}

impl AbiBlockSubmitOutcome {
    pub const fn rejected(cause: AbiError) -> Self {
        Self {
            disposition: AbiBlockDisposition::Rejected as u32,
            status: cause as i32,
        }
    }

    pub const fn accepted() -> Self {
        Self {
            disposition: AbiBlockDisposition::Accepted as u32,
            status: AbiError::Success as i32,
        }
    }

    pub const fn outcome_unknown(cause: AbiError) -> Self {
        Self {
            disposition: AbiBlockDisposition::OutcomeUnknown as u32,
            status: cause as i32,
        }
    }

    /// # Errors
    /// An unknown tag is a protocol failure with no retry authority.
    pub const fn disposition(self) -> Result<AbiBlockDisposition, AbiError> {
        match self.disposition {
            1 => Ok(AbiBlockDisposition::Rejected),
            2 => Ok(AbiBlockDisposition::Accepted),
            3 => Ok(AbiBlockDisposition::OutcomeUnknown),
            _ => Err(AbiError::InvalidParam),
        }
    }
}

/// One validated completion of the current submission on the registered queue.
/// `bytes` counts payload bytes, excluding protocol headers and status fields.
/// Even an error completion proves that this submission can no longer DMA.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct AbiBlockCompletion {
    pub request_id: u64,
    pub lease_id: u64,
    pub generation: u64,
    pub status: i32,
    pub bytes: usize,
}

/// Driver callbacks are retained until every accepted request and `stop` finish.
/// The host serializes callbacks for this queue without holding a kernel lock.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbiBlockDeviceRegistration {
    pub abi_size: u64,
    pub info: AbiBlockDeviceInfo,
    pub queue: AbiBlockQueueInfo,
    pub opaque: u64,
    /// The input is borrowed for the call; reserve before activating, and retain
    /// an accepted request's notification metadata until polling emits it.
    pub submit: unsafe extern "C" fn(u64, *const AbiBlockSubmission) -> AbiBlockSubmitOutcome,
    /// Output pointers are valid for `capacity` entries and one count. Always
    /// report `written <= capacity`, including a committed prefix on failure.
    /// No unreported completion may be consumed.
    pub poll: unsafe extern "C" fn(u64, *mut AbiBlockCompletion, usize, *mut usize) -> i32,
    pub is_ready: extern "C" fn(u64) -> bool,
    /// Close admission and finalize descriptor/ring DMA. Success certifies that
    /// the runtime has no device access, deferred callbacks, or retained buffers.
    /// Busy/failure retains the runtime and is retried by its shutdown owner.
    pub stop: unsafe extern "C" fn(u64) -> i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acceptance_and_status_are_independent() {
        let result = AbiBlockSubmitOutcome::outcome_unknown(AbiError::Timeout);
        assert_eq!(
            result.disposition(),
            Ok(AbiBlockDisposition::OutcomeUnknown)
        );
        assert_eq!(result.status, AbiError::Timeout as i32);
        let result = AbiBlockSubmitOutcome::rejected(AbiError::DeviceBusy);
        assert_eq!(result.disposition(), Ok(AbiBlockDisposition::Rejected));
        assert_eq!(
            AbiBlockSubmitOutcome::accepted().disposition(),
            Ok(AbiBlockDisposition::Accepted)
        );
        assert!(
            AbiBlockSubmitOutcome {
                disposition: 0,
                status: 0
            }
            .disposition()
            .is_err()
        );
    }

    #[test]
    fn queue_observations_preserve_generation_and_capacity() {
        let mut info = AbiBlockQueueInfo {
            device: PackedPciLocation::new(0, 0, 4, 0),
            index: 73,
            capacity: 32,
            generation: 91,
        };
        let identity = info.identity().expect("fixture defines one live queue");
        assert_eq!(identity.device(), info.device);
        assert_eq!(identity.index(), 73);
        assert_eq!(identity.generation(), 91);
        info.capacity = 0;
        assert_eq!(info.identity(), Err(AbiError::InvalidParam));
        info.capacity = 1;
        info.generation = 0;
        assert_eq!(info.identity(), Err(AbiError::InvalidParam));
    }
}
