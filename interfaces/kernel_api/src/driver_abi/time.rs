//! Opaque timer ownership. Poll and cancellation execute in the provider image;
//! an importing cell never dereferences the provider's Rust representation.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::ptr::NonNull;
use core::task::{Context, Poll};

use super::AbiTaskWaker;
use crate::service::time::{TimerError, TimerMode, TimerRegistration, TimerSchedule};

/// Absolute deadlines and relative intervals remain distinct across the ABI.
#[repr(C)]
pub struct AbiTimerSchedule {
    pub kind: u8,
    pub mode: u8,
    pub reserved: [u8; 6],
    pub value_ms: u64,
}

impl AbiTimerSchedule {
    pub fn from_schedule(schedule: TimerSchedule) -> Self {
        let (kind, mode, value_ms) = match schedule {
            TimerSchedule::At(deadline) => (0, 0, deadline),
            TimerSchedule::After { interval_ms, mode } => {
                (1, u8::from(mode == TimerMode::Periodic), interval_ms)
            }
        };
        Self {
            kind,
            mode,
            reserved: [0; 6],
            value_ms,
        }
    }

    /// # Errors
    /// Malformed input is rejected before provider resource admission.
    pub fn decode(&self) -> Result<TimerSchedule, TimerError> {
        if self.reserved != [0; 6] {
            return Err(TimerError::InvalidOptions);
        }
        match (self.kind, self.mode) {
            (0, 0) => Ok(TimerSchedule::At(self.value_ms)),
            (1, 0) => Ok(TimerSchedule::After {
                interval_ms: self.value_ms,
                mode: TimerMode::OneShot,
            }),
            (1, 1) if self.value_ms != 0 => Ok(TimerSchedule::After {
                interval_ms: self.value_ms,
                mode: TimerMode::Periodic,
            }),
            (1, 1) => Err(TimerError::ZeroPeriodicInterval),
            _ => Err(TimerError::InvalidOptions),
        }
    }
}

/// Owns provider-created storage and its paired cancellation callback. Moving
/// this capsule does not move the registration stored inside the provider Box.
#[repr(C)]
pub struct AbiTimerRegistration {
    data: Option<NonNull<()>>,
    poll: unsafe extern "C" fn(*mut (), *const AbiTaskWaker) -> u8,
    destroy: unsafe extern "C" fn(*mut ()),
}

// SAFETY: provider storage contains a Send registration. Unique ownership
// permits transfer between CPUs, with exclusive polling and exactly one drop.
unsafe impl Send for AbiTimerRegistration {}

unsafe extern "C" fn poll_registration(data: *mut (), waker: *const AbiTaskWaker) -> u8 {
    // SAFETY: the capsule exclusively owns initialized provider storage.
    let registration = unsafe { &mut *data.cast::<Option<TimerRegistration>>() };
    // SAFETY: the importing poll retains this kernel waker for the entire call.
    let waker = unsafe { (&*waker).clone_owned() };
    let mut context = Context::from_waker(&waker);
    match Pin::new(
        registration
            .as_mut()
            .expect("published timer is initialized"),
    )
    .poll(&mut context)
    {
        Poll::Pending => 0,
        Poll::Ready(Ok(())) => 1,
        Poll::Ready(Err(TimerError::ClockExhausted)) => 2,
        Poll::Ready(Err(_)) => 3,
    }
}

unsafe extern "C" fn destroy_registration(data: *mut ()) {
    // SAFETY: the same provider callback reclaims its own transferred Box.
    // Dropping the registration cancels its endpoint before freeing storage.
    drop(unsafe { Box::from_raw(data.cast::<Option<TimerRegistration>>()) });
}

impl AbiTimerRegistration {
    fn vacant() -> Self {
        Self {
            data: None,
            poll: poll_registration,
            destroy: destroy_registration,
        }
    }

    /// Reserves the ABI storage before calling the provider's admission path.
    /// The closure must return a cancellation receipt for a published timer.
    ///
    /// # Errors
    /// Envelope exhaustion precedes publication. Provider rejection publishes
    /// no timer and releases the prepared storage before returning its cause.
    pub fn register(
        admit: impl FnOnce() -> Result<TimerRegistration, TimerError>,
    ) -> Result<Self, TimerError> {
        let mut owner = Box::try_new(None).map_err(|_| TimerError::MemoryExhausted)?;
        *owner = Some(admit()?);
        Ok(Self {
            data: Some(NonNull::from(Box::leak(owner)).cast()),
            poll: poll_registration,
            destroy: destroy_registration,
        })
    }
}

impl Future for AbiTimerRegistration {
    type Output = Result<(), TimerError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let owner = self.get_mut();
        let Some(data) = owner.data else {
            return Poll::Ready(Err(TimerError::InvalidAbiResponse));
        };
        let waker = AbiTaskWaker::borrow(context.waker());
        // SAFETY: the provider callbacks and their unique allocation remain
        // live; the kernel image containing these callbacks is never reclaimed.
        match unsafe { (owner.poll)(data.as_ptr(), &waker) } {
            0 => Poll::Pending,
            1 => Poll::Ready(Ok(())),
            2 => Poll::Ready(Err(TimerError::ClockExhausted)),
            _ => Poll::Ready(Err(TimerError::InvalidAbiResponse)),
        }
    }
}

impl Drop for AbiTimerRegistration {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            // SAFETY: removing the sole owner prevents repeated cancellation;
            // provider code and its paired deallocator remain in the kernel.
            unsafe { (self.destroy)(data.as_ptr()) };
        }
    }
}

/// Status zero carries one cancellation owner. Failure carries no owner and
/// preserves its reason. Import validates the combination before exposing it.
#[repr(C)]
pub struct AbiTimerAdmission {
    pub registration: AbiTimerRegistration,
    pub status: u32,
    pub reserved: u32,
}

impl AbiTimerAdmission {
    pub fn from_result(result: Result<AbiTimerRegistration, TimerError>) -> Self {
        match result {
            Ok(registration) => Self {
                registration,
                status: 0,
                reserved: 0,
            },
            Err(cause) => Self {
                registration: AbiTimerRegistration::vacant(),
                status: match cause {
                    TimerError::ServiceUnavailable => 1,
                    TimerError::MemoryExhausted => 2,
                    TimerError::OrderExhausted => 3,
                    TimerError::ZeroPeriodicInterval => 4,
                    TimerError::ClockExhausted => 5,
                    TimerError::InvalidOptions => 6,
                    TimerError::InvalidAbiResponse => 7,
                    TimerError::RuntimeAbiMismatch => 8,
                },
                reserved: 0,
            },
        }
    }

    /// # Errors
    /// Rejects malformed receipts without constructing cancellation authority.
    /// Valid rejection retains the provider's exact admission failure.
    pub fn into_result(self) -> Result<TimerRegistration, TimerError> {
        if self.reserved != 0 || (self.status == 0) != self.registration.data.is_some() {
            return Err(TimerError::InvalidAbiResponse);
        }
        match self.status {
            0 => Ok(TimerRegistration::from_abi(self.registration)),
            1 => Err(TimerError::ServiceUnavailable),
            2 => Err(TimerError::MemoryExhausted),
            3 => Err(TimerError::OrderExhausted),
            4 => Err(TimerError::ZeroPeriodicInterval),
            5 => Err(TimerError::ClockExhausted),
            6 => Err(TimerError::InvalidOptions),
            8 => Err(TimerError::RuntimeAbiMismatch),
            _ => Err(TimerError::InvalidAbiResponse),
        }
    }
}

/// Read-only time observation. `available` is one after provider installation;
/// clock mutation and interrupt delivery are not exposed to importing cells.
#[repr(C)]
pub struct AbiTimeSnapshot {
    pub available: u64,
    pub tick_ms: u64,
    pub uptime_ns: u64,
    pub unix_seconds: u64,
    pub unix_ms: u64,
}

/// Statistics are queried separately from the clock: reading time never locks
/// or scans the pending-timer registry.
#[repr(C)]
pub struct AbiTimerStatistics {
    pub active_timers: u64,
    pub total_fired: u64,
    pub notifications: u64,
    pub due_timers: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_schedule_tags_validate_deadlines_and_periods() {
        let mut raw = AbiTimerSchedule {
            kind: 0,
            mode: 0,
            reserved: [0; 6],
            value_ms: 37,
        };
        assert_eq!(raw.decode(), Ok(TimerSchedule::At(37)));
        raw.kind = 1;
        raw.mode = 1;
        assert_eq!(
            raw.decode(),
            Ok(TimerSchedule::After {
                interval_ms: 37,
                mode: TimerMode::Periodic
            })
        );
        raw.value_ms = 0;
        assert_eq!(raw.decode(), Err(TimerError::ZeroPeriodicInterval));
        raw.mode = 0;
        assert_eq!(
            raw.decode(),
            Ok(TimerSchedule::After {
                interval_ms: 0,
                mode: TimerMode::OneShot
            })
        );
        raw.reserved[2] = 1;
        assert_eq!(raw.decode(), Err(TimerError::InvalidOptions));
    }

    #[test]
    fn rejection_receipt_has_no_notification_or_cancellation_owner() {
        let admission = AbiTimerAdmission::from_result(Err(TimerError::OrderExhausted));
        assert!(admission.registration.data.is_none());
        assert_eq!(admission.status, 3);
        assert!(matches!(
            admission.into_result(),
            Err(TimerError::OrderExhausted)
        ));
        let malformed = AbiTimerAdmission {
            registration: AbiTimerRegistration::vacant(),
            status: 0,
            reserved: 0,
        };
        assert!(matches!(
            malformed.into_result(),
            Err(TimerError::InvalidAbiResponse)
        ));
    }
}
