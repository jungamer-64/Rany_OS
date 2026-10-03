//! Timer consumption through the kernel's owned ABI receipt. The proxy has no
//! interrupt, notification delivery or clock mutation authority.

use crate::abi::driver::AbiTimerSchedule;
use crate::service::time::{
    TimeService, TimerError, TimerRegistration, TimerSchedule, TimerServiceStats,
};

pub(super) struct CellTime;
pub(super) static TIME: CellTime = CellTime;

impl TimeService for CellTime {
    fn register_timer(&self, schedule: TimerSchedule) -> Result<TimerRegistration, TimerError> {
        if super::abi().task_waker_abi != crate::abi::driver::TASK_WAKER_ABI {
            return Err(TimerError::RuntimeAbiMismatch);
        }
        let schedule = AbiTimerSchedule::from_schedule(schedule);
        // SAFETY: the provider synchronously borrows initialized, aligned stack
        // input. The successful receipt transfers the sole cancellation owner.
        unsafe { (super::abi().timer_register)(&schedule) }.into_result()
    }

    fn current_tick_ms(&self) -> u64 {
        (super::abi().time_snapshot)().tick_ms
    }
    fn uptime_ns(&self) -> u64 {
        (super::abi().time_snapshot)().uptime_ns
    }
    fn unix_timestamp(&self) -> u64 {
        (super::abi().time_snapshot)().unix_seconds
    }
    fn unix_timestamp_ms(&self) -> u64 {
        (super::abi().time_snapshot)().unix_ms
    }
    fn stats(&self) -> TimerServiceStats {
        let snapshot = (super::abi().timer_statistics)();
        TimerServiceStats {
            active_timers: usize::try_from(snapshot.active_timers).unwrap_or(usize::MAX),
            total_fired: snapshot.total_fired,
            notifications: snapshot.notifications,
            due_timers: usize::try_from(snapshot.due_timers).unwrap_or(usize::MAX),
        }
    }
}
