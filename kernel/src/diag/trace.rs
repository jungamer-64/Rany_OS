use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::cpu::CpuId;
use crate::sync::IrqPoisonLock;

const CAPACITY: usize = 256;

#[derive(Clone, Copy)]
pub(crate) enum TracePoint {
    Timer,
    Interrupt,
}

impl TracePoint {
    pub(crate) const ALL: [Self; 2] = [Self::Timer, Self::Interrupt];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Timer => "timer",
            Self::Interrupt => "interrupt",
        }
    }

    const fn mask(self) -> u8 {
        match self {
            Self::Timer => 1,
            Self::Interrupt => 2,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TraceEvent {
    pub(crate) point: TracePoint,
    pub(crate) tsc: u64,
    pub(crate) cpu: CpuId,
    pub(crate) vector: u8,
}

pub(crate) struct TraceSnapshot {
    enabled: u8,
    pub(crate) events: Vec<TraceEvent>,
    pub(crate) dropped: u64,
}

impl TraceSnapshot {
    pub(crate) fn enabled(&self, point: TracePoint) -> bool {
        self.enabled & point.mask() != 0
    }
}

struct Ring<const N: usize> {
    slots: [Option<TraceEvent>; N],
    head: usize,
    len: usize,
}

struct Recorder<const N: usize> {
    enabled: AtomicU8,
    ring: IrqPoisonLock<Ring<N>>,
    dropped: AtomicU64,
}

impl<const N: usize> Recorder<N> {
    const fn new() -> Self {
        assert!(N != 0);
        Self {
            enabled: AtomicU8::new(0),
            ring: IrqPoisonLock::new(Ring {
                slots: [None; N],
                head: 0,
                len: 0,
            }),
            dropped: AtomicU64::new(0),
        }
    }

    fn set_enabled(&self, point: TracePoint, enabled: bool) {
        // Serialize disable with admission. The atomic also gates the ISR
        // fast path when tracing is disabled.
        let _ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        if enabled {
            self.enabled.fetch_or(point.mask(), Ordering::Relaxed);
        } else {
            self.enabled.fetch_and(!point.mask(), Ordering::Relaxed);
        }
    }

    fn record(&self, point: TracePoint, cpu: CpuId, vector: u8) {
        if self.enabled.load(Ordering::Relaxed) & point.mask() == 0 {
            return;
        }
        let Ok(mut ring) = self.ring.try_lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if self.enabled.load(Ordering::Relaxed) & point.mask() == 0 {
            return;
        }
        let tail = (ring.head + ring.len) % N;
        ring.slots[tail] = Some(TraceEvent {
            point,
            tsc: crate::time::rdtsc(),
            cpu,
            vector,
        });
        if ring.len == N {
            ring.head = (ring.head + 1) % N;
            self.dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            ring.len += 1;
        }
    }

    fn snapshot(&self) -> Result<TraceSnapshot, TryReserveError> {
        let mut events = Vec::new();
        events.try_reserve_exact(N)?;
        let ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        events.extend(
            (0..ring.len).map(|index| {
                ring.slots[(ring.head + index) % N].expect("occupied trace ring entry")
            }),
        );
        Ok(TraceSnapshot {
            enabled: self.enabled.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            events,
        })
    }
}

static RECORDER: Recorder<CAPACITY> = Recorder::new();

pub(crate) fn set_enabled(point: TracePoint, enabled: bool) {
    RECORDER.set_enabled(point, enabled);
}

pub(crate) fn record_interrupt(point: TracePoint, cpu: CpuId, vector: u8) {
    RECORDER.record(point, cpu, vector);
}

pub(crate) fn snapshot() -> Result<TraceSnapshot, TryReserveError> {
    RECORDER.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn trace_controls_filter_and_preserve_the_newest_bounded_events() {
        let recorder = Recorder::<2>::new();
        let cpu = CpuId::BOOTSTRAP;
        recorder.record(TracePoint::Interrupt, cpu, 1);
        recorder.set_enabled(TracePoint::Interrupt, true);
        recorder.record(TracePoint::Timer, cpu, 2);
        for vector in 3..=5 {
            recorder.record(TracePoint::Interrupt, cpu, vector);
        }
        recorder.set_enabled(TracePoint::Interrupt, false);
        recorder.record(TracePoint::Interrupt, cpu, 6);

        let snapshot = recorder.snapshot().unwrap();
        assert!(!snapshot.enabled(TracePoint::Interrupt));
        assert!(!snapshot.enabled(TracePoint::Timer));
        assert_eq!(snapshot.dropped, 1);
        assert_eq!(
            snapshot
                .events
                .iter()
                .map(|event| event.vector)
                .collect::<Vec<_>>(),
            [4, 5]
        );
        assert_eq!(recorder.snapshot().unwrap().events.len(), 2);
    }
}
