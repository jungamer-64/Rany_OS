#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TaskId(u64);

#[derive(Debug)]
pub struct Task {
    pub id: TaskId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingTimerWakerStats {
    pub pending: usize,
    pub capacity: usize,
}

impl TaskId {
    pub const fn from_raw(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl Task {
    pub fn new<F>(_future: F) -> Self
    where
        F: core::future::Future<Output = ()> + 'static,
    {
        static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Self {
            id: TaskId::from_raw(id),
        }
    }
}

pub mod per_core_executor {
    pub fn spawn<F>(_future: F)
    where
        F: core::future::Future<Output = ()> + 'static,
    {
    }
}

pub async fn sleep_ms(_ms: u64) {}

pub fn current_tick() -> u64 {
    0
}

pub fn handle_timer_interrupt() {}

pub fn process_pending_timer_wakers() {}

pub fn pending_timer_waker_count() -> usize {
    0
}

pub fn pending_waker_stats() -> PendingTimerWakerStats {
    PendingTimerWakerStats {
        pending: 0,
        capacity: 0,
    }
}

pub fn spawn_detached<F>(_future: F) -> TaskId
where
    F: core::future::Future<Output = ()> + 'static,
{
    TaskId::from_raw(0)
}

pub fn spawn_detached_in_domain<F>(_future: F, _domain: crate::domain::DomainId) -> TaskId
where
    F: core::future::Future<Output = ()> + 'static,
{
    TaskId::from_raw(0)
}

/// Synchronous helper to drive a Future to completion in tests
pub fn block_on<F: core::future::Future>(future: F) -> F::Output {
    use alloc::sync::Arc;

    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use alloc::boxed::Box;
    let flag = Arc::new(AtomicBool::new(false));

    unsafe fn clone_data(data: *const ()) -> RawWaker {
        let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
        let cloned = arc.clone();
        let _ = Arc::into_raw(arc);
        RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
    }

    unsafe fn wake_data(data: *const ()) {
        let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
        arc.store(true, Ordering::SeqCst);
    }

    unsafe fn wake_by_ref_data(data: *const ()) {
        let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
        arc.store(true, Ordering::SeqCst);
        let _ = Arc::into_raw(arc);
    }

    unsafe fn drop_data(data: *const ()) {
        let _arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
    }

    const VTABLE: RawWakerVTable =
        RawWakerVTable::new(clone_data, wake_data, wake_by_ref_data, drop_data);

    let raw = RawWaker::new(Arc::into_raw(flag.clone()) as *const (), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    // Pin the future on the heap and poll a Pin<&mut F>
    let mut boxed = Box::pin(future);

    // LOOP_PROOF: mode=event; reason=Polling loop returns once the future resolves and otherwise waits for the wake flag before polling again.;
    loop {
        match core::pin::Pin::new(&mut boxed).poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => {
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                while !flag.load(Ordering::SeqCst) {
                    core::hint::spin_loop();
                }
                flag.store(false, Ordering::SeqCst);
            }
        }
    }
}

#[cfg(all(any(test, feature = "bench"), not(feature = "std")))]
pub mod fuel {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static CURRENT_FUEL: AtomicU64 = AtomicU64::new(0);
    static FUEL_ACTIVE: AtomicBool = AtomicBool::new(false);

    pub struct Fuel;

    impl Fuel {
        pub fn refill(amount: u64) {
            FUEL_ACTIVE.store(amount > 0, Ordering::Relaxed);
            CURRENT_FUEL.store(amount, Ordering::Relaxed);
        }

        pub fn consume(amount: u64) -> bool {
            if !FUEL_ACTIVE.load(Ordering::Relaxed) {
                return true;
            }

            let mut current = CURRENT_FUEL.load(Ordering::Relaxed);
            // LOOP_PROOF: mode=event; reason=CAS retry loop exits once fuel is successfully decremented or when the available budget is insufficient.;
            loop {
                if let Some(remaining) = current.checked_sub(amount) {
                    match CURRENT_FUEL.compare_exchange_weak(
                        current,
                        remaining,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => return true,
                        Err(v) => current = v,
                    }
                } else {
                    match CURRENT_FUEL.compare_exchange_weak(
                        current,
                        0,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => return false,
                        Err(v) => current = v,
                    }
                }
            }
        }

        pub fn is_active() -> bool {
            FUEL_ACTIVE.load(Ordering::Relaxed)
        }

        pub fn remaining() -> u64 {
            CURRENT_FUEL.load(Ordering::Relaxed)
        }

        pub fn exhaust() {
            FUEL_ACTIVE.store(false, Ordering::Relaxed);
            CURRENT_FUEL.store(0, Ordering::Relaxed);
        }
    }

    pub struct FuelConfig {
        pub default_fuel: u64,
    }

    impl FuelConfig {
        pub fn new() -> Self {
            Self { default_fuel: 0 }
        }
    }
}

#[cfg(all(any(test, feature = "bench"), feature = "std"))]
pub mod fuel {
    use core::cell::Cell;

    thread_local! {
        static CURRENT_FUEL: Cell<u64> = Cell::new(0);
        static FUEL_ACTIVE: Cell<bool> = Cell::new(false);
    }

    pub struct Fuel;

    impl Fuel {
        pub fn refill(amount: u64) {
            FUEL_ACTIVE.with(|a| a.set(amount > 0));
            CURRENT_FUEL.with(|c| c.set(amount));
        }

        pub fn consume(amount: u64) -> bool {
            // If fuel is not active (amount==0 at refill), treat as unlimited and always allow
            let active = FUEL_ACTIVE.with(|a| a.get());
            if !active {
                return true;
            }
            CURRENT_FUEL.with(|c| {
                let current = c.get();
                if let Some(remaining) = current.checked_sub(amount) {
                    c.set(remaining);
                    true
                } else {
                    c.set(0);
                    false
                }
            })
        }

        pub fn remaining() -> u64 {
            CURRENT_FUEL.with(|c| c.get())
        }

        pub fn is_active() -> bool {
            FUEL_ACTIVE.with(|a| a.get())
        }

        pub fn exhaust() {
            FUEL_ACTIVE.with(|a| a.set(false));
            CURRENT_FUEL.with(|c| c.set(0))
        }
    }

    pub struct FuelConfig {
        pub default_fuel: u64,
    }

    impl FuelConfig {
        pub const DEFAULT: Self = Self {
            default_fuel: 10_000,
        };
    }
}

// Minimal preemption shim used by unit tests to avoid pulling the full
// preemption implementation into every test build while keeping the API
// expected by I/O modules and interrupts.
pub mod preemption {
    /// Lightweight stats struct mirroring the real implementation used by monitors.
    #[derive(Debug, Clone)]
    pub struct PreemptionStats {
        pub forced_preemptions: u64,
        pub voluntary_yields: u64,
        pub current_time_slice: u64,
        pub enabled: bool,
    }

    /// Minimal controller stub that exposes only `stats()` for tests.
    pub struct PreemptionController;

    impl PreemptionController {
        pub fn stats(&self) -> PreemptionStats {
            PreemptionStats {
                forced_preemptions: 0,
                voluntary_yields: 0,
                current_time_slice: 0,
                enabled: false,
            }
        }
    }

    /// Return a static reference to the stub controller.
    pub fn preemption_controller() -> &'static PreemptionController {
        static CTRL: PreemptionController = PreemptionController;
        &CTRL
    }

    pub fn aggregate_preemption_stats() -> PreemptionStats {
        preemption_controller().stats()
    }

    /// No-op stubs used by code paths that call into preemption during tests.
    pub fn voluntary_yield() {}
    pub fn yield_point() {}
    pub fn is_preemption_pending() -> bool {
        false
    }
    pub fn clear_preemption_pending() {}
    pub fn check_and_clear_yield_request() -> bool {
        false
    }
    pub fn handle_timer_tick(_tick: u64) {}
    pub fn set_preemption_pending() {}
    pub fn request_yield() {}
    pub fn decrement_time_slice() {}
    pub fn notify_task_started(_tick: u64) {}
}

// Minimal interrupts shim
pub mod interrupts {
    use core::sync::atomic::{AtomicBool, Ordering};

    static INTERRUPTS_ENABLED: AtomicBool = AtomicBool::new(true);

    pub fn get_timer_ticks() -> u64 {
        0
    }

    pub fn runtime_local_timers_enabled() -> bool {
        false
    }

    pub fn ensure_runtime_local_timer_started() {}

    pub fn transition_to_runtime_local_timers() -> bool {
        false
    }

    pub fn enable_interrupts() {
        INTERRUPTS_ENABLED.store(true, Ordering::Release);
    }

    pub fn disable_interrupts() {
        INTERRUPTS_ENABLED.store(false, Ordering::Release);
    }

    pub fn are_interrupts_enabled() -> bool {
        INTERRUPTS_ENABLED.load(Ordering::Acquire)
    }
}

// Minimal IO shims for tests
pub mod io {
    pub mod log {
        pub fn early_print_char(_c: u8) {}
    }

    pub mod interrupt_manager {
        pub fn send_ipi(_apic_id: u32, _vector: u8) {}
        pub fn broadcast_ipi(_vector: u8) {}
    }

    pub mod nvme {
        /// Minimal NVMe completion type for tests
        #[derive(Clone, Copy, Debug)]
        pub struct NvmeCompletion {
            pub cid: u16,
            pub status: u16,
        }

        impl NvmeCompletion {
            pub fn is_success(&self) -> bool {
                (self.status & 0x1) != 0
            }
            pub fn command_id(&self) -> u16 {
                self.cid
            }
        }

        /// Minimal driver handle stub used in `with_driver` closures.
        #[derive(Debug)]
        pub struct NvmePollingDriver;

        impl NvmePollingDriver {
            pub fn new() -> Self {
                NvmePollingDriver
            }

            /// Submit a read command (test stub)
            pub unsafe fn submit_read(
                &self,
                _core_id: u32,
                _nsid: u32,
                _lba: u64,
                _blocks: u16,
                _prp1: u64,
                _prp2: u64,
            ) -> Result<u16, &'static str> {
                Err("no-driver")
            }

            /// Submit a write command (test stub)
            pub unsafe fn submit_write(
                &self,
                _core_id: u32,
                _nsid: u32,
                _lba: u64,
                _blocks: u16,
                _prp1: u64,
                _prp2: u64,
            ) -> Result<u16, &'static str> {
                Err("no-driver")
            }

            pub fn check_completion(&self, _core_id: u32, _cid: u16) -> Option<NvmeCompletion> {
                None
            }
            pub fn register_waker(&self, _core_id: u32, _cid: u16, _waker: core::task::Waker) {}
            pub fn namespace_block_size(&self, _nsid: u32) -> u32 {
                512
            }
        }

        pub mod global {
            use crate::task::io::nvme::NvmePollingDriver;

            pub fn with_driver<F, R>(_f: F) -> Option<R>
            where
                F: FnOnce(&NvmePollingDriver) -> R,
            {
                None
            }

            pub fn with_driver_mut<F, R>(_f: F) -> Option<R>
            where
                F: FnOnce(&mut NvmePollingDriver) -> R,
            {
                None
            }
        }
    }
}
// Test shim removed: tests and benches should use the canonical
// `crate::task::TaskId` directly. If you see failures related to TaskId
// field access, please update tests to use `as_u64()` accessor.

/// Minimal interrupt_waker shim used by some I/O drivers in tests and benches.
pub mod interrupt_waker {
    #[derive(Clone, Copy)]
    pub enum InterruptSource {
        Other(u8),
    }

    pub fn wake_from_interrupt(_src: InterruptSource) {
        // No-op in tests/bench harness
    }
}
