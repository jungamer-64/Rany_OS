use super::*;


// Minimal task/time shims for tests and benches
#[cfg(any(all(test, not(feature = "full_mm_tests")), feature = "bench"))]
pub mod task {
    pub mod timer {
        /// Return current tick in milliseconds (test stub)
        pub fn current_tick() -> u64 {
            0
        }
    }

    // Convenience shim for tests/benches removed — use `crate::task::timer::current_tick()` directly.

    pub mod scheduler {
        /// Yield the current task (test stub - no-op)
        pub fn yield_current(_cpu_id: usize) {}
    }

    pub mod per_core_executor {
        pub fn spawn<F>(_future: F)
        where
            F: core::future::Future<Output = ()> + 'static,
        {
        }
    }

    pub async fn sleep_ms(_ms: u64) {}

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

        loop {
            match core::pin::Pin::new(&mut boxed).poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => {
                    while !flag.load(Ordering::SeqCst) {
                        core::hint::spin_loop();
                    }
                    flag.store(false, Ordering::SeqCst);
                }
            }
        }
    }

    #[cfg(all(test, not(feature = "std")))]
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

    #[cfg(all(test, feature = "std"))]
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

    // Basic smp shim for test builds
    pub mod smp {
        pub fn current_cpu() -> u32 { 0 }
        pub fn cpu_count() -> usize { 1 }
        pub fn try_current_cpu_id() -> Option<u32> { Some(0) }
    }

    // Minimal work_stealing_advanced shim used by NUMA helpers in tests
    pub mod work_stealing_advanced {
        pub struct NumaTopology;
        impl NumaTopology {
            pub fn get() -> &'static Self {
                static T: NumaTopology = NumaTopology;
                &T
            }

            pub fn num_nodes(&self) -> usize { 1 }

            pub fn get_cores_in_node(&self, _node: usize) -> &'static [u32] {
                static CORES: [u32; 1] = [0];
                &CORES
            }

            pub fn get_numa_node(&self, _cpu: u32) -> usize { 0 }
        }
    }

    // Minimal memory helpers for tests
    pub mod memory {
        pub fn physical_memory_offset() -> u64 { 0 }
        pub fn total_memory_kb() -> u64 { 1024 * 1024 }
        pub fn free_memory_kb() -> u64 { 512 * 1024 }
    }

    // Minimal interrupts shim
    pub mod interrupts {
        pub fn get_timer_ticks() -> u64 { 0 }
    }

    // Minimal domain system stub
    pub mod domain_system {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct DomainId(pub u64);

        impl DomainId {
            pub const fn new(v: u64) -> Self {
                DomainId(v)
            }

            pub fn as_u64(&self) -> u64 {
                self.0
            }
        }

        impl core::fmt::Display for DomainId {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "DomainId({})", self.0)
            }
        }
    }

    // Task context counters used by procfs tests
    pub mod context {
        use core::sync::atomic::AtomicU64;
        pub static CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
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
                pub fn is_success(&self) -> bool { (self.status & 0x1) != 0 }
                pub fn command_id(&self) -> u16 { self.cid }
            }

            /// Minimal driver handle stub used in `with_driver` closures.
            #[derive(Debug)]
            pub struct NvmePollingDriver;

            impl NvmePollingDriver {
                pub fn new() -> Self { NvmePollingDriver }

                /// Submit a read command (test stub)
                pub unsafe fn submit_read(&self, _core_id: u32, _nsid: u32, _lba: u64, _blocks: u16, _prp1: u64, _prp2: u64) -> Result<u16, &'static str> {
                    Err("no-driver")
                }

                /// Submit a write command (test stub)
                pub unsafe fn submit_write(&self, _core_id: u32, _nsid: u32, _lba: u64, _blocks: u16, _prp1: u64, _prp2: u64) -> Result<u16, &'static str> {
                    Err("no-driver")
                }

                pub fn check_completion(&self, _core_id: u32, _cid: u16) -> Option<NvmeCompletion> { None }
                pub fn register_waker(&self, _core_id: u32, _cid: u16, _waker: core::task::Waker) {}
                pub fn namespace_block_size(&self, _nsid: u32) -> u32 { 512 }
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
    // Minimal process manager stub for tests (provides `process_manager()` and types used by `procfs` tests)
    #[cfg(feature = "posix-compat")]
    pub mod process {
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use alloc::string::String;
        use core::sync::atomic::{AtomicU64, Ordering};
        use spin::RwLock;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct ProcessId(u64);
        impl ProcessId {
            pub const KERNEL: Self = Self(0);
            pub const INIT: Self = Self(1);
            pub const fn new(id: u64) -> Self { Self(id) }
            pub fn as_u64(&self) -> u64 { self.0 }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ProcessState { Running, Blocked, Ready, Stopped, Zombie, Dead, Creating }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct UserId(u32);
        impl UserId { pub fn as_u32(&self) -> u32 { self.0 } }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct GroupId(u32);
        impl GroupId { pub fn as_u32(&self) -> u32 { self.0 } }

        #[derive(Clone, Debug)]
        pub struct Credentials { pub uid: UserId, pub gid: GroupId }

        #[derive(Clone, Debug)]
        pub struct ProcessInner {
            pub name: String,
            pub state: ProcessState,
            pub ppid: ProcessId,
            pub credentials: Credentials,
            pub threads: Vec<u64>,
            pub priority: Priority,
            pub cmdline: Vec<String>,
            pub memcg_id: crate::mm::memcg::MemcgId,
            pub exit_code: Option<u64>,
        }

        impl ProcessInner {
            pub fn threads(&self) -> &Vec<u64> { &self.threads }
        }

        #[derive(Clone, Copy, Debug)]
        pub struct Priority(i8);
        impl Priority { pub fn as_i8(&self) -> i8 { self.0 } }

        pub type Process = Arc<RwLock<ProcessInner>>;

        pub struct ProcessManager;
        impl ProcessManager {
            pub fn count(&self) -> usize { 0 }
            pub fn get(&self, _pid: ProcessId) -> Option<Process> { None }
            pub fn create(&self, _ppid: ProcessId, _name: &str) -> Result<ProcessId, ()> { Err(()) }
        }

        static PROCESS_MANAGER: ProcessManager = ProcessManager;
        pub fn process_manager() -> &'static ProcessManager { &PROCESS_MANAGER }

        /// Minimal process info type used by some subsystems
        #[derive(Debug)]
        pub struct ProcessInfo {
            pub pid: ProcessId,
            pub numa_scan_addr: core::sync::atomic::AtomicU64,
        }

        pub fn get_current_process() -> ProcessId { ProcessId::new(1) }

        // Helper to return current process memcg id (used by some tests)
        pub fn get_current_process_memcg_id() -> crate::mm::memcg::MemcgId { crate::mm::memcg::MemcgId::ROOT }

        // Re-export the minimal io::nvme driver for compatibility with code that
        // expects `crate::io::nvme` in test builds. This points at `crate::task::io::nvme`.
        pub mod nvme {
            pub use crate::task::io::nvme::*;
        }
    }

    // Test shim removed: tests and benches should use the canonical
    // `crate::task::TaskId` directly. If you see failures related to TaskId
    // field access, please update tests to use `as_u64()` accessor.

    /// Minimal interrupt_waker shim used by some I/O drivers in tests and benches.
    pub mod interrupt_waker {
        #[derive(Clone, Copy)]
        pub enum InterruptSource {
            VirtioBlk(u8),
            VirtioNet(u8),
            Other(u8),
        }

        pub fn wake_from_interrupt(_src: InterruptSource) {
            // No-op in tests/bench harness
        }
    }
}
