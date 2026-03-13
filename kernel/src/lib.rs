// When not running tests or benches, compile as `no_std`. For benches we
// enable the standard library so benchmark harnesses (Criterion) and
// alloc-dependent graphics helpers can build and run under the host test
// runner.
#![cfg_attr(all(not(feature = "std"), not(all(test, target_os = "linux"))), no_std)]
#![cfg_attr(all(test, not(feature = "std"), not(target_os = "linux")), no_main)]
#![cfg_attr(
    all(test, not(any(feature = "std", target_os = "linux"))),
    feature(custom_test_frameworks)
)]
#![cfg_attr(
    all(test, not(any(feature = "std", target_os = "linux"))),
    test_runner(crate::test_runner)
)]
#![cfg_attr(
    all(test, not(any(feature = "std", target_os = "linux"))),
    reexport_test_harness_main = "test_main"
)]
#![cfg_attr(
    any(not(test), feature = "full_mm_tests"),
    allow(unsafe_op_in_unsafe_fn)
)]
#![cfg_attr(any(not(test), feature = "full_mm_tests"), feature(const_heap))]
#![cfg_attr(any(not(test), feature = "full_mm_tests"), feature(abi_x86_interrupt))]
#![cfg_attr(
    any(not(test), feature = "full_mm_tests"),
    feature(alloc_error_handler)
)]
#![feature(format_args_nl)]
#![feature(ptr_metadata)]

extern crate alloc;

// Interrupt helper macro moved to a shared module so it's visible in both the
// library and binary crate (define_interrupt! is used by modules included by
// `main.rs`). See `interrupt_macros.rs` for the implementation.
#[macro_use]
mod interrupt_macros;

// ========== Test Runner & Entry Point ==========

// Global Allocator for tests (requires full_mm_tests)
#[cfg(all(feature = "full_mm_tests", not(feature = "std")))]
#[cfg_attr(all(test, not(target_os = "linux")), global_allocator)]
pub static ALLOCATOR: DummyGlobalAlloc = DummyGlobalAlloc;

// Dummy allocator for tests if not found or problematic
#[cfg(all(feature = "full_mm_tests", not(feature = "std")))]
pub struct DummyGlobalAlloc;

#[cfg(all(feature = "full_mm_tests", not(feature = "std")))]
impl DummyGlobalAlloc {
    /// full_mm_tests のダミー実装ではヒープ未初期化扱い。
    pub fn is_initialized(&self) -> Option<bool> {
        Some(false)
    }
}

#[cfg(all(feature = "full_mm_tests", not(feature = "std")))]
unsafe impl core::alloc::GlobalAlloc for DummyGlobalAlloc {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

// Bump allocator for unit tests. Provides a working 64MB heap so tests that
// use `alloc::vec::Vec`, `alloc::boxed::Box`, etc. succeed in the no_std QEMU
// test environment (the previous `LockedBuddyHeap::empty()` returned null for
// every allocation).
#[cfg(all(test, not(feature = "full_mm_tests"), not(feature = "std")))]
mod test_bump_alloc {
    use core::alloc::{GlobalAlloc, Layout};
    use core::sync::atomic::{AtomicUsize, Ordering};

    const HEAP_SIZE: usize = 64 * 1024 * 1024; // 64 MB

    #[repr(C, align(4096))]
    struct HeapMem([u8; HEAP_SIZE]);

    static mut HEAP: HeapMem = HeapMem([0; HEAP_SIZE]);
    static OFFSET: AtomicUsize = AtomicUsize::new(0);

    pub struct BumpAlloc;

    impl BumpAlloc {
        pub const fn new() -> Self {
            Self
        }

        /// Compatibility shim: the kernel sometimes checks `ALLOCATOR.is_initialized()`.
        pub fn is_initialized(&self) -> Option<bool> {
            Some(true)
        }
    }

    unsafe impl GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                let current = OFFSET.load(Ordering::Relaxed);
                let aligned = (current + layout.align() - 1) & !(layout.align() - 1);
                let new_off = aligned + layout.size();
                if new_off > HEAP_SIZE {
                    return core::ptr::null_mut();
                }
                if OFFSET
                    .compare_exchange_weak(current, new_off, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return unsafe { core::ptr::addr_of_mut!(HEAP).cast::<u8>().add(aligned) };
                }
            }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // Bump allocator: no individual deallocation.
        }
    }
}

#[cfg(all(test, not(feature = "full_mm_tests"), not(feature = "std")))]
#[global_allocator]
pub static ALLOCATOR: test_bump_alloc::BumpAlloc = test_bump_alloc::BumpAlloc::new();

#[cfg(all(test, not(feature = "std"), not(target_os = "linux")))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Minimal serial init for test output
    unsafe {
        let port = 0x3F8u16;
        core::arch::asm!("out dx, al", in("dx") port + 1, in("al") 0u8); // INT disable
        core::arch::asm!("out dx, al", in("dx") port + 3, in("al") 0x80u8); // DLAB on
        core::arch::asm!("out dx, al", in("dx") port + 0, in("al") 0x03u8); // Divisor low
        core::arch::asm!("out dx, al", in("dx") port + 1, in("al") 0x00u8); // Divisor high
        core::arch::asm!("out dx, al", in("dx") port + 3, in("al") 0x03u8); // 8N1
        core::arch::asm!("out dx, al", in("dx") port + 2, in("al") 0xC7u8); // FIFO
        core::arch::asm!("out dx, al", in("dx") port + 4, in("al") 0x0Bu8); // RTS/DSR
    }

    test_main();

    exit_qemu(QemuExitCode::Success);
}

#[cfg(all(
    test,
    not(feature = "full_mm_tests"),
    not(feature = "std"),
    not(target_os = "linux")
))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        for byte in b"[test] FAILED\n" {
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *byte);
        }
        for byte in b"[qemu-suite] kernel-unit fail\n" {
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *byte);
        }
    }
    exit_qemu(QemuExitCode::Failed);
}

#[cfg(all(
    test,
    feature = "full_mm_tests",
    not(feature = "std"),
    not(target_os = "linux")
))]
#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::panic_handler::panic(info)
}

// Macro helpers
#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($($arg:tt)*) => ({
        if cfg!(any(feature = "std", all(test, target_os = "linux"))) {
            // Host tests and std-enabled builds can use the stock stdout path.
            #[cfg(any(feature = "std", all(test, target_os = "linux")))]
            std::println!($($arg)*);
        } else {
             // In no_std, use kernel logger
             $crate::io::log::print(format_args!("{}\n", format_args!($($arg)*)));
        }
    });
}

#[macro_export]
macro_rules! eprintln {
    () => (eprint!("\n"));
    ($($arg:tt)*) => ({
        if cfg!(any(feature = "std", all(test, target_os = "linux"))) {
            // Host tests and std-enabled builds can use the stock stderr path.
            #[cfg(any(feature = "std", all(test, target_os = "linux")))]
            std::eprintln!($($arg)*);
        } else {
             // In no_std, use kernel logger w/ error level or just print
             $crate::io::log::print(format_args!("{}\n", format_args!($($arg)*)));
        }
    });
}

#[cfg(all(test, not(feature = "std"), not(target_os = "linux")))]
pub fn test_runner(tests: &[&dyn Fn()]) {
    crate::io::log::early_print("[qemu-suite] kernel-unit start\n");
    crate::io::log::early_print("[test] running ");
    crate::io::log::early_print_dec(tests.len() as u64);
    crate::io::log::early_print(" tests...\n");

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut failed_indices: [usize; 64] = [0; 64];

    for (i, t) in tests.iter().enumerate() {
        crate::io::log::early_print("[test] #");
        crate::io::log::early_print_dec(i as u64);
        crate::io::log::early_print(" ... ");

        // In no_std test builds there is no catch_unwind; run the test directly.
        // If the test panics the panic handler will abort (QEMU test behavior).
        t();
        crate::io::log::early_print("[test] ok\n");
        passed += 1;
    }

    crate::io::log::early_print("\n[test] results: ");
    crate::io::log::early_print_dec(passed as u64);
    crate::io::log::early_print(" passed, ");
    crate::io::log::early_print_dec(failed as u64);
    crate::io::log::early_print(" failed\n");

    if failed > 0 {
        crate::io::log::early_print("[test] failed indices: ");
        let show = if failed < 64 { failed } else { 64 };
        for fi in 0..show {
            if fi > 0 {
                crate::io::log::early_print(", ");
            }
            crate::io::log::early_print_dec(failed_indices[fi] as u64);
        }
        crate::io::log::early_print("\n");
    }

    if failed > 0 {
        crate::io::log::early_print("[qemu-suite] kernel-unit FAIL\n");
        exit_qemu(QemuExitCode::Failed);
    }

    crate::io::log::early_print("[qemu-suite] kernel-unit pass\n");
}

#[cfg(test)]
pub(crate) mod host_test_support {
    #[cfg(any(feature = "std", target_os = "linux"))]
    pub struct Guard(std::sync::MutexGuard<'static, ()>);

    #[cfg(not(any(feature = "std", target_os = "linux")))]
    pub struct Guard;

    #[cfg(any(feature = "std", target_os = "linux"))]
    pub fn guard() -> Guard {
        use std::sync::{Mutex, OnceLock};

        static HOST_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = HOST_TEST_LOCK.get_or_init(|| Mutex::new(()));
        Guard(lock.lock().expect("host test lock poisoned"))
    }

    #[cfg(not(any(feature = "std", target_os = "linux")))]
    pub fn guard() -> Guard {
        Guard
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(code: QemuExitCode) -> ! {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") 0xf4u16,
            in("eax") code as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {}
}

// For unit testing we expose a small set of modules via the library entry
// point. This keeps most of the kernel as a binary-only crate while still
// allowing targeted library-style tests (e.g. security/capability) to run
// under `cargo test --lib` without pulling the entire binary test harness.
#[cfg(all(
    test,
    not(feature = "full_mm_tests"),
    not(feature = "qemu-test-export")
))]
pub mod security;

// QEMU test exports are compiled when `qemu-test-export` is enabled and are
// consumed by the kernel full-boot runtime dispatcher. Pure host tests should
// prefer crate-local `#[cfg(test)]`.
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// Expose additional modules when building tests so unit tests inside those
// modules can be executed via `cargo test --lib`.
// Also expose the `graphics` module when compiling benches via the
// `bench` feature so Criterion benches can access framebuffer types and
// helpers. This keeps the default binary layout unchanged while allowing
// convenient benching during development.
#[cfg(any(not(test), test, feature = "bench", feature = "full_mm_tests"))]
pub mod graphics;

// Provide fallback TLS symbols on host Windows builds where the kernel
// linker script is not used. This prevents undefined reference linker
// errors for `__tls_start` / `__tls_end` when building the binary for
// `cargo test` on Windows hosts.
#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
pub static __tls_start: u8 = 0;
#[cfg(target_os = "windows")]
#[unsafe(no_mangle)]
pub static __tls_end: u8 = 0;

// Minimal test/bench `mm::numa` shim to satisfy IOMMU tests and benchmark builds
// without pulling in the full memory subsystem and its heavy dependencies.
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
#[path = "../../filesystems/kernel_fs/mod.rs"]
pub mod fs;

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod durability;

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod debug;

// Intrusive collections for kernel use (always available)
pub mod collections;

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod mm;
// The real `per_cpu` module is not compiled when running tests or benches
// because we provide a lightweight stub later in this file that satisfies
// the few symbols needed by unit tests.  Without this guard the crate ends up
// defining `per_cpu` twice during `cargo test`, which triggers a compile
// error.
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod console;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod cpu;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod crypto;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod domain;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod driver_domain;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod drivers;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod error;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod interrupts;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod io;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod ipc;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod loader;
pub mod memory;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod monitor;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod net;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod panic_handler;
#[cfg(any(
    not(any(test, feature = "bench")),
    feature = "full_mm_tests",
    feature = "qemu-test-export"
))]
pub mod per_cpu;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod platform;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod power;
pub mod provider_registry;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod sas;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod security;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod service_impl;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
mod smp;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod sync;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod system_info;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod task;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod thermal;
#[cfg(any(not(test), test, feature = "full_mm_tests"))]
pub mod time;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod unwind;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod util;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod watchdog;

#[cfg(not(feature = "full_mm_tests"))]
#[cfg(any(test, feature = "bench"))]
#[cfg(not(feature = "qemu-test-export"))]
pub mod mm {
    use alloc::alloc::{Layout, alloc_zeroed, dealloc};
    use core::ptr::NonNull;
    use x86_64::PhysAddr;
    use x86_64::VirtAddr;
    use x86_64::structures::paging::{PhysFrame, Size4KiB};

    pub mod magazine {
        pub struct Magazine<T, const N: usize> {
            _marker: core::marker::PhantomData<T>,
        }
        impl<T, const N: usize> Magazine<T, N> {
            pub fn new() -> Self {
                Self {
                    _marker: core::marker::PhantomData,
                }
            }
        }
        // Clone implementation might be needed if IovaMagazine is cloned in tests
        impl<T, const N: usize> Clone for Magazine<T, N> {
            fn clone(&self) -> Self {
                Self::new()
            }
        }
        impl<T, const N: usize> Copy for Magazine<T, N> {}
    }

    pub mod memcg {
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub struct MemcgId;
        impl MemcgId {
            pub const ROOT: Self = Self;
        }
    }

    // Minimal fast allocator shim used by IOMMU tests
    pub mod fast_allocator {

        pub const PAGE_SIZE_4K: u64 = 4096;
        pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
        pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

        #[derive(Clone, Copy, Debug)]
        pub enum PageGranularity {
            Page4K,
            Page2M,
            Page1G,
        }

        impl PageGranularity {
            pub fn size_bytes(&self) -> u64 {
                match self {
                    PageGranularity::Page4K => PAGE_SIZE_4K,
                    PageGranularity::Page2M => PAGE_SIZE_2M,
                    PageGranularity::Page1G => PAGE_SIZE_1G,
                }
            }
        }

        use core::sync::atomic::{AtomicU64, Ordering};

        #[derive(Debug)]
        pub struct FastBitmapAllocator {
            base: u64,
            size: u64,
            next: AtomicU64,
        }

        impl FastBitmapAllocator {
            pub fn new(base: u64, size: u64) -> Self {
                Self {
                    base,
                    size,
                    next: AtomicU64::new(0),
                }
            }

            pub fn allocate_4k(&self) -> Option<u64> {
                self.allocate_with_size(PAGE_SIZE_4K)
            }
            pub fn allocate_2m(&self) -> Option<u64> {
                self.allocate_with_size(PAGE_SIZE_2M)
            }
            pub fn allocate_1g(&self) -> Option<u64> {
                self.allocate_with_size(PAGE_SIZE_1G)
            }

            fn allocate_with_size(&self, sz: u64) -> Option<u64> {
                // Simple atomic bump allocator
                // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
                loop {
                    let cur = self.next.load(Ordering::Relaxed);
                    if cur + sz > self.size {
                        return None;
                    }
                    if self
                        .next
                        .compare_exchange(cur, cur + sz, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        return Some(self.base + cur);
                    }
                }
            }

            pub fn allocate_4k_below(&self, limit: u64) -> Option<u64> {
                self.allocate_below(PAGE_SIZE_4K, limit)
            }
            pub fn allocate_2m_below(&self, limit: u64) -> Option<u64> {
                self.allocate_below(PAGE_SIZE_2M, limit)
            }
            pub fn allocate_1g_below(&self, limit: u64) -> Option<u64> {
                self.allocate_below(PAGE_SIZE_1G, limit)
            }

            fn allocate_below(&self, sz: u64, limit: u64) -> Option<u64> {
                // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
                loop {
                    let cur = self.next.load(Ordering::Relaxed);
                    if cur + sz > self.size || self.base + cur + sz > limit {
                        return None;
                    }
                    if self
                        .next
                        .compare_exchange(cur, cur + sz, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        return Some(self.base + cur);
                    }
                }
            }

            pub fn allocate_contiguous(&self, _size: u64, _align: u64) -> Option<u64> {
                // Align up current pointer and allocate
                // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
                loop {
                    let cur = self.next.load(Ordering::Relaxed);
                    let aligned = ((cur + (_align - 1)) / _align) * _align;
                    if aligned + _size > self.size {
                        return None;
                    }
                    if self
                        .next
                        .compare_exchange(cur, aligned + _size, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        return Some(self.base + aligned);
                    }
                }
            }

            pub fn free_immediate(&self, _addr: u64, _gran: PageGranularity) -> Result<(), ()> {
                Ok(())
            }

            pub fn reserve(&self, _start: u64, _size: u64) -> Result<(), ()> {
                Ok(())
            }

            pub fn reconfigure_for_cpu_ids(&mut self, _cpu_ids: &[usize]) {}

            pub fn enable_single_writer_arenas(&self) {}

            pub fn drain_remote_frees(&self) {}
            pub fn base(&self) -> u64 {
                self.base
            }
            pub fn size(&self) -> u64 {
                self.size
            }
        }
    }

    // Minimal remote-free / quarantine shim used by IOVA allocator
    pub mod remote_free {
        use alloc::collections::VecDeque;

        #[derive(Debug, Clone, Copy, Default)]
        pub struct QuarantineEntry {
            pub addr: u64,
            pub epoch: u32,
            pub size_class: u8,
        }

        #[derive(Debug)]
        pub struct QuarantineRing<const CAP: usize> {
            buf: VecDeque<QuarantineEntry>,
        }

        impl<const CAP: usize> QuarantineRing<CAP> {
            pub const fn new() -> Self {
                Self {
                    buf: VecDeque::new(),
                }
            }

            pub fn push(&mut self, addr: u64, size_class: u8, epoch: u32) -> bool {
                if self.buf.len() >= CAP {
                    false
                } else {
                    self.buf.push_back(QuarantineEntry {
                        addr,
                        epoch,
                        size_class,
                    });
                    true
                }
            }

            pub fn push_entry(&mut self, entry: QuarantineEntry) -> bool {
                self.push(entry.addr, entry.size_class, entry.epoch)
            }

            pub fn drain_older_than(
                &mut self,
                completed_epoch: u32,
                limit: usize,
                out: &mut [QuarantineEntry],
            ) -> usize {
                let mut count = 0usize;
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                while count < limit {
                    if let Some(front) = self.buf.front() {
                        if front.epoch <= completed_epoch {
                            let e = self.buf.pop_front().unwrap();
                            out[count] = e;
                            count += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                count
            }

            pub fn drain_all(&mut self, out: &mut [QuarantineEntry]) -> usize {
                let mut count = 0usize;
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                while count < out.len() {
                    if let Some(e) = self.buf.pop_front() {
                        out[count] = e;
                        count += 1;
                    } else {
                        break;
                    }
                }
                count
            }
        }
    }

    pub mod types {
        #[derive(Clone, Copy)]
        pub struct NumaNodeId(pub u8);
        impl NumaNodeId {
            pub fn new(n: u8) -> Self {
                Self(n)
            }
            pub fn as_usize(&self) -> usize {
                self.0 as usize
            }
        }
        pub const PAGE_SIZE_4K: usize = 4096;
        pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
        pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;
    }

    pub mod frame_allocator {
        use x86_64::PhysAddr;
        use x86_64::structures::paging::{PhysFrame, Size4KiB};

        pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
            super::buddy_alloc_frame()
        }

        pub fn alloc_frame_on_numa_node(
            node: super::types::NumaNodeId,
        ) -> Option<PhysFrame<Size4KiB>> {
            super::buddy_alloc_frame_on_node(node)
        }

        pub fn alloc_contiguous_frames(frames: usize) -> Option<PhysAddr> {
            super::buddy_alloc_contiguous_frames(frames)
        }

        pub fn dealloc_contiguous_frames(_phys: PhysAddr, _frames: usize) {
            // No-op in test shim
        }

        pub fn pmm_managed_end() -> Option<u64> {
            None
        }

        pub fn is_range_managed_by_pmm(_addr: PhysAddr, _size: u64) -> bool {
            true
        }

        pub fn dealloc_frame(frame: PhysFrame<Size4KiB>) {
            super::buddy_dealloc_frame(frame);
        }

        /// Memory pressure hint for tests (0 = no pressure)
        pub fn memory_pressure_level() -> u8 {
            0
        }
    }

    // Re-export frame allocator helpers at `crate::mm::phys::frame_allocator::dealloc_frame` etc.
    pub use frame_allocator::dealloc_frame;
    pub use frame_allocator::memory_pressure_level;

    // Minimal `higher_half` shim (for tests): small wrappers around u64 addresses
    pub mod higher_half {
        #[derive(Clone, Copy, Debug)]
        pub struct VirtAddr(u64);
        impl VirtAddr {
            pub const fn new(addr: u64) -> Self {
                Self(addr)
            }
            pub const fn as_u64(&self) -> u64 {
                self.0
            }
        }

        #[derive(Clone, Copy, Debug)]
        pub struct PhysAddr(u64);
        impl PhysAddr {
            pub const fn new(addr: u64) -> Self {
                Self(addr)
            }
            pub const fn as_u64(&self) -> u64 {
                self.0
            }
        }
    }

    // Global translate helper for tests (use kernel `higher_half` types)
    pub fn global_translate(
        virt: crate::mm::virt::higher_half::VirtAddr,
    ) -> Option<crate::mm::virt::higher_half::PhysAddr> {
        let v = x86_64::VirtAddr::new(virt.as_u64());
        let p = mapping::virt_to_phys(v);
        Some(crate::mm::virt::higher_half::PhysAddr::new(p.as_u64()))
    }

    // Minimal address translation helpers for tests/benches.
    pub mod mapping {
        use x86_64::{PhysAddr, VirtAddr};

        pub fn virt_to_phys(addr: VirtAddr) -> PhysAddr {
            PhysAddr::new(addr.as_u64())
        }

        pub fn phys_to_virt(addr: PhysAddr) -> VirtAddr {
            VirtAddr::new(addr.as_u64())
        }
    }

    pub fn buddy_alloc_frame() -> Option<PhysFrame<Size4KiB>> {
        let layout = Layout::from_size_align(4096, 4096).ok()?;
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr)?;
        let phys = PhysAddr::new(ptr.as_ptr() as u64);
        match PhysFrame::from_start_address(phys) {
            Ok(frame) => Some(frame),
            Err(_) => {
                unsafe { dealloc(ptr.as_ptr(), layout) };
                None
            }
        }
    }

    pub fn buddy_alloc_frame_on_node(_node: types::NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
        buddy_alloc_frame()
    }

    pub fn buddy_alloc_contiguous_frames(frame_count: usize) -> Option<PhysAddr> {
        if frame_count == 0 {
            return None;
        }
        let bytes = frame_count.checked_mul(4096)?;
        let layout = Layout::from_size_align(bytes, 4096).ok()?;
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr)?;
        Some(PhysAddr::new(ptr.as_ptr() as u64))
    }

    pub fn buddy_dealloc_frame(frame: PhysFrame<Size4KiB>) {
        let layout = Layout::from_size_align(4096, 4096).expect("buddy layout");
        let ptr = frame.start_address().as_u64() as *mut u8;
        unsafe { dealloc(ptr, layout) };
    }

    // Convenience wrappers for IOMMU/legacy APIs used in some modules/tests
    pub fn alloc_contiguous_frames(frames: usize) -> Option<PhysAddr> {
        buddy_alloc_contiguous_frames(frames)
    }

    pub fn dealloc_contiguous_frames(_phys: PhysAddr, _frames: usize) {
        // Test shim: no-op - memory will be reclaimed when the test process exits.
    }

    pub fn mapping_phys_to_virt(phys: PhysAddr) -> VirtAddr {
        VirtAddr::new(phys.as_u64())
    }

    /// 4K page size constant for compatibility with drivers/tests
    pub const PAGE_SIZE_4K: usize = 4096;

    // ======================================================================
    // Wrapper sub-modules mirroring the new directory-based module hierarchy
    // ======================================================================
    pub mod phys {
        pub mod fast_allocator {
            #[allow(clippy::wildcard_imports)]
            pub use super::super::fast_allocator::*;
        }
        pub mod frame_allocator {
            #[allow(clippy::wildcard_imports)]
            pub use super::super::frame_allocator::*;
        }
        pub mod buddy_allocator {
            /// Stub for buddy_allocator_stats (test shim)
            pub struct BuddyAllocatorStats {
                pub total_frames: usize,
                pub free_frames: usize,
                pub split_count: u64,
                pub coalesce_count: u64,
                pub order_stats: [(usize, usize); 19],
            }
            pub fn buddy_allocator_stats() -> BuddyAllocatorStats {
                BuddyAllocatorStats {
                    total_frames: 0,
                    free_frames: 0,
                    split_count: 0,
                    coalesce_count: 0,
                    order_stats: [(0, 0); 19],
                }
            }
        }
        pub mod unified_alloc {
            pub fn memory_pressure_level() -> u8 {
                0
            }
        }
    }

    pub mod virt {
        pub mod higher_half {
            #[allow(clippy::wildcard_imports)]
            pub use super::super::higher_half::*;
        }
        pub mod mapping {
            #[allow(clippy::wildcard_imports)]
            pub use super::super::mapping::*;
        }
    }

    pub mod cache {
        pub mod magazine {
            #[allow(clippy::wildcard_imports)]
            pub use super::super::magazine::*;
        }
    }

    pub mod numa {
        pub mod topology {
            use alloc::alloc::{alloc_zeroed, dealloc};
            use core::alloc::Layout;
            use core::ptr::NonNull;

            pub const MAX_NUMA_NODES: usize = 8;

            pub fn num_nodes() -> usize {
                1
            }
            pub fn current_node() -> usize {
                0
            }

            pub fn allocate_zeroed_on_node(
                layout: Layout,
                _node: Option<usize>,
            ) -> Option<NonNull<u8>> {
                unsafe {
                    let ptr = alloc_zeroed(layout);
                    NonNull::new(ptr)
                }
            }

            pub fn allocate_zeroed_on_node_with_info(
                layout: Layout,
                _node: Option<usize>,
            ) -> Option<(NonNull<u8>, usize)> {
                unsafe {
                    let ptr = alloc_zeroed(layout);
                    NonNull::new(ptr).map(|p| (p, 0))
                }
            }

            pub unsafe fn deallocate_on_node(
                ptr: NonNull<u8>,
                layout: Layout,
                _node: Option<usize>,
            ) {
                unsafe {
                    dealloc(ptr.as_ptr(), layout);
                }
            }
        }
    }

    pub mod meta {
        pub mod memcg {
            #[allow(wildcard_imports)]
            pub use super::super::memcg::*;
        }
    }
}

// Minimal per-CPU stubs for tests (crate-root level to match new module hierarchy).
#[cfg(not(feature = "full_mm_tests"))]
#[cfg(any(test, feature = "bench"))]
#[cfg(not(feature = "qemu-test-export"))]
pub mod per_cpu {
    use core::array;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

    #[derive(Clone, Copy, Default)]
    pub struct DomainCacheEntry {
        pub device_id: u16,
        pub domain_id: u16,
        pub controller_idx: u8,
        pub valid: bool,
    }

    pub struct PerCpuDomainCache {
        pub entries: [DomainCacheEntry; Self::CACHE_SIZE],
    }

    impl PerCpuDomainCache {
        pub const CACHE_SIZE: usize = 64;

        pub fn new() -> Self {
            Self {
                entries: [DomainCacheEntry {
                    device_id: 0,
                    domain_id: 0,
                    controller_idx: 0,
                    valid: false,
                }; Self::CACHE_SIZE],
            }
        }

        pub fn lookup(&self, device_id: u16) -> Option<(u16, u8)> {
            let idx = (device_id as usize) % Self::CACHE_SIZE;
            let entry = self.entries[idx];
            if entry.valid && entry.device_id == device_id {
                Some((entry.domain_id, entry.controller_idx))
            } else {
                None
            }
        }

        pub fn insert(&mut self, device_id: u16, domain_id: u16, controller_idx: u8) {
            let idx = (device_id as usize) % Self::CACHE_SIZE;
            self.entries[idx] = DomainCacheEntry {
                device_id,
                domain_id,
                controller_idx,
                valid: true,
            };
        }

        pub fn invalidate(&mut self, device_id: u16) {
            let idx = (device_id as usize) % Self::CACHE_SIZE;
            if self.entries[idx].device_id == device_id {
                self.entries[idx].valid = false;
            }
        }
    }

    pub const IOVA_MAG_CAPACITY: usize = 256;
    pub const MAX_IOMMU_CONTROLLERS: usize = 8;

    use crate::mm::cache::magazine::Magazine;
    pub type IovaMagazine = Magazine<u64, IOVA_MAG_CAPACITY>;

    pub const PT_MAG_CAPACITY: usize = 8;

    #[derive(Clone, Copy)]
    pub struct PtMagEntry {
        pub phys: u64,
        pub virt: usize,
        pub node: u8,
    }

    impl PtMagEntry {
        pub const fn empty() -> Self {
            Self {
                phys: 0,
                virt: 0,
                node: 0,
            }
        }
        pub const fn is_valid(&self) -> bool {
            self.phys != 0
        }
    }

    pub struct PtMagazine {
        entries: [PtMagEntry; PT_MAG_CAPACITY],
        len: usize,
        preferred_node: u8,
    }

    impl PtMagazine {
        pub fn new() -> Self {
            Self {
                entries: [PtMagEntry::empty(); PT_MAG_CAPACITY],
                len: 0,
                preferred_node: 0,
            }
        }

        pub fn pop(&mut self) -> Option<PtMagEntry> {
            if self.len == 0 {
                None
            } else {
                self.len -= 1;
                let entry = self.entries[self.len];
                self.entries[self.len] = PtMagEntry::empty();
                Some(entry)
            }
        }

        pub fn push(&mut self, entry: PtMagEntry) -> bool {
            if self.len >= PT_MAG_CAPACITY {
                false
            } else {
                self.entries[self.len] = entry;
                self.len += 1;
                true
            }
        }

        pub fn available(&self) -> usize {
            PT_MAG_CAPACITY - self.len
        }

        pub fn len(&self) -> usize {
            self.len
        }

        pub fn set_preferred_node(&mut self, node: u8) {
            self.preferred_node = node;
        }

        pub fn preferred_node(&self) -> u8 {
            self.preferred_node
        }
    }

    #[repr(C, align(64))]
    pub struct PerCpuHot {
        pub self_ptr: usize,
        pub cpu_id: usize,
        pub interrupt_depth: AtomicU32,
        pub preempt_disable_count: AtomicU32,
        pub in_page_fault: AtomicBool,
        pub current_task_ptr: AtomicU64,
        pub current_task_id: AtomicU64,
        cold: Option<NonNull<PerCpuCold>>,
    }

    impl PerCpuHot {
        pub fn new(cpu_id: usize) -> Self {
            Self {
                self_ptr: 0,
                cpu_id,
                interrupt_depth: AtomicU32::new(0),
                preempt_disable_count: AtomicU32::new(0),
                in_page_fault: AtomicBool::new(false),
                current_task_ptr: AtomicU64::new(0),
                current_task_id: AtomicU64::new(0),
                cold: None,
            }
        }

        pub fn set_cold(&mut self, cold_ptr: *mut PerCpuCold) {
            self.cold = NonNull::new(cold_ptr);
        }

        pub fn cold(&self) -> &PerCpuCold {
            self.cold_opt().expect("PerCpuHot.cold not initialized")
        }

        pub fn cold_opt(&self) -> Option<&PerCpuCold> {
            self.cold.map(|ptr| unsafe { ptr.as_ref() })
        }

        pub fn current_task_ptr(&self) -> u64 {
            self.current_task_ptr.load(Ordering::Acquire)
        }

        pub fn current_task_id(&self) -> u64 {
            self.current_task_id.load(Ordering::Acquire)
        }

        pub fn set_current_task(&self, task_ptr: u64, task_id: u64) {
            self.current_task_ptr.store(task_ptr, Ordering::Release);
            self.current_task_id.store(task_id, Ordering::Release);
        }

        pub fn clear_current_task(&self) {
            self.set_current_task(0, 0);
        }

        pub fn enter_page_fault(&self) -> bool {
            self.in_page_fault.swap(true, Ordering::SeqCst)
        }

        pub fn exit_page_fault(&self) {
            self.in_page_fault.store(false, Ordering::SeqCst);
        }

        pub fn in_interrupt(&self) -> bool {
            self.interrupt_depth.load(Ordering::Relaxed) > 0
        }

        pub fn preempt_disable(&self) {
            self.preempt_disable_count.fetch_add(1, Ordering::Relaxed);
        }

        pub fn preempt_enable(&self) {
            let _ = self.preempt_disable_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub struct PerCpuRcuState {
        pub read_depth: AtomicU32,
    }

    impl PerCpuRcuState {
        pub const fn new() -> Self {
            Self {
                read_depth: AtomicU32::new(0),
            }
        }
    }

    pub struct PerCpuCold {
        pub iommu_domain_cache: PerCpuDomainCache,
        pub iova_magazines: [IovaMagazine; MAX_IOMMU_CONTROLLERS],
        pub pt_magazine: PtMagazine,
        pub numa_zonelist:
            [crate::mm::types::NumaNodeId; crate::mm::numa::topology::MAX_NUMA_NODES],
        pub numa_zonelist_len: u8,
        pub local_numa_node: crate::mm::types::NumaNodeId,
        pub rcu_state: PerCpuRcuState,
    }

    impl PerCpuCold {
        pub fn new() -> Self {
            Self {
                iommu_domain_cache: PerCpuDomainCache::new(),
                iova_magazines: array::from_fn(|_| IovaMagazine::new()),
                pt_magazine: PtMagazine::new(),
                numa_zonelist: [crate::mm::types::NumaNodeId::new(0);
                    crate::mm::numa::topology::MAX_NUMA_NODES],
                numa_zonelist_len: 1,
                local_numa_node: crate::mm::types::NumaNodeId::new(0),
                rcu_state: PerCpuRcuState::new(),
            }
        }

        pub fn setup_numa_zonelist(
            &mut self,
            local_node: crate::mm::types::NumaNodeId,
            sorted_nodes: &[crate::mm::types::NumaNodeId;
                 crate::mm::numa::topology::MAX_NUMA_NODES],
            node_count: usize,
        ) {
            self.local_numa_node = local_node;
            self.numa_zonelist_len =
                (node_count as u8).min(crate::mm::numa::topology::MAX_NUMA_NODES as u8);
            for i in 0..self.numa_zonelist_len as usize {
                self.numa_zonelist[i] = sorted_nodes[i];
            }
        }

        pub fn get_local_numa_node(&self) -> crate::mm::types::NumaNodeId {
            self.local_numa_node
        }
    }

    pub fn try_current_cpu_id() -> Option<usize> {
        Some(0)
    }

    pub fn in_interrupt_context() -> bool {
        false
    }

    pub const MAX_CPUS: usize = 8;

    use alloc::boxed::Box;

    static PER_CPU_INIT: AtomicBool = AtomicBool::new(false);
    static mut PER_CPU_HOT_PTR: *mut PerCpuHot = core::ptr::null_mut();
    static mut PER_CPU_COLD_PTR: *mut PerCpuCold = core::ptr::null_mut();

    fn ensure_test_per_cpu() {
        unsafe {
            if !PER_CPU_INIT.load(Ordering::SeqCst) {
                let mut hot = Box::new(PerCpuHot::new(0));
                let cold = Box::new(PerCpuCold::new());
                let cold_ptr = Box::into_raw(cold);
                hot.set_cold(cold_ptr);
                hot.self_ptr = hot.as_ref() as *const _ as usize;
                PER_CPU_HOT_PTR = Box::into_raw(hot);
                PER_CPU_COLD_PTR = cold_ptr;
                PER_CPU_INIT.store(true, Ordering::SeqCst);
            }
        }
    }

    pub fn hot_for_cpu(cpu_id: usize) -> Option<&'static PerCpuHot> {
        if cpu_id >= MAX_CPUS {
            return None;
        }
        ensure_test_per_cpu();
        unsafe { PER_CPU_HOT_PTR.as_ref() }
    }

    pub fn cold_for_cpu(cpu_id: usize) -> Option<&'static PerCpuCold> {
        if cpu_id >= MAX_CPUS {
            return None;
        }
        ensure_test_per_cpu();
        unsafe { PER_CPU_COLD_PTR.as_ref() }
    }

    pub fn with_cpu_hot<R>(cpu_id: usize, f: impl FnOnce(&PerCpuHot) -> R) -> Option<R> {
        hot_for_cpu(cpu_id).map(f)
    }

    pub fn with_cpu_cold<R>(cpu_id: usize, f: impl FnOnce(&PerCpuCold) -> R) -> Option<R> {
        cold_for_cpu(cpu_id).map(f)
    }

    pub fn current_hot() -> Option<&'static PerCpuHot> {
        hot_for_cpu(0)
    }

    pub fn current_cold() -> Option<&'static PerCpuCold> {
        cold_for_cpu(0)
    }

    pub fn with_current_hot<R>(f: impl FnOnce(&PerCpuHot) -> R) -> Option<R> {
        with_cpu_hot(0, f)
    }

    pub fn with_current_cold<R>(f: impl FnOnce(&PerCpuCold) -> R) -> Option<R> {
        with_cpu_cold(0, f)
    }

    pub fn with_current_hot_mut<R>(f: impl FnOnce(&mut PerCpuHot) -> R) -> Option<R> {
        ensure_test_per_cpu();
        unsafe { PER_CPU_HOT_PTR.as_mut().map(f) }
    }

    pub fn with_current_cold_mut<R>(f: impl FnOnce(&mut PerCpuCold) -> R) -> Option<R> {
        ensure_test_per_cpu();
        unsafe { PER_CPU_COLD_PTR.as_mut().map(f) }
    }
}

// Minimal IPC/RRef shims for tests (avoid pulling full IPC/SAS stack).
#[cfg(all(
    test,
    not(feature = "full_mm_tests"),
    not(feature = "qemu-test-export")
))]
pub mod ipc {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct DomainId(u64);

    impl DomainId {
        pub const fn new(id: u64) -> Self {
            Self(id)
        }

        pub const fn as_u64(self) -> u64 {
            self.0
        }

        pub const KERNEL: DomainId = DomainId(0);
    }

    pub mod rref {
        use alloc::boxed::Box;
        use core::ops::{Deref, DerefMut};
        use core::ptr::NonNull;

        use super::DomainId;

        #[derive(Debug)]
        pub struct RRef<T: ?Sized> {
            ptr: NonNull<T>,
            owner: DomainId,
        }

        impl<T> RRef<T> {
            pub fn new(owner: DomainId, val: T) -> Self {
                let boxed = Box::new(val);
                let ptr = NonNull::new(Box::into_raw(boxed)).expect("RRef Box pointer is null");
                Self { ptr, owner }
            }

            pub fn into_raw_parts(self) -> RRefRawParts {
                RRefRawParts::from_rref(self)
            }

            pub unsafe fn from_raw_parts_for_zombie(parts: RRefRawParts) -> Self {
                // Test shim only supports sized types; panic on mismatch in debug mode.
                unsafe {
                    parts
                        .into_rref::<T>()
                        .expect("RRefRawParts type mismatch in test shim")
                }
            }
        }

        impl<T: ?Sized> RRef<T> {
            pub unsafe fn from_raw(ptr: NonNull<T>, owner: DomainId) -> Self {
                Self { ptr, owner }
            }

            pub fn into_raw(self) -> (NonNull<T>, DomainId) {
                let ptr = self.ptr;
                let owner = self.owner;
                core::mem::forget(self);
                (ptr, owner)
            }
        }

        impl<T: ?Sized> Deref for RRef<T> {
            type Target = T;

            fn deref(&self) -> &Self::Target {
                unsafe { self.ptr.as_ref() }
            }
        }

        impl<T: ?Sized> DerefMut for RRef<T> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                unsafe { self.ptr.as_mut() }
            }
        }

        impl<T: ?Sized> Drop for RRef<T> {
            fn drop(&mut self) {
                unsafe {
                    drop(Box::from_raw(self.ptr.as_ptr()));
                }
            }
        }

        unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
        unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RawPartsError {
            TypeMismatch,
            SizeMismatch,
        }

        #[derive(Debug)]
        pub struct RRefRawParts {
            ptr: NonNull<u8>,
            owner: DomainId,
            meta: usize,
            #[cfg(debug_assertions)]
            size: usize,
            #[cfg(debug_assertions)]
            type_hash: u64,
            drop_fn: unsafe fn(NonNull<u8>, DomainId, usize),
        }

        unsafe impl Send for RRefRawParts {}
        unsafe impl Sync for RRefRawParts {}

        impl RRefRawParts {
            pub fn from_rref<T: Sized>(rref: RRef<T>) -> Self {
                #[cfg(debug_assertions)]
                let size = core::mem::size_of_val(&*rref);
                #[cfg(debug_assertions)]
                let type_hash = debug_type_hash(&*rref);
                let (ptr, owner) = rref.into_raw();
                // Simplified: avoid unstable ptr::metadata / ptr::from_raw_parts usage by
                // only supporting sized `RRef<T>` in the test shim. Store meta as zero.
                let meta = 0usize;

                // Embed type-specific drop function (Sized-only for test shim)
                unsafe fn drop_impl<T: Sized>(ptr: NonNull<u8>, owner: DomainId, _meta: usize) {
                    // For sized types we can reconstruct the typed pointer directly.
                    let data_ptr = ptr.as_ptr() as *mut T;
                    let rref: RRef<T> =
                        unsafe { RRef::from_raw(NonNull::new_unchecked(data_ptr), owner) };
                    drop(rref);
                }

                Self {
                    ptr: ptr.cast(),
                    owner,
                    meta,
                    #[cfg(debug_assertions)]
                    size,
                    #[cfg(debug_assertions)]
                    type_hash,
                    drop_fn: drop_impl::<T>,
                }
            }

            pub unsafe fn into_rref<T: Sized>(self) -> Result<RRef<T>, RawPartsError> {
                // Reconstruct typed pointer - test shim assumes sized T.
                let typed_ptr = self.ptr.as_ptr() as *mut T;

                #[cfg(debug_assertions)]
                {
                    let typed_ref: &T = unsafe { &*typed_ptr };
                    let actual_size = core::mem::size_of_val(typed_ref);
                    let actual_hash = debug_type_hash(typed_ref);
                    if self.type_hash != actual_hash {
                        return Err(RawPartsError::TypeMismatch);
                    }
                    if self.size != actual_size {
                        return Err(RawPartsError::SizeMismatch);
                    }
                }

                Ok(unsafe { RRef::from_raw(NonNull::new_unchecked(typed_ptr), self.owner) })
            }

            pub unsafe fn drop_erased(self) {
                unsafe { (self.drop_fn)(self.ptr, self.owner, self.meta) };
            }

            pub(crate) fn into_components(
                self,
            ) -> (
                NonNull<u8>,
                DomainId,
                usize,
                unsafe fn(NonNull<u8>, DomainId, usize),
            ) {
                (self.ptr, self.owner, self.meta, self.drop_fn)
            }

            pub fn owner(&self) -> DomainId {
                self.owner
            }
        }

        #[cfg(debug_assertions)]
        fn debug_type_hash<T: ?Sized>(val: &T) -> u64 {
            crate::util::compute_type_hash(
                core::any::type_name::<T>(),
                core::mem::size_of_val(val),
                core::mem::align_of_val(val),
            )
        }
    }

    pub use rref::RRef;
}

// Minimal task/time shims for tests and benches
#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub mod smp {
    pub fn current_cpu() -> u32 {
        0
    }
    pub fn cpu_count() -> usize {
        1
    }
    pub fn cpu_index() -> usize {
        0
    }
    pub fn try_current_cpu_id() -> Option<u32> {
        Some(0)
    }
    pub fn apic_id_for_cpu(cpu_id: usize) -> Option<u32> {
        Some(cpu_id as u32)
    }
    pub fn cpu_for_apic_id(apic_id: u32) -> Option<usize> {
        Some(apic_id as usize)
    }
    pub fn runtime_workers_released() -> bool {
        false
    }
    pub fn release_runtime_workers() {}
    pub fn wait_for_runtime_workers() {}
    pub fn register_cpu_apic_mapping(_cpu_id: usize, _apic_id: u32) {}
    pub fn reset_cpu_routing_for_tests() {}
    pub fn reset_runtime_workers_for_tests() {}
}

#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub mod cpu {
    pub use crate::smp::{apic_id_for_cpu as apic_id, cpu_for_apic_id as cpu_for_apic};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct CpuBootReport {
        pub detected: u32,
        pub started: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CpuStage {
        Detected,
        BootPrepared,
        Launching,
        PerCpuReady,
        Parked,
        Released,
        LazyTlbExited,
        ExecutorRunning,
        Failed,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CpuSnapshot {
        pub detected_cpu_count: usize,
        pub bootable_cpu_count: usize,
        pub online_cpu_count: usize,
        pub online_cpu_mask: u64,
        pub runtime_workers_released: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IpiKind {
        ExecutorWake,
        TlbFlush,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CpuRecord {
        pub logical_cpu_id: usize,
        pub apic_id: u32,
        pub is_bsp: bool,
        pub numa_node: Option<usize>,
        pub boot_slot: Option<usize>,
        pub bootable: bool,
    }

    pub fn initialize(_boot_info: &boot_proto::ExoBootInfo) -> Result<CpuBootReport, &'static str> {
        Ok(CpuBootReport::default())
    }

    pub fn count() -> usize {
        1
    }

    pub fn detected_count() -> usize {
        1
    }

    pub fn bootable_count() -> usize {
        1
    }

    pub fn current_id() -> usize {
        0
    }

    pub fn try_current_id() -> Option<usize> {
        Some(0)
    }

    pub fn active_ids() -> alloc::vec::Vec<usize> {
        alloc::vec![0]
    }

    pub fn snapshot() -> CpuSnapshot {
        CpuSnapshot {
            detected_cpu_count: 1,
            bootable_cpu_count: 1,
            online_cpu_count: 1,
            online_cpu_mask: 1,
            runtime_workers_released: false,
        }
    }

    pub fn stage(_cpu_id: usize) -> Option<CpuStage> {
        Some(CpuStage::PerCpuReady)
    }

    pub fn stage_name(_cpu_id: usize) -> Option<&'static str> {
        Some("per_cpu_ready")
    }

    pub fn numa_node(_cpu_id: usize) -> Option<usize> {
        Some(0)
    }

    pub fn workers_released() -> bool {
        false
    }

    pub fn release_workers() {}

    pub fn send_ipi(_cpu_id: usize, _kind: IpiKind) {}

    pub fn broadcast_ipi(_kind: IpiKind) {}

    pub fn send_eoi_current_cpu() {}

    pub fn current_apic_id() -> u32 {
        0
    }
}

#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub mod task {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct TaskId(u64);

    impl TaskId {
        pub const fn from_raw(id: u64) -> Self {
            Self(id)
        }

        pub const fn as_u64(self) -> u64 {
            self.0
        }
    }

    pub mod timer {
        /// Return current tick in milliseconds (test stub)
        pub fn current_tick() -> u64 {
            0
        }
    }

    // Convenience shim for tests/benches removed — use `crate::task::current_tick()` directly.

    pub mod per_core_executor {
        pub fn spawn<F>(_future: F)
        where
            F: core::future::Future<Output = ()> + 'static,
        {
        }
    }

    pub async fn sleep_ms(_ms: u64) {}

    pub fn current_tick() -> u64 {
        timer::current_tick()
    }

    pub fn spawn_detached<F>(_future: F) -> TaskId
    where
        F: core::future::Future<Output = ()> + 'static,
    {
        TaskId::from_raw(0)
    }

    pub fn spawn_detached_in_domain<F>(
        _future: F,
        _domain: crate::domain_system::DomainId,
    ) -> TaskId
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

    // Minimal memory helpers for tests
    pub mod memory {
        pub fn physical_memory_offset() -> u64 {
            0
        }
        pub fn total_memory_kb() -> u64 {
            1024 * 1024
        }
        pub fn free_memory_kb() -> u64 {
            512 * 1024
        }
    }

    // Minimal interrupts shim
    pub mod interrupts {
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
    }

    // Minimal domain system stub (正規版 domain_system.rs と互換)
    pub mod domain_system {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct DomainId(pub u64);

        impl DomainId {
            pub const fn new(v: u64) -> Self {
                DomainId(v)
            }

            pub const fn as_u64(&self) -> u64 {
                self.0
            }

            pub const KERNEL: DomainId = DomainId(0);
        }

        impl core::fmt::Display for DomainId {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "Domain({})", self.0)
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum DomainState {
            Initializing,
            Running,
            Suspended,
            Stopped,
            Terminated,
        }

        #[derive(Debug, Clone, Default)]
        pub struct DomainStats {
            pub total: usize,
            pub running: usize,
            pub stopped: usize,
            pub terminated: usize,
            pub memory_used: u64,
            pub total_rrefs: u64,
        }

        pub fn init() {}
        pub fn create_domain(_name: alloc::string::String) -> Option<DomainId> {
            static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
            let id = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Some(DomainId(id))
        }
        pub fn set_domain_state(_id: DomainId, _state: DomainState) {}
        pub fn get_domain_stats() -> DomainStats {
            DomainStats::default()
        }
        pub fn get_stats() -> DomainStats {
            DomainStats::default()
        }
        pub fn handle_domain_panic(_id: DomainId, _msg: alloc::string::String) {}
        pub fn start_domain(_id: DomainId) -> Result<(), &'static str> {
            Ok(())
        }
        pub fn stop_domain(_id: DomainId) -> Result<(), &'static str> {
            Ok(())
        }
        pub fn resume_domain(_id: DomainId) -> Result<(), &'static str> {
            Ok(())
        }
        pub fn terminate_domain(_id: DomainId) -> Result<(), &'static str> {
            Ok(())
        }
        pub fn set_domain_numa(_id: DomainId, _node: usize) {}
        pub fn get_domain_numa(_id: DomainId) -> Option<usize> {
            None
        }
        pub fn add_task_to_domain(_domain_id: DomainId, _task_id: u64) {}
    }

    // Task context counters used by legacy management tests
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
            VirtioBlk(u8),
            VirtioNet(u8),
            Other(u8),
        }

        pub fn wake_from_interrupt(_src: InterruptSource) {
            // No-op in tests/bench harness
        }
    }
}

// time shim removed

// pcid_support shim は未使用のため削除。本来の PCID 実装は mm/sync/pcid.rs を参照。

#[cfg(all(
    test,
    not(feature = "bench"),
    not(feature = "full_mm_tests"),
    not(feature = "qemu-test-export")
))]
pub mod io {
    // Include only the IOMMU implementation for test builds to avoid
    // pulling in the whole I/O subsystem and its wide dependency graph.
    #[path = "iommu/mod.rs"]
    pub mod iommu;

    /// Minimal logger shim for test builds. Kernel code calls `io::log::early_print`,
    /// `io::log::init()` and `io::log::notify_heap_available()` during early boot. We
    /// provide lightweight no-op implementations here so unit tests can run without
    /// pulling the full I/O logging subsystem into the test build.
    pub mod log {
        /// Early boot serial-like print used before the full logger is initialized.
        pub fn early_print(s: &str) {
            std::print!("{}", s);
        }

        pub fn early_print_dec(n: u64) {
            std::print!("{}", n);
        }

        pub fn early_print_hex(n: u64) {
            std::print!("0x{:016x}", n);
        }

        /// Early boot single-character print used by low-level routines.
        pub fn early_print_char(c: u8) {
            std::print!("{}", c as char);
        }

        /// Initialize the logger. Returns Ok(()) for the test shim.
        pub fn init() -> Result<(), ()> {
            Ok(())
        }

        /// Notify the logging subsystem that the heap is now available.
        pub fn notify_heap_available() {}

        /// Print formatted arguments (test stub delegates to early_print).
        pub fn print(args: core::fmt::Arguments) {
            #[cfg(feature = "std")]
            {
                std::print!("{}", args);
            }
            #[cfg(not(feature = "std"))]
            {
                use core::fmt::Write;
                struct SerialWriter;
                impl core::fmt::Write for SerialWriter {
                    fn write_str(&mut self, s: &str) -> core::fmt::Result {
                        early_print(s);
                        Ok(())
                    }
                }
                let _ = SerialWriter.write_fmt(args);
            }
        }
    }

    pub mod interrupt_manager {
        pub fn send_ipi(_apic_id: u32, _vector: u8) {}
        pub fn broadcast_ipi(_vector: u8) {}
    }

    // Minimal PCI stub for test builds so IOMMU functions that reference
    // `crate::io::pci::PciDeviceInfo` compile.
    pub mod pci {
        #[derive(Debug, Clone, Copy)]
        pub struct Bus(pub u8);
        #[derive(Debug, Clone, Copy)]
        pub struct Device(pub u8);
        #[derive(Debug, Clone, Copy)]
        pub struct Function(pub u8);

        #[derive(Debug, Clone, Copy)]
        pub struct Bdf {
            pub bus: Bus,
            pub device: Device,
            pub function: Function,
        }

        #[derive(Debug)]
        pub struct PciDeviceInfo {
            pub bdf: Bdf,
            pub iommu_domain_id: Option<u16>,
        }

        impl PciDeviceInfo {
            pub fn is_pci_bridge(&self) -> bool {
                false
            }
        }
    }

    pub mod nvme {
        // Re-export the task-scoped NVMe driver for compatibility in test builds.
        // Tests expect `crate::io::nvme::NvmePollingDriver` and driver-global helpers.
        pub use crate::task::io::nvme::NvmePollingDriver;

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

    // Minimal MMIO stubs used by the IOMMU unit tests. These provide
    // deterministic behavior suitable for unit testing.
    pub mod mmio {
        pub fn mmio_read_u8(_addr: usize) -> u8 {
            0
        }
        pub fn mmio_read_u16(_addr: usize) -> u16 {
            0
        }
        pub fn mmio_read_u32(_addr: usize) -> u32 {
            0
        }
        pub fn mmio_read_u64(_addr: usize) -> u64 {
            0
        }
        pub fn mmio_write_u8(_addr: usize, _v: u8) {}
        pub fn mmio_write_u16(_addr: usize, _v: u16) {}
        pub fn mmio_write_u32(_addr: usize, _v: u32) {}
        pub fn mmio_write_u64(_addr: usize, _v: u64) {}

        /// Generic volatile read for test builds.
        pub fn volatile_read<T: Copy>(addr: usize) -> T {
            unsafe { core::ptr::read_volatile(addr as *const T) }
        }

        /// Generic volatile write for test builds.
        pub fn volatile_write<T>(addr: usize, val: T) {
            unsafe {
                core::ptr::write_volatile(addr as *mut T, val);
            }
        }
    }

    // Expose a minimal ACPI module in tests so IOMMU init can call into
    // `crate::io::acpi::dmar::parse_dmar` without pulling the full ACPI
    // runtime dependencies into every unit test. This delegates only the
    // DMAR parsing API to the acpi driver crate.
    pub mod acpi {
        pub mod dmar {
            pub use acpi_driver::dmar::*;
        }
        pub mod ivrs {
            pub use acpi_driver::ivrs::*;
        }
    }
}

// When building benches enable a *minimal* I/O module that only includes
// `crate::io::log` so benchmark harnesses can access logging helpers while
// avoiding the heavy dependencies of the full I/O subsystem.
#[cfg(feature = "bench")]
#[path = "io/bench_mod.rs"]
pub mod io;

#[cfg(any(test, feature = "bench"))]
pub use hal;

#[cfg(all(
    test,
    not(feature = "full_mm_tests"),
    not(feature = "qemu-test-export")
))]
pub mod unwind;

#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub mod crypto;
#[cfg(any(not(test), test, feature = "bench", feature = "full_mm_tests"))]
pub mod driver_registry;
#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub mod loader;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod runtime_bridge;
#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub mod sync;

#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub mod sas;

#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub mod util;

#[cfg(any(test, feature = "bench"))]
pub mod nvme {
    pub use crate::io::nvme::*;
}

// Re-export task-scoped shims at crate root so modules that reference
// `crate::memory`, `crate::smp`, `crate::interrupts`, and
// `crate::domain_system` compile in test builds without changes.
#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub use crate::task::domain_system;
#[cfg(any(
    all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ),
    feature = "bench"
))]
pub use crate::task::interrupts;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub mod domain_system;

#[cfg(all(test, feature = "std", not(target_os = "none")))]
mod async_swapout_sim_lib {
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SwapKind {
        File,
        Anon,
    }

    #[derive(Clone, Copy, Debug)]
    struct SwapEntry {
        frame: usize,
        kind: SwapKind,
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn async_swapout_sim_short_baseline() {
        // Simulation parameters (short baseline run)
        // Allow overriding via environment variables for quick parameter sweeps
        let channel_size: usize = std::env::var("ASYNC_SWAPOUT_CHANNEL_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(512);
        let batch_size: usize = std::env::var("ASYNC_SWAPOUT_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16);
        let reserved_file_slots: usize = std::env::var("ASYNC_SWAPOUT_RESERVED_FILE_SLOTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(channel_size / 8);
        let token_bucket_capacity: usize = std::env::var("ASYNC_SWAPOUT_TOKEN_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(channel_size / 4);
        let token_refill_per_batch: usize = std::env::var("ASYNC_SWAPOUT_TOKEN_REFILL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(batch_size / 2);

        let threads: usize = std::env::var("ASYNC_SWAPOUT_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8);
        let iters: usize = std::env::var("ASYNC_SWAPOUT_ITERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(400); // each thread iterations
        // Optional processing delay (ms) to simulate slower I/O via env var
        let proc_delay_ms: u64 = std::env::var("ASYNC_SWAPOUT_PROCESSING_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        // Shared state
        let queue = Arc::new((Mutex::new(VecDeque::<SwapEntry>::new()), Condvar::new()));
        let pending = Arc::new(Mutex::new(HashSet::<usize>::new()));
        let file_queue_count = Arc::new(AtomicUsize::new(0));
        let queue_len_max = Arc::new(AtomicUsize::new(0));
        let tokens = Arc::new(AtomicUsize::new(token_bucket_capacity));

        let enqueue_success = Arc::new(AtomicUsize::new(0));
        let enqueue_failures = Arc::new(AtomicUsize::new(0));
        let processed = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Worker thread
        {
            let queue = queue.clone();
            let pending = pending.clone();
            let file_queue_count = file_queue_count.clone();
            let queue_len_max = queue_len_max.clone();
            let tokens = tokens.clone();
            let processed = processed.clone();
            let shutdown = shutdown.clone();

            thread::spawn(move || {
                loop {
                    // Wait for work or shutdown
                    let mut batch = Vec::new();
                    {
                        let (lock, cvar) = &*queue;
                        let mut q = lock.lock().unwrap();
                        while q.is_empty() && !shutdown.load(Ordering::Acquire) {
                            q = cvar.wait(q).unwrap();
                        }

                        if q.is_empty() && shutdown.load(Ordering::Acquire) {
                            break;
                        }

                        for _ in 0..batch_size {
                            if let Some(e) = q.pop_front() {
                                batch.push(e);
                            } else {
                                break;
                            }
                        }

                        // update observed queue length
                        let cur = q.len();
                        loop {
                            let old = queue_len_max.load(Ordering::Acquire);
                            if cur <= old
                                || queue_len_max
                                    .compare_exchange(old, cur, Ordering::AcqRel, Ordering::Acquire)
                                    .is_ok()
                            {
                                break;
                            }
                        }
                    }

                    if batch.is_empty() {
                        continue;
                    }

                    // process batch (simulate I/O)
                    for entry in batch.iter() {
                        match entry.kind {
                            SwapKind::File => {
                                // simulate page writeback latency
                                thread::sleep(Duration::from_millis(proc_delay_ms));
                                file_queue_count.fetch_sub(1, Ordering::AcqRel);
                            }
                            SwapKind::Anon => {
                                // simulate zswap store latency (faster)
                                thread::sleep(Duration::from_millis(proc_delay_ms));
                            }
                        }

                        // mark processed and clear pending
                        processed.fetch_add(1, Ordering::AcqRel);
                        pending.lock().unwrap().remove(&entry.frame);
                    }

                    // refill tokens after processing batch
                    loop {
                        let cur = tokens.load(Ordering::Acquire);
                        if cur >= token_bucket_capacity {
                            break;
                        }
                        let new = (cur + token_refill_per_batch).min(token_bucket_capacity);
                        if tokens
                            .compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                        {
                            break;
                        }
                    }
                }
            });
        }

        // Enqueuer threads
        let mut joiners = Vec::new();
        let start = Instant::now();
        for t in 0..threads {
            let queue = queue.clone();
            let pending = pending.clone();
            let file_queue_count = file_queue_count.clone();
            let tokens = tokens.clone();
            let enqueue_success = enqueue_success.clone();
            let enqueue_failures = enqueue_failures.clone();

            let j = thread::spawn(move || {
                for i in 0..iters {
                    let is_file = ((i + t) % 2) == 0;
                    let frame = (t * iters) + i; // unique frame id per attempt

                    // try pending check
                    {
                        let mut p = pending.lock().unwrap();
                        if p.contains(&frame) {
                            enqueue_failures.fetch_add(1, Ordering::AcqRel);
                            continue;
                        }

                        // capacity check
                        let (lock, cvar) = &*queue;
                        let mut q = lock.lock().unwrap();
                        if q.len() >= channel_size {
                            enqueue_failures.fetch_add(1, Ordering::AcqRel);
                            continue;
                        }

                        // reservation for file writes
                        if !is_file {
                            let total = q.len();
                            let file_q = file_queue_count.load(Ordering::Acquire);
                            let free_slots = channel_size.saturating_sub(total);
                            if free_slots <= reserved_file_slots && file_q >= reserved_file_slots {
                                enqueue_failures.fetch_add(1, Ordering::AcqRel);
                                continue;
                            }
                        }

                        // token consumption for anon
                        if !is_file {
                            let ok = loop {
                                let cur = tokens.load(Ordering::Acquire);
                                if cur == 0 {
                                    enqueue_failures.fetch_add(1, Ordering::AcqRel);
                                    break false;
                                }
                                if tokens
                                    .compare_exchange(
                                        cur,
                                        cur - 1,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                                {
                                    break true;
                                }
                            };
                            if !ok {
                                continue;
                            }
                        }

                        // all checks passed: insert
                        p.insert(frame);
                        if is_file {
                            file_queue_count.fetch_add(1, Ordering::AcqRel);
                        }
                        q.push_back(SwapEntry {
                            frame,
                            kind: if is_file {
                                SwapKind::File
                            } else {
                                SwapKind::Anon
                            },
                        });
                        cvar.notify_one();
                        enqueue_success.fetch_add(1, Ordering::AcqRel);
                    }
                }
            });
            joiners.push(j);
        }

        for j in joiners {
            j.join().unwrap();
        }

        // Give worker time to finish processing
        loop {
            let (lock, _) = &*queue;
            let q = lock.lock().unwrap();
            if q.is_empty() {
                break;
            }
            drop(q);
            thread::sleep(Duration::from_millis(10));
        }

        // shutdown and wait a moment
        shutdown.store(true, Ordering::Release);
        {
            let (lock, cvar) = &*queue;
            drop(lock.lock().unwrap());
            cvar.notify_all();
        }
        // Wait for workers to finish processing enqueued items (respect proc_delay_ms)
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while processed.load(Ordering::Acquire) < enqueue_success.load(Ordering::Acquire)
            && Instant::now() < wait_deadline
        {
            thread::sleep(Duration::from_millis(10));
        }

        let elapsed = start.elapsed();
        let success = enqueue_success.load(Ordering::Acquire);
        let failures = enqueue_failures.load(Ordering::Acquire);
        let processed = processed.load(Ordering::Acquire);
        let tokens_left = tokens.load(Ordering::Acquire);
        let max_q = queue_len_max.load(Ordering::Acquire);

        println!(
            "async_swapout_sim_short_baseline: threads={} iters={} time={:?}",
            threads, iters, elapsed
        );
        println!(
            "enq_success={}, enq_failures={}, processed={}, tokens_left={}, max_queue_len={}",
            success, failures, processed, tokens_left, max_q
        );

        // Basic sanity checks
        assert_eq!(processed, success);
        assert!(success > 0);
    }
}
