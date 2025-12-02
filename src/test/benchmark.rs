// ============================================================================
// src/test/benchmark.rs - Performance Benchmarks
// ============================================================================

use crate::test::TestResult;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

/// Simple cycle counter for benchmarking
#[inline(always)]
fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
        ((hi as u64) << 32) | (lo as u64)
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Fallback for non-x86_64
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

/// Benchmark result
pub struct BenchmarkResult {
    pub name: &'static str,
    pub iterations: u64,
    pub total_cycles: u64,
    pub min_cycles: u64,
    pub max_cycles: u64,
    pub avg_cycles: u64,
}

impl BenchmarkResult {
    pub fn new(name: &'static str) -> Self {
        BenchmarkResult {
            name,
            iterations: 0,
            total_cycles: 0,
            min_cycles: u64::MAX,
            max_cycles: 0,
            avg_cycles: 0,
        }
    }
    
    pub fn record(&mut self, cycles: u64) {
        self.iterations += 1;
        self.total_cycles += cycles;
        self.min_cycles = self.min_cycles.min(cycles);
        self.max_cycles = self.max_cycles.max(cycles);
        self.avg_cycles = self.total_cycles / self.iterations;
    }
    
    pub fn report(&self) {
        crate::log!("  Benchmark: {}\n", self.name);
        crate::log!("    Iterations: {}\n", self.iterations);
        crate::log!("    Total cycles: {}\n", self.total_cycles);
        crate::log!("    Min cycles: {}\n", self.min_cycles);
        crate::log!("    Max cycles: {}\n", self.max_cycles);
        crate::log!("    Avg cycles: {}\n", self.avg_cycles);
    }
}

/// Benchmark memory throughput
pub fn bench_memory_throughput() -> TestResult {
    const ITERATIONS: usize = 1000;
    const BLOCK_SIZE: usize = 4096;
    
    crate::log!("\n[BENCH] Memory Throughput Benchmark\n");
    
    // Benchmark: Small allocations
    let mut small_alloc = BenchmarkResult::new("small_alloc_64b");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let _data: Box<[u8; 64]> = Box::new([0u8; 64]);
        let end = rdtsc();
        small_alloc.record(end - start);
    }
    small_alloc.report();
    
    // Benchmark: Medium allocations
    let mut medium_alloc = BenchmarkResult::new("medium_alloc_4kb");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let _data: Box<[u8; BLOCK_SIZE]> = Box::new([0u8; BLOCK_SIZE]);
        let end = rdtsc();
        medium_alloc.record(end - start);
    }
    medium_alloc.report();
    
    // Benchmark: Large allocations
    let mut large_alloc = BenchmarkResult::new("large_alloc_64kb");
    for _ in 0..100 { // Fewer iterations for large allocs
        let start = rdtsc();
        let _data: Vec<u8> = Vec::with_capacity(65536);
        let end = rdtsc();
        large_alloc.record(end - start);
    }
    large_alloc.report();
    
    // Benchmark: Memory copy
    let mut memcpy_bench = BenchmarkResult::new("memcpy_4kb");
    let src = [0xAAu8; BLOCK_SIZE];
    let mut dst = [0u8; BLOCK_SIZE];
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        dst.copy_from_slice(&src);
        let end = rdtsc();
        memcpy_bench.record(end - start);
        // Prevent optimization
        core::hint::black_box(&dst);
    }
    memcpy_bench.report();
    
    // Benchmark: Vec push
    let mut vec_push = BenchmarkResult::new("vec_push_1000");
    for _ in 0..100 {
        let start = rdtsc();
        let mut v: Vec<u64> = Vec::new();
        for i in 0..1000 {
            v.push(i);
        }
        let end = rdtsc();
        vec_push.record(end - start);
        core::hint::black_box(v);
    }
    vec_push.report();
    
    crate::log!("[BENCH] Memory throughput benchmark completed\n\n");
    
    TestResult::Passed
}

/// Benchmark task switching
pub fn bench_task_switch() -> TestResult {
    const ITERATIONS: usize = 10000;
    
    crate::log!("\n[BENCH] Task Switch Benchmark\n");
    
    // Benchmark: Yield point overhead
    let mut yield_bench = BenchmarkResult::new("yield_point");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        crate::task::yield_point();
        let end = rdtsc();
        yield_bench.record(end - start);
    }
    yield_bench.report();
    
    // Benchmark: Task creation
    let mut task_create = BenchmarkResult::new("task_create");
    for _ in 0..1000 {
        let start = rdtsc();
        let task = crate::task::Task::new(async {});
        let end = rdtsc();
        task_create.record(end - start);
        core::hint::black_box(task);
    }
    task_create.report();
    
    // Benchmark: TaskId generation
    let mut taskid_gen = BenchmarkResult::new("taskid_gen");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let id = crate::task::TaskId::new();
        let end = rdtsc();
        taskid_gen.record(end - start);
        core::hint::black_box(id);
    }
    taskid_gen.report();
    
    // Benchmark: Atomic operations (baseline)
    let counter = AtomicU64::new(0);
    let mut atomic_bench = BenchmarkResult::new("atomic_inc");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        counter.fetch_add(1, Ordering::SeqCst);
        let end = rdtsc();
        atomic_bench.record(end - start);
    }
    atomic_bench.report();
    
    crate::log!("[BENCH] Task switch benchmark completed\n\n");
    
    TestResult::Passed
}

/// Benchmark function call vs syscall equivalent
pub fn bench_function_call() -> TestResult {
    const ITERATIONS: usize = 100000;
    
    crate::log!("\n[BENCH] Function Call Performance Benchmark\n");
    crate::log!("  (Demonstrating ExoRust's advantage: syscalls are just function calls)\n\n");
    
    // Simple function call (baseline)
    #[inline(never)]
    fn simple_add(a: u64, b: u64) -> u64 {
        a + b
    }
    
    let mut simple_call = BenchmarkResult::new("simple_function_call");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let result = simple_add(42, 58);
        let end = rdtsc();
        simple_call.record(end - start);
        core::hint::black_box(result);
    }
    simple_call.report();
    
    // Function with memory access
    #[inline(never)]
    fn memory_function(data: &[u8]) -> u64 {
        data.iter().map(|&x| x as u64).sum()
    }
    
    let data = [1u8; 64];
    let mut memory_call = BenchmarkResult::new("memory_function_call");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let result = memory_function(&data);
        let end = rdtsc();
        memory_call.record(end - start);
        core::hint::black_box(result);
    }
    memory_call.report();
    
    // Trait object call (dynamic dispatch)
    trait Calculator {
        fn calculate(&self, x: u64) -> u64;
    }
    
    struct Adder(u64);
    impl Calculator for Adder {
        #[inline(never)]
        fn calculate(&self, x: u64) -> u64 {
            x + self.0
        }
    }
    
    let adder: &dyn Calculator = &Adder(10);
    let mut trait_call = BenchmarkResult::new("trait_object_call");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let result = adder.calculate(32);
        let end = rdtsc();
        trait_call.record(end - start);
        core::hint::black_box(result);
    }
    trait_call.report();
    
    // "System call" in ExoRust (just a function)
    let mut syscall_bench = BenchmarkResult::new("exorust_syscall");
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let tick = crate::task::current_tick();
        let end = rdtsc();
        syscall_bench.record(end - start);
        core::hint::black_box(tick);
    }
    syscall_bench.report();
    
    // Comparison summary
    crate::log!("\n  Summary:\n");
    crate::log!("    Simple call: {} cycles avg\n", simple_call.avg_cycles);
    crate::log!("    Memory call: {} cycles avg\n", memory_call.avg_cycles);
    crate::log!("    Trait call:  {} cycles avg\n", trait_call.avg_cycles);
    crate::log!("    ExoRust syscall: {} cycles avg\n", syscall_bench.avg_cycles);
    crate::log!("    (Traditional Linux syscall: ~1000-10000 cycles)\n");
    crate::log!("\n[BENCH] Function call benchmark completed\n\n");
    
    TestResult::Passed
}

/// Benchmark IPC performance
pub fn bench_ipc() -> TestResult {
    use crate::ipc::{RRef, DomainId};
    
    const ITERATIONS: usize = 10000;
    
    crate::log!("\n[BENCH] IPC Performance Benchmark\n");
    
    // RRef creation
    let mut rref_create = BenchmarkResult::new("rref_create");
    for _ in 0..1000 {
        let start = rdtsc();
        let rref = RRef::new(DomainId::new(1), alloc::vec![0u8; 64]);
        let end = rdtsc();
        rref_create.record(end - start);
        core::hint::black_box(rref);
    }
    rref_create.report();
    
    // RRef ownership transfer
    let mut rref_transfer = BenchmarkResult::new("rref_transfer");
    for _ in 0..1000 {
        let rref = RRef::new(DomainId::new(1), alloc::vec![0u8; 64]);
        let start = rdtsc();
        let rref2 = rref.move_to(DomainId::new(2));
        let end = rdtsc();
        rref_transfer.record(end - start);
        core::hint::black_box(rref2);
    }
    rref_transfer.report();
    
    // RRef access
    let mut rref_access = BenchmarkResult::new("rref_access");
    let rref = RRef::new(DomainId::new(1), alloc::vec![0xAAu8; 256]);
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let slice = &rref[..];
        let sum: u64 = slice.iter().map(|&x| x as u64).sum();
        let end = rdtsc();
        rref_access.record(end - start);
        core::hint::black_box(sum);
    }
    rref_access.report();
    
    crate::log!("[BENCH] IPC benchmark completed\n\n");
    
    TestResult::Passed
}

/// Benchmark network stack performance
pub fn bench_network() -> TestResult {
    use crate::net::ethernet::{EthernetFrame, MacAddress, EtherType};
    use crate::net::ipv4::{Ipv4Packet, Ipv4Address};
    
    const ITERATIONS: usize = 10000;
    
    crate::log!("\n[BENCH] Network Stack Benchmark\n");
    
    // Ethernet frame parsing
    let mut eth_parse = BenchmarkResult::new("ethernet_parse");
    let frame_data = {
        let mut data = [0u8; 64];
        data[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        data[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[12..14].copy_from_slice(&[0x08, 0x00]);
        data
    };
    
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let frame = EthernetFrame::parse(&frame_data);
        let end = rdtsc();
        eth_parse.record(end - start);
        core::hint::black_box(frame);
    }
    eth_parse.report();
    
    // IPv4 packet parsing
    let mut ip_parse = BenchmarkResult::new("ipv4_parse");
    let packet_data = {
        let mut data = [0u8; 40];
        data[0] = 0x45;
        data[2..4].copy_from_slice(&[0x00, 0x28]);
        data[8] = 64;
        data[9] = 6;
        data[12..16].copy_from_slice(&[192, 168, 1, 1]);
        data[16..20].copy_from_slice(&[192, 168, 1, 2]);
        data
    };
    
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let packet = Ipv4Packet::parse(&packet_data);
        let end = rdtsc();
        ip_parse.record(end - start);
        core::hint::black_box(packet);
    }
    ip_parse.report();
    
    // MAC address comparison
    let mut mac_cmp = BenchmarkResult::new("mac_compare");
    let mac1 = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    let mac2 = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x56);
    
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let equal = mac1 == mac2;
        let end = rdtsc();
        mac_cmp.record(end - start);
        core::hint::black_box(equal);
    }
    mac_cmp.report();
    
    crate::log!("[BENCH] Network benchmark completed\n\n");
    
    TestResult::Passed
}

/// Run all benchmarks
pub fn run_all_benchmarks() {
    crate::log!("\n");
    crate::log!("================================================================================\n");
    crate::log!("                        ExoRust Performance Benchmark Suite\n");
    crate::log!("================================================================================\n\n");
    
    let _ = bench_memory_throughput();
    let _ = bench_task_switch();
    let _ = bench_function_call();
    let _ = bench_ipc();
    let _ = bench_network();
    
    crate::log!("================================================================================\n");
    crate::log!("                          Benchmark Suite Completed\n");
    crate::log!("================================================================================\n\n");
}
