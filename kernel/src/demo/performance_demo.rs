// ============================================================================
// src/demo/performance_demo.rs - Performance Demonstration
// Shows the benefits of ExoRust's SAS/SPL architecture
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::demo::DemoResult;

/// RDTSC instruction for cycle counting
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
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

/// Demonstration categories
pub struct PerformanceDemo {
    results: Vec<DemoResult>,
}

impl PerformanceDemo {
    pub fn new() -> Self {
        PerformanceDemo {
            results: Vec::new(),
        }
    }
}

/// Run the performance demonstration
pub fn run() -> DemoResult {
    log::info!("\n");
    log::info!("================================================================================\n");
    log::info!("               ExoRust Performance Characteristics Demo\n");
    log::info!("================================================================================\n\n");
    
    log::info!("This demonstration highlights the performance benefits of ExoRust's\n");
    log::info!("Single Address Space (SAS) and Single Privilege Level (SPL) architecture.\n\n");
    
    // Demo 1: System Call Elimination
    demo_syscall_elimination();
    
    // Demo 2: Zero-Copy Communication
    demo_zero_copy();
    
    // Demo 3: TLB Efficiency
    demo_tlb_efficiency();
    
    // Demo 4: Async Task Efficiency
    demo_async_efficiency();
    
    // Demo 5: Memory Management
    demo_memory_management();
    
    log::info!("================================================================================\n");
    log::info!("                     Performance Demo Completed\n");
    log::info!("================================================================================\n\n");
    
    DemoResult::Success
}

/// Demo: System call elimination
fn demo_syscall_elimination() {
    log::info!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    log::info!("│  Demo 1: System Call Elimination (SPL)                                    │\n");
    log::info!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    log::info!("In traditional OSes, system calls involve:\n");
    log::info!("  1. SYSCALL instruction (~100-200 cycles)\n");
    log::info!("  2. Privilege level switch (Ring 3 → Ring 0)\n");
    log::info!("  3. Stack switch\n");
    log::info!("  4. Register save/restore\n");
    log::info!("  5. KPTI overhead (~400-1000 cycles extra)\n");
    log::info!("  Total: ~500-2000+ CPU cycles\n\n");
    
    log::info!("In ExoRust, 'system calls' are just function calls:\n");
    
    // Measure function call overhead
    const ITERATIONS: usize = 100000;
    let mut total_cycles: u64 = 0;
    
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        // This is what a "syscall" looks like in ExoRust - just a function call!
        let _tick = crate::task::current_tick();
        let end = rdtsc();
        total_cycles += end - start;
    }
    
    let avg_cycles = total_cycles / ITERATIONS as u64;
    
    log::info!("  Measured: {} cycles average (function call)\n", avg_cycles);
    log::info!("  Speedup: ~{}x faster than traditional syscalls\n\n", 
        1500 / avg_cycles.max(1));
    
    log::info!("This eliminates:\n");
    log::info!("  ✓ Mode switch overhead\n");
    log::info!("  ✓ KPTI page table switching\n");
    log::info!("  ✓ Spectre/Meltdown mitigations in syscall path\n\n");
}

/// Demo: Zero-copy communication
fn demo_zero_copy() {
    use crate::ipc::{RRef, DomainId};
    
    log::info!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    log::info!("│  Demo 2: Zero-Copy Inter-Domain Communication                             │\n");
    log::info!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    log::info!("Traditional IPC requires copying data between address spaces.\n");
    log::info!("ExoRust uses ownership transfer in a single address space.\n\n");
    
    const DATA_SIZE: usize = 4096;
    const ITERATIONS: usize = 10000;
    
    // Measure traditional approach (with copy)
    let mut copy_cycles: u64 = 0;
    for _ in 0..ITERATIONS {
        let src = alloc::vec![0xAAu8; DATA_SIZE];
        let start = rdtsc();
        let dst = src.clone(); // This is what traditional IPC does
        let end = rdtsc();
        copy_cycles += end - start;
        core::hint::black_box(dst);
    }
    let avg_copy = copy_cycles / ITERATIONS as u64;
    
    // Measure ExoRust approach (zero-copy ownership transfer)
    let mut transfer_cycles: u64 = 0;
    for _ in 0..ITERATIONS {
        let data = alloc::vec![0xAAu8; DATA_SIZE];
        let rref = RRef::new(DomainId::new(1), data);
        let start = rdtsc();
        let rref2 = rref.move_to(DomainId::new(2)); // Just pointer transfer!
        let end = rdtsc();
        transfer_cycles += end - start;
        core::hint::black_box(rref2);
    }
    let avg_transfer = transfer_cycles / ITERATIONS as u64;
    
    log::info!("  Data size: {} bytes\n", DATA_SIZE);
    log::info!("  Traditional (copy): {} cycles\n", avg_copy);
    log::info!("  ExoRust (RRef transfer): {} cycles\n", avg_transfer);
    log::info!("  Speedup: {:.1}x faster\n\n", avg_copy as f64 / avg_transfer.max(1) as f64);
    
    log::info!("Benefits:\n");
    log::info!("  ✓ O(1) transfer regardless of data size\n");
    log::info!("  ✓ Memory bandwidth preserved\n");
    log::info!("  ✓ Cache contents remain valid\n\n");
}

/// Demo: TLB efficiency
fn demo_tlb_efficiency() {
    log::info!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    log::info!("│  Demo 3: TLB Efficiency (SAS)                                             │\n");
    log::info!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    log::info!("Traditional OS context switches flush TLB entries:\n");
    log::info!("  - Each CR3 write can invalidate hundreds of TLB entries\n");
    log::info!("  - TLB miss penalty: ~50-100 cycles per access\n");
    log::info!("  - Working set must be re-cached after each switch\n\n");
    
    log::info!("ExoRust's Single Address Space:\n");
    log::info!("  - NO CR3 writes during task switching\n");
    log::info!("  - TLB entries persist across all tasks\n");
    log::info!("  - Effective TLB size = physical TLB size\n\n");
    
    // Demonstrate memory access patterns
    const REGION_SIZE: usize = 1024 * 1024; // 1MB
    let region: Box<[u8; REGION_SIZE]> = Box::new([0u8; REGION_SIZE]);
    
    // First pass: populate TLB
    let mut sum1: u64 = 0;
    let start1 = rdtsc();
    for i in (0..REGION_SIZE).step_by(4096) {
        sum1 += region[i] as u64;
    }
    let end1 = rdtsc();
    let cold_cycles = end1 - start1;
    
    // Second pass: TLB should be warm
    let mut sum2: u64 = 0;
    let start2 = rdtsc();
    for i in (0..REGION_SIZE).step_by(4096) {
        sum2 += region[i] as u64;
    }
    let end2 = rdtsc();
    let warm_cycles = end2 - start2;
    
    let pages = REGION_SIZE / 4096;
    
    log::info!("  Memory region: {} bytes ({} pages)\n", REGION_SIZE, pages);
    log::info!("  Cold access: {} cycles ({} per page)\n", cold_cycles, cold_cycles / pages as u64);
    log::info!("  Warm access: {} cycles ({} per page)\n", warm_cycles, warm_cycles / pages as u64);
    log::info!("  TLB hit speedup: {:.1}x\n\n", cold_cycles as f64 / warm_cycles.max(1) as f64);
    
    core::hint::black_box(sum1);
    core::hint::black_box(sum2);
    
    log::info!("In ExoRust, TLB stays warm across ALL domain switches!\n\n");
}

/// Demo: Async task efficiency
fn demo_async_efficiency() {
    log::info!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    log::info!("│  Demo 4: Async Task Efficiency                                            │\n");
    log::info!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    log::info!("Traditional OS thread context switch:\n");
    log::info!("  - Save all registers (~16 GP + FPU/SSE state)\n");
    log::info!("  - Switch stacks (typically 8KB each)\n");
    log::info!("  - Update scheduler data structures\n");
    log::info!("  - Typical cost: 3000-10000 cycles\n\n");
    
    log::info!("ExoRust async task switch:\n");
    log::info!("  - State machine transition (poll returns Pending)\n");
    log::info!("  - No stack switch (stackless coroutines)\n");
    log::info!("  - Minimal register usage\n");
    
    // Measure yield_point overhead
    const ITERATIONS: usize = 100000;
    let mut total_cycles: u64 = 0;
    
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        crate::task::yield_point();
        let end = rdtsc();
        total_cycles += end - start;
    }
    
    let avg_cycles = total_cycles / ITERATIONS as u64;
    
    log::info!("  Measured yield_point: {} cycles\n", avg_cycles);
    log::info!("  Compared to thread switch: ~{}x faster\n\n", 5000 / avg_cycles.max(1));
    
    // Task creation
    let mut create_cycles: u64 = 0;
    for _ in 0..1000 {
        let start = rdtsc();
        let task = crate::task::Task::new(async {});
        let end = rdtsc();
        create_cycles += end - start;
        core::hint::black_box(task);
    }
    
    log::info!("  Task creation: {} cycles avg\n", create_cycles / 1000);
    log::info!("  (Traditional thread creation: ~10000-50000 cycles)\n\n");
}

/// Demo: Memory management efficiency
fn demo_memory_management() {
    log::info!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    log::info!("│  Demo 5: Memory Management                                                │\n");
    log::info!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    // Small allocation benchmark
    const SMALL_SIZE: usize = 64;
    const ITERATIONS: usize = 10000;
    
    let mut alloc_cycles: u64 = 0;
    let mut dealloc_cycles: u64 = 0;
    
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let data: Box<[u8; SMALL_SIZE]> = Box::new([0u8; SMALL_SIZE]);
        let mid = rdtsc();
        drop(data);
        let end = rdtsc();
        
        alloc_cycles += mid - start;
        dealloc_cycles += end - mid;
    }
    
    log::info!("  Small allocation ({} bytes):\n", SMALL_SIZE);
    log::info!("    Alloc: {} cycles avg\n", alloc_cycles / ITERATIONS as u64);
    log::info!("    Dealloc: {} cycles avg\n", dealloc_cycles / ITERATIONS as u64);
    
    // Medium allocation benchmark
    const MEDIUM_SIZE: usize = 4096;
    let mut med_alloc: u64 = 0;
    
    for _ in 0..ITERATIONS {
        let start = rdtsc();
        let data: Box<[u8; MEDIUM_SIZE]> = Box::new([0u8; MEDIUM_SIZE]);
        let end = rdtsc();
        med_alloc += end - start;
        core::hint::black_box(data);
    }
    
    log::info!("\n  Medium allocation ({} bytes):\n", MEDIUM_SIZE);
    log::info!("    Alloc: {} cycles avg\n", med_alloc / ITERATIONS as u64);
    
    // Show heap stats
    let (used, free) = crate::memory::heap_stats();
    log::info!("\n  Current heap state:\n");
    log::info!("    Used: {} bytes\n", used);
    log::info!("    Free: {} bytes\n\n", free);
}
