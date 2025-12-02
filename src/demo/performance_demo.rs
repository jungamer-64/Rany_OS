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
    crate::log!("\n");
    crate::log!("================================================================================\n");
    crate::log!("               ExoRust Performance Characteristics Demo\n");
    crate::log!("================================================================================\n\n");
    
    crate::log!("This demonstration highlights the performance benefits of ExoRust's\n");
    crate::log!("Single Address Space (SAS) and Single Privilege Level (SPL) architecture.\n\n");
    
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
    
    crate::log!("================================================================================\n");
    crate::log!("                     Performance Demo Completed\n");
    crate::log!("================================================================================\n\n");
    
    DemoResult::Success
}

/// Demo: System call elimination
fn demo_syscall_elimination() {
    crate::log!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    crate::log!("│  Demo 1: System Call Elimination (SPL)                                    │\n");
    crate::log!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    crate::log!("In traditional OSes, system calls involve:\n");
    crate::log!("  1. SYSCALL instruction (~100-200 cycles)\n");
    crate::log!("  2. Privilege level switch (Ring 3 → Ring 0)\n");
    crate::log!("  3. Stack switch\n");
    crate::log!("  4. Register save/restore\n");
    crate::log!("  5. KPTI overhead (~400-1000 cycles extra)\n");
    crate::log!("  Total: ~500-2000+ CPU cycles\n\n");
    
    crate::log!("In ExoRust, 'system calls' are just function calls:\n");
    
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
    
    crate::log!("  Measured: {} cycles average (function call)\n", avg_cycles);
    crate::log!("  Speedup: ~{}x faster than traditional syscalls\n\n", 
        1500 / avg_cycles.max(1));
    
    crate::log!("This eliminates:\n");
    crate::log!("  ✓ Mode switch overhead\n");
    crate::log!("  ✓ KPTI page table switching\n");
    crate::log!("  ✓ Spectre/Meltdown mitigations in syscall path\n\n");
}

/// Demo: Zero-copy communication
fn demo_zero_copy() {
    use crate::ipc::{RRef, DomainId};
    
    crate::log!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    crate::log!("│  Demo 2: Zero-Copy Inter-Domain Communication                             │\n");
    crate::log!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    crate::log!("Traditional IPC requires copying data between address spaces.\n");
    crate::log!("ExoRust uses ownership transfer in a single address space.\n\n");
    
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
    
    crate::log!("  Data size: {} bytes\n", DATA_SIZE);
    crate::log!("  Traditional (copy): {} cycles\n", avg_copy);
    crate::log!("  ExoRust (RRef transfer): {} cycles\n", avg_transfer);
    crate::log!("  Speedup: {:.1}x faster\n\n", avg_copy as f64 / avg_transfer.max(1) as f64);
    
    crate::log!("Benefits:\n");
    crate::log!("  ✓ O(1) transfer regardless of data size\n");
    crate::log!("  ✓ Memory bandwidth preserved\n");
    crate::log!("  ✓ Cache contents remain valid\n\n");
}

/// Demo: TLB efficiency
fn demo_tlb_efficiency() {
    crate::log!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    crate::log!("│  Demo 3: TLB Efficiency (SAS)                                             │\n");
    crate::log!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    crate::log!("Traditional OS context switches flush TLB entries:\n");
    crate::log!("  - Each CR3 write can invalidate hundreds of TLB entries\n");
    crate::log!("  - TLB miss penalty: ~50-100 cycles per access\n");
    crate::log!("  - Working set must be re-cached after each switch\n\n");
    
    crate::log!("ExoRust's Single Address Space:\n");
    crate::log!("  - NO CR3 writes during task switching\n");
    crate::log!("  - TLB entries persist across all tasks\n");
    crate::log!("  - Effective TLB size = physical TLB size\n\n");
    
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
    
    crate::log!("  Memory region: {} bytes ({} pages)\n", REGION_SIZE, pages);
    crate::log!("  Cold access: {} cycles ({} per page)\n", cold_cycles, cold_cycles / pages as u64);
    crate::log!("  Warm access: {} cycles ({} per page)\n", warm_cycles, warm_cycles / pages as u64);
    crate::log!("  TLB hit speedup: {:.1}x\n\n", cold_cycles as f64 / warm_cycles.max(1) as f64);
    
    core::hint::black_box(sum1);
    core::hint::black_box(sum2);
    
    crate::log!("In ExoRust, TLB stays warm across ALL domain switches!\n\n");
}

/// Demo: Async task efficiency
fn demo_async_efficiency() {
    crate::log!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    crate::log!("│  Demo 4: Async Task Efficiency                                            │\n");
    crate::log!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
    crate::log!("Traditional OS thread context switch:\n");
    crate::log!("  - Save all registers (~16 GP + FPU/SSE state)\n");
    crate::log!("  - Switch stacks (typically 8KB each)\n");
    crate::log!("  - Update scheduler data structures\n");
    crate::log!("  - Typical cost: 3000-10000 cycles\n\n");
    
    crate::log!("ExoRust async task switch:\n");
    crate::log!("  - State machine transition (poll returns Pending)\n");
    crate::log!("  - No stack switch (stackless coroutines)\n");
    crate::log!("  - Minimal register usage\n");
    
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
    
    crate::log!("  Measured yield_point: {} cycles\n", avg_cycles);
    crate::log!("  Compared to thread switch: ~{}x faster\n\n", 5000 / avg_cycles.max(1));
    
    // Task creation
    let mut create_cycles: u64 = 0;
    for _ in 0..1000 {
        let start = rdtsc();
        let task = crate::task::Task::new(async {});
        let end = rdtsc();
        create_cycles += end - start;
        core::hint::black_box(task);
    }
    
    crate::log!("  Task creation: {} cycles avg\n", create_cycles / 1000);
    crate::log!("  (Traditional thread creation: ~10000-50000 cycles)\n\n");
}

/// Demo: Memory management efficiency
fn demo_memory_management() {
    crate::log!("┌────────────────────────────────────────────────────────────────────────────┐\n");
    crate::log!("│  Demo 5: Memory Management                                                │\n");
    crate::log!("└────────────────────────────────────────────────────────────────────────────┘\n\n");
    
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
    
    crate::log!("  Small allocation ({} bytes):\n", SMALL_SIZE);
    crate::log!("    Alloc: {} cycles avg\n", alloc_cycles / ITERATIONS as u64);
    crate::log!("    Dealloc: {} cycles avg\n", dealloc_cycles / ITERATIONS as u64);
    
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
    
    crate::log!("\n  Medium allocation ({} bytes):\n", MEDIUM_SIZE);
    crate::log!("    Alloc: {} cycles avg\n", med_alloc / ITERATIONS as u64);
    
    // Show heap stats
    let (used, free) = crate::memory::heap_stats();
    crate::log!("\n  Current heap state:\n");
    crate::log!("    Used: {} bytes\n", used);
    crate::log!("    Free: {} bytes\n\n", free);
}
