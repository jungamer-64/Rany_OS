// ============================================================================
// src/smp.rs - Symmetric Multi-Processing Support
// ============================================================================
//!
//! SMP (対称型マルチプロセッシング) サポート
//!
//! ## 設計原則 (仕様書 4.3準拠)
//! - AP (Application Processor) 起動シーケンス
//! - Per-CPU データ構造
//! - CPU間通信 (IPI)
//!
//! ## 起動シーケンス
//! 1. BSP: ACPI MADT からCPU情報を取得
//! 2. BSP: トランポリンコードを設定
//! 3. BSP: INIT-SIPI-SIPI シーケンスでAPを起動
//! 4. AP: トランポリンコードを実行
//! 5. AP: 64ビットモードに移行
//! 6. AP: Per-CPUデータを初期化

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 256;

/// Trampoline code physical address (must be below 1MB)
pub const TRAMPOLINE_ADDR: u64 = 0x8000;

/// Stack size per CPU (64KB)
pub const CPU_STACK_SIZE: usize = 64 * 1024;

/// Local APIC base address
pub const LAPIC_BASE: u64 = 0xFEE00000;

// ============================================================================
// Local APIC Registers
// ============================================================================

pub mod lapic_regs {
    /// APIC ID register
    pub const APIC_ID: u64 = 0x20;
    /// APIC Version register
    pub const APIC_VER: u64 = 0x30;
    /// Task Priority Register
    pub const TPR: u64 = 0x80;
    /// End of Interrupt register
    pub const EOI: u64 = 0xB0;
    /// Logical Destination Register
    pub const LDR: u64 = 0xD0;
    /// Destination Format Register
    pub const DFR: u64 = 0xE0;
    /// Spurious Interrupt Vector Register
    pub const SVR: u64 = 0xF0;
    /// Interrupt Command Register (low)
    pub const ICR_LOW: u64 = 0x300;
    /// Interrupt Command Register (high)
    pub const ICR_HIGH: u64 = 0x310;
    /// LVT Timer register
    pub const LVT_TIMER: u64 = 0x320;
    /// LVT LINT0 register
    pub const LVT_LINT0: u64 = 0x350;
    /// LVT LINT1 register
    pub const LVT_LINT1: u64 = 0x360;
    /// LVT Error register
    pub const LVT_ERROR: u64 = 0x370;
    /// Initial Count register
    pub const INIT_COUNT: u64 = 0x380;
    /// Current Count register
    pub const CURR_COUNT: u64 = 0x390;
    /// Divide Configuration register
    pub const DIV_CONF: u64 = 0x3E0;
}

/// ICR delivery modes
pub mod icr_modes {
    /// Fixed delivery mode
    pub const ICR_FIXED: u32 = 0 << 8;
    /// Lowest priority mode
    pub const ICR_LOWEST: u32 = 1 << 8;
    /// SMI delivery mode
    pub const ICR_SMI: u32 = 2 << 8;
    /// NMI delivery mode
    pub const ICR_NMI: u32 = 4 << 8;
    /// INIT delivery mode
    pub const ICR_INIT: u32 = 5 << 8;
    /// Startup IPI delivery mode
    pub const ICR_SIPI: u32 = 6 << 8;
    
    /// Physical destination mode
    pub const ICR_PHYSICAL: u32 = 0 << 11;
    /// Logical destination mode
    pub const ICR_LOGICAL: u32 = 1 << 11;
    
    /// Assert level
    pub const ICR_ASSERT: u32 = 1 << 14;
    /// De-assert level
    pub const ICR_DEASSERT: u32 = 0 << 14;
    
    /// Edge trigger
    pub const ICR_EDGE: u32 = 0 << 15;
    /// Level trigger
    pub const ICR_LEVEL: u32 = 1 << 15;
    
    /// No shorthand
    pub const ICR_NO_SHORTHAND: u32 = 0 << 18;
    /// Self shorthand
    pub const ICR_SELF: u32 = 1 << 18;
    /// All including self
    pub const ICR_ALL_INCL: u32 = 2 << 18;
    /// All excluding self
    pub const ICR_ALL_EXCL: u32 = 3 << 18;
}

// ============================================================================
// CPU State
// ============================================================================

/// CPU state enumeration
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuState {
    /// CPU not present
    NotPresent = 0,
    /// CPU present but not started
    Present = 1,
    /// CPU is being started
    Starting = 2,
    /// CPU is online and idle
    Online = 3,
    /// CPU is busy
    Busy = 4,
    /// CPU is halted
    Halted = 5,
}

impl From<u8> for CpuState {
    fn from(val: u8) -> Self {
        match val {
            1 => CpuState::Present,
            2 => CpuState::Starting,
            3 => CpuState::Online,
            4 => CpuState::Busy,
            5 => CpuState::Halted,
            _ => CpuState::NotPresent,
        }
    }
}

// ============================================================================
// Per-CPU Data
// ============================================================================

/// Per-CPU data structure
#[repr(C, align(64))] // Cache line aligned
pub struct PerCpuData {
    /// CPU ID (Local APIC ID)
    pub cpu_id: u32,
    /// CPU index (0-based)
    pub cpu_index: u32,
    /// CPU state
    state: AtomicU32,
    /// Is BSP flag
    pub is_bsp: bool,
    /// Stack top address
    pub stack_top: u64,
    /// GS base for this CPU
    pub gs_base: u64,
    /// Current task ID
    pub current_task: AtomicU64,
    /// Ticks counted by this CPU
    pub local_ticks: AtomicU64,
    /// IPIs received
    pub ipi_count: AtomicU64,
    /// Preemption disabled counter
    pub preempt_count: AtomicU32,
    /// CPU is in interrupt handler
    pub in_interrupt: AtomicBool,
    _padding: [u8; 16],
}

impl PerCpuData {
    /// Create new per-CPU data
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            cpu_index: 0,
            state: AtomicU32::new(CpuState::NotPresent as u32),
            is_bsp: false,
            stack_top: 0,
            gs_base: 0,
            current_task: AtomicU64::new(0),
            local_ticks: AtomicU64::new(0),
            ipi_count: AtomicU64::new(0),
            preempt_count: AtomicU32::new(0),
            in_interrupt: AtomicBool::new(false),
            _padding: [0; 16],
        }
    }
    
    /// Get CPU state
    pub fn state(&self) -> CpuState {
        CpuState::from(self.state.load(Ordering::Acquire) as u8)
    }
    
    /// Set CPU state
    pub fn set_state(&self, state: CpuState) {
        self.state.store(state as u32, Ordering::Release);
    }
    
    /// Check if preemption is disabled
    pub fn preempt_disabled(&self) -> bool {
        self.preempt_count.load(Ordering::Acquire) > 0
    }
    
    /// Disable preemption
    pub fn disable_preempt(&self) {
        self.preempt_count.fetch_add(1, Ordering::AcqRel);
    }
    
    /// Enable preemption
    pub fn enable_preempt(&self) {
        self.preempt_count.fetch_sub(1, Ordering::AcqRel);
    }
    
    /// Increment local tick counter
    pub fn tick(&self) {
        self.local_ticks.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increment IPI counter
    pub fn count_ipi(&self) {
        self.ipi_count.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// CPU Info
// ============================================================================

/// CPU information from ACPI
#[derive(Clone, Debug)]
pub struct CpuInfo {
    /// Local APIC ID
    pub apic_id: u8,
    /// ACPI processor ID
    pub acpi_id: u8,
    /// Is enabled
    pub enabled: bool,
    /// Is BSP
    pub is_bsp: bool,
}

// ============================================================================
// SMP Manager
// ============================================================================

/// SMP Manager
pub struct SmpManager {
    /// Per-CPU data array
    per_cpu: [PerCpuData; MAX_CPUS],
    /// CPU info list
    cpus: Vec<CpuInfo>,
    /// Number of CPUs detected
    cpu_count: AtomicU32,
    /// Number of CPUs online
    online_count: AtomicU32,
    /// BSP APIC ID
    bsp_apic_id: u32,
    /// Local APIC base address
    lapic_base: u64,
    /// Initialization complete
    initialized: AtomicBool,
}

impl SmpManager {
    /// Create a new SMP manager
    pub const fn new() -> Self {
        const INIT_PER_CPU: PerCpuData = PerCpuData::new();
        
        Self {
            per_cpu: [INIT_PER_CPU; MAX_CPUS],
            cpus: Vec::new(),
            cpu_count: AtomicU32::new(1), // At least BSP
            online_count: AtomicU32::new(1),
            bsp_apic_id: 0,
            lapic_base: LAPIC_BASE,
            initialized: AtomicBool::new(false),
        }
    }
    
    /// Initialize the SMP manager
    pub fn init(&mut self) {
        // Read BSP APIC ID
        self.bsp_apic_id = self.read_lapic_id();
        
        // Initialize BSP per-CPU data
        self.per_cpu[0].cpu_id = self.bsp_apic_id;
        self.per_cpu[0].cpu_index = 0;
        self.per_cpu[0].is_bsp = true;
        self.per_cpu[0].set_state(CpuState::Online);
        
        // Set GS base for BSP
        self.per_cpu[0].gs_base = &self.per_cpu[0] as *const _ as u64;
        
        self.initialized.store(true, Ordering::Release);
        
        crate::log!("[SMP] BSP initialized (APIC ID: {})\n", self.bsp_apic_id);
    }
    
    /// Read local APIC ID
    fn read_lapic_id(&self) -> u32 {
        unsafe {
            let ptr = (self.lapic_base + lapic_regs::APIC_ID) as *const u32;
            (core::ptr::read_volatile(ptr) >> 24) & 0xFF
        }
    }
    
    /// Read local APIC register
    unsafe fn read_lapic(&self, reg: u64) -> u32 {
        let ptr = (self.lapic_base + reg) as *const u32;
        core::ptr::read_volatile(ptr)
    }
    
    /// Write local APIC register
    unsafe fn write_lapic(&self, reg: u64, value: u32) {
        let ptr = (self.lapic_base + reg) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }
    
    /// Add CPU info (from ACPI parsing)
    pub fn add_cpu(&mut self, info: CpuInfo) {
        if info.is_bsp {
            self.bsp_apic_id = info.apic_id as u32;
        }
        
        let index = self.cpus.len();
        if index < MAX_CPUS {
            self.per_cpu[index].cpu_id = info.apic_id as u32;
            self.per_cpu[index].cpu_index = index as u32;
            self.per_cpu[index].is_bsp = info.is_bsp;
            self.per_cpu[index].set_state(if info.enabled {
                CpuState::Present
            } else {
                CpuState::NotPresent
            });
            
            self.cpus.push(info);
            self.cpu_count.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// Start all APs
    pub fn start_aps(&self) -> usize {
        if !self.initialized.load(Ordering::Acquire) {
            return 0;
        }
        
        let mut started = 0;
        
        for (index, cpu) in self.cpus.iter().enumerate() {
            if !cpu.is_bsp && cpu.enabled {
                if self.start_ap(index, cpu.apic_id) {
                    started += 1;
                }
            }
        }
        
        crate::log!("[SMP] Started {} APs\n", started);
        started
    }
    
    /// Start a single AP
    fn start_ap(&self, index: usize, apic_id: u8) -> bool {
        // Setup trampoline code (would copy real-mode bootstrap code to TRAMPOLINE_ADDR)
        self.setup_trampoline(index);
        
        // Mark CPU as starting
        self.per_cpu[index].set_state(CpuState::Starting);
        
        // Send INIT IPI
        unsafe {
            self.send_ipi(apic_id as u32, icr_modes::ICR_INIT | icr_modes::ICR_ASSERT | icr_modes::ICR_LEVEL);
            self.delay_us(10000); // 10ms delay
            
            self.send_ipi(apic_id as u32, icr_modes::ICR_INIT | icr_modes::ICR_DEASSERT | icr_modes::ICR_LEVEL);
            self.delay_us(200); // 200us delay
            
            // Send SIPI (twice for reliability)
            let sipi_vector = (TRAMPOLINE_ADDR >> 12) as u32;
            
            self.send_ipi(apic_id as u32, icr_modes::ICR_SIPI | sipi_vector);
            self.delay_us(200);
            
            self.send_ipi(apic_id as u32, icr_modes::ICR_SIPI | sipi_vector);
        }
        
        // Wait for AP to come online
        for _ in 0..1000 {
            if self.per_cpu[index].state() == CpuState::Online {
                self.online_count.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            unsafe { self.delay_us(1000); } // 1ms
        }
        
        crate::log!("[SMP] Failed to start AP {} (APIC ID: {})\n", index, apic_id);
        self.per_cpu[index].set_state(CpuState::Present);
        false
    }
    
    /// Setup trampoline code for AP startup
    fn setup_trampoline(&self, cpu_index: usize) {
        // In a real implementation, this would:
        // 1. Copy real-mode bootstrap code to TRAMPOLINE_ADDR
        // 2. Set up parameters (stack pointer, entry point, etc.)
        // 3. Set up temporary GDT for 32-bit and 64-bit mode transitions
        
        // For now, we just record the CPU index
        let _ = cpu_index;
    }
    
    /// Send IPI to a specific CPU
    unsafe fn send_ipi(&self, target_apic_id: u32, flags: u32) {
        // Set destination APIC ID
        self.write_lapic(lapic_regs::ICR_HIGH, target_apic_id << 24);
        
        // Send IPI
        self.write_lapic(lapic_regs::ICR_LOW, flags | icr_modes::ICR_PHYSICAL);
        
        // Wait for delivery
        for _ in 0..10000 {
            if self.read_lapic(lapic_regs::ICR_LOW) & (1 << 12) == 0 {
                break;
            }
        }
    }
    
    /// Send IPI to all other CPUs
    pub fn send_ipi_all(&self, vector: u8) {
        unsafe {
            let flags = icr_modes::ICR_FIXED | icr_modes::ICR_ALL_EXCL | (vector as u32);
            self.write_lapic(lapic_regs::ICR_LOW, flags);
        }
    }
    
    /// Send IPI to self
    pub fn send_ipi_self(&self, vector: u8) {
        unsafe {
            let flags = icr_modes::ICR_FIXED | icr_modes::ICR_SELF | (vector as u32);
            self.write_lapic(lapic_regs::ICR_LOW, flags);
        }
    }
    
    /// Microsecond delay (busy wait)
    unsafe fn delay_us(&self, us: u32) {
        // Simple delay loop - would use PIT or TSC in real implementation
        for _ in 0..us * 100 {
            core::hint::spin_loop();
        }
    }
    
    /// End of interrupt
    pub fn eoi(&self) {
        unsafe {
            self.write_lapic(lapic_regs::EOI, 0);
        }
    }
    
    /// Get number of CPUs
    pub fn cpu_count(&self) -> u32 {
        self.cpu_count.load(Ordering::Acquire)
    }
    
    /// Get number of online CPUs
    pub fn online_count(&self) -> u32 {
        self.online_count.load(Ordering::Acquire)
    }
    
    /// Get current CPU index
    pub fn current_cpu(&self) -> u32 {
        let apic_id = self.read_lapic_id();
        
        for (index, data) in self.per_cpu.iter().enumerate() {
            if data.cpu_id == apic_id {
                return index as u32;
            }
        }
        
        0 // Default to BSP
    }
    
    /// Get per-CPU data for current CPU
    pub fn current_per_cpu(&self) -> &PerCpuData {
        let index = self.current_cpu() as usize;
        &self.per_cpu[index]
    }
    
    /// Get per-CPU data by index
    pub fn per_cpu(&self, index: usize) -> Option<&PerCpuData> {
        if index < MAX_CPUS {
            Some(&self.per_cpu[index])
        } else {
            None
        }
    }
    
    /// Check if running on BSP
    pub fn is_bsp(&self) -> bool {
        self.read_lapic_id() == self.bsp_apic_id
    }
}

// ============================================================================
// Global SMP Manager
// ============================================================================

static SMP_MANAGER: RwLock<SmpManager> = RwLock::new(SmpManager::new());

/// Initialize SMP subsystem
pub fn init() {
    SMP_MANAGER.write().init();
}

/// Start all APs
pub fn start_aps() -> usize {
    SMP_MANAGER.read().start_aps()
}

/// Get number of CPUs
pub fn cpu_count() -> u32 {
    SMP_MANAGER.read().cpu_count()
}

/// Get number of online CPUs
pub fn online_count() -> u32 {
    SMP_MANAGER.read().online_count()
}

/// Get current CPU index
pub fn current_cpu() -> u32 {
    SMP_MANAGER.read().current_cpu()
}

/// Check if running on BSP
pub fn is_bsp() -> bool {
    SMP_MANAGER.read().is_bsp()
}

/// Send IPI to all other CPUs
pub fn send_ipi_all(vector: u8) {
    SMP_MANAGER.read().send_ipi_all(vector);
}

/// End of interrupt
pub fn eoi() {
    SMP_MANAGER.read().eoi();
}

/// Get per-CPU data for current CPU
pub fn current_per_cpu() -> &'static PerCpuData {
    // This is safe because per_cpu array is static
    unsafe {
        let manager = SMP_MANAGER.read();
        let index = manager.current_cpu() as usize;
        &*(&manager.per_cpu[index] as *const PerCpuData)
    }
}

// ============================================================================
// AP Entry Point (called from trampoline)
// ============================================================================

/// AP entry point after transitioning to 64-bit mode
#[unsafe(no_mangle)]
pub extern "C" fn ap_entry(cpu_index: u32) -> ! {
    // Get per-CPU data
    let manager = SMP_MANAGER.read();
    
    if let Some(per_cpu) = manager.per_cpu(cpu_index as usize) {
        // Mark CPU as online
        per_cpu.set_state(CpuState::Online);
        
        crate::log!("[SMP] AP {} online (APIC ID: {})\n", cpu_index, per_cpu.cpu_id);
    }
    
    drop(manager);
    
    // Initialize local APIC
    // Enable interrupts
    // Enter scheduler
    
    // For now, just idle
    loop {
        // Wait for work
        unsafe { core::arch::asm!("hlt"); }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cpu_state() {
        assert_eq!(CpuState::from(0), CpuState::NotPresent);
        assert_eq!(CpuState::from(3), CpuState::Online);
    }
    
    #[test]
    fn test_per_cpu_data() {
        let data = PerCpuData::new();
        assert_eq!(data.state(), CpuState::NotPresent);
        assert!(!data.preempt_disabled());
        
        data.disable_preempt();
        assert!(data.preempt_disabled());
        
        data.enable_preempt();
        assert!(!data.preempt_disabled());
    }
}
