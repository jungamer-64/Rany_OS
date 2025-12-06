//! SMP Bootstrap Module for ExoRust Kernel
//!
//! Implements Application Processor (AP) startup sequence using
//! INIT-SIPI-SIPI protocol and per-CPU initialization.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering, fence};
use spin::Mutex;

/// AP Bootstrap state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApState {
    /// AP is offline
    Offline = 0,
    /// INIT sent, waiting
    InitSent = 1,
    /// SIPI sent, starting
    SipiSent = 2,
    /// AP is running trampoline
    Trampoline = 3,
    /// AP is initializing kernel structures
    Initializing = 4,
    /// AP is online and ready
    Online = 5,
    /// AP startup failed
    Failed = 6,
}

/// Per-AP startup info (passed via trampoline)
#[repr(C, align(4096))]
pub struct ApBootInfo {
    /// AP APIC ID
    pub apic_id: u32,
    /// Stack pointer for this AP
    pub stack_ptr: u64,
    /// Page table base (CR3)
    pub page_table: u64,
    /// GDT pointer
    pub gdt_ptr: u64,
    /// IDT pointer
    pub idt_ptr: u64,
    /// Entry point for AP
    pub entry_point: u64,
    /// Startup flag (AP sets to 1 when running)
    pub started: AtomicBool,
    /// Current state
    pub state: AtomicU32,
}

impl ApBootInfo {
    /// Create new AP boot info
    pub const fn new() -> Self {
        ApBootInfo {
            apic_id: 0,
            stack_ptr: 0,
            page_table: 0,
            gdt_ptr: 0,
            idt_ptr: 0,
            entry_point: 0,
            started: AtomicBool::new(false),
            state: AtomicU32::new(ApState::Offline as u32),
        }
    }

    /// Set state
    pub fn set_state(&self, state: ApState) {
        self.state.store(state as u32, Ordering::Release);
    }

    /// Get state
    pub fn get_state(&self) -> ApState {
        match self.state.load(Ordering::Acquire) {
            0 => ApState::Offline,
            1 => ApState::InitSent,
            2 => ApState::SipiSent,
            3 => ApState::Trampoline,
            4 => ApState::Initializing,
            5 => ApState::Online,
            _ => ApState::Failed,
        }
    }
}

/// LAPIC registers (MMIO)
pub struct LocalApic {
    base_address: u64,
}

impl LocalApic {
    /// LAPIC ID register
    const ID: u32 = 0x20;
    /// LAPIC version
    const VERSION: u32 = 0x30;
    /// End of Interrupt
    const EOI: u32 = 0xB0;
    /// Spurious Interrupt Vector
    const SPURIOUS: u32 = 0xF0;
    /// Interrupt Command Register (low)
    const ICR_LOW: u32 = 0x300;
    /// Interrupt Command Register (high)
    const ICR_HIGH: u32 = 0x310;
    /// Timer register
    const TIMER_LVT: u32 = 0x320;
    /// Timer initial count
    const TIMER_INIT: u32 = 0x380;
    /// Timer current count
    const TIMER_CURRENT: u32 = 0x390;
    /// Timer divide config
    const TIMER_DIVIDE: u32 = 0x3E0;

    /// ICR delivery modes
    const DELIVERY_INIT: u32 = 5 << 8;
    const DELIVERY_STARTUP: u32 = 6 << 8;
    const LEVEL_ASSERT: u32 = 1 << 14;
    const LEVEL_DEASSERT: u32 = 0;
    const TRIGGER_EDGE: u32 = 0;
    const TRIGGER_LEVEL: u32 = 1 << 15;

    /// Create new LAPIC instance
    pub fn new(base_address: u64) -> Self {
        LocalApic { base_address }
    }

    /// Read LAPIC register
    ///
    /// # Safety
    /// Must be valid LAPIC address
    #[inline]
    pub unsafe fn read(&self, reg: u32) -> u32 { unsafe {
        let ptr = (self.base_address + reg as u64) as *const u32;
        core::ptr::read_volatile(ptr)
    }}

    /// Write LAPIC register
    ///
    /// # Safety
    /// Must be valid LAPIC address
    #[inline]
    pub unsafe fn write(&self, reg: u32, value: u32) { unsafe {
        let ptr = (self.base_address + reg as u64) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }}

    /// Get LAPIC ID
    pub fn id(&self) -> u32 {
        unsafe { self.read(Self::ID) >> 24 }
    }

    /// Send End of Interrupt
    pub fn eoi(&self) {
        unsafe { self.write(Self::EOI, 0) };
    }

    /// Enable LAPIC
    pub fn enable(&self) {
        unsafe {
            let spurious = self.read(Self::SPURIOUS);
            self.write(Self::SPURIOUS, spurious | 0x100);
        }
    }

    /// Send INIT IPI to target AP
    pub fn send_init(&self, target_apic_id: u32) {
        unsafe {
            // Set destination
            self.write(Self::ICR_HIGH, target_apic_id << 24);

            // Send INIT assert
            self.write(
                Self::ICR_LOW,
                Self::DELIVERY_INIT | Self::LEVEL_ASSERT | Self::TRIGGER_LEVEL,
            );

            // Wait for delivery
            self.wait_for_delivery();

            // Send INIT deassert
            self.write(
                Self::ICR_LOW,
                Self::DELIVERY_INIT | Self::LEVEL_DEASSERT | Self::TRIGGER_LEVEL,
            );

            self.wait_for_delivery();
        }
    }

    /// Send SIPI (Startup IPI) to target AP
    pub fn send_sipi(&self, target_apic_id: u32, vector: u8) {
        unsafe {
            // Set destination
            self.write(Self::ICR_HIGH, target_apic_id << 24);

            // Send SIPI with vector (address = vector * 0x1000)
            self.write(Self::ICR_LOW, Self::DELIVERY_STARTUP | (vector as u32));

            self.wait_for_delivery();
        }
    }

    /// Wait for IPI delivery
    unsafe fn wait_for_delivery(&self) { unsafe {
        // Bit 12 = Delivery Status (0 = idle, 1 = pending)
        while (self.read(Self::ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }}

    /// Send IPI to specific CPU
    pub fn send_ipi(&self, target_apic_id: u32, vector: u8) {
        unsafe {
            self.write(Self::ICR_HIGH, target_apic_id << 24);
            self.write(Self::ICR_LOW, vector as u32);
            self.wait_for_delivery();
        }
    }

    /// Broadcast IPI (excluding self)
    pub fn broadcast_ipi(&self, vector: u8) {
        unsafe {
            // All excluding self
            self.write(Self::ICR_LOW, (vector as u32) | (3 << 18)); // Destination shorthand: All excluding self
            self.wait_for_delivery();
        }
    }
}

/// AP trampoline code location (must be in first 1MB, 4K aligned)
const TRAMPOLINE_BASE: u64 = 0x8000;
/// Size of trampoline code
const TRAMPOLINE_SIZE: usize = 4096;

/// AP Bootstrap manager
pub struct ApBootstrap {
    /// LAPIC instance
    lapic: LocalApic,
    /// Boot info for each AP
    ap_info: Vec<ApBootInfo>,
    /// Number of APs started
    aps_started: AtomicU32,
    /// Expected number of APs
    expected_aps: u32,
}

impl ApBootstrap {
    /// Create new AP bootstrap manager
    pub fn new(lapic_base: u64, num_aps: u32) -> Self {
        let mut ap_info = Vec::with_capacity(num_aps as usize);
        for _ in 0..num_aps {
            ap_info.push(ApBootInfo::new());
        }

        ApBootstrap {
            lapic: LocalApic::new(lapic_base),
            ap_info,
            aps_started: AtomicU32::new(0),
            expected_aps: num_aps,
        }
    }

    /// Get boot info for AP
    pub fn get_ap_info(&self, index: usize) -> Option<&ApBootInfo> {
        self.ap_info.get(index)
    }

    /// Setup trampoline code
    ///
    /// # Safety
    /// Writes to low memory
    pub unsafe fn setup_trampoline(&self) -> Result<(), &'static str> { unsafe {
        // Trampoline code (simplified - real code would be in assembly)
        // This is a placeholder for the actual AP startup code
        static TRAMPOLINE_CODE: [u8; 32] = [
            // 16-bit real mode entry (simplified)
            0xFA, // CLI
            0x31, 0xC0, // XOR AX, AX
            0x8E, 0xD8, // MOV DS, AX
            0x8E, 0xC0, // MOV ES, AX
            0x8E, 0xD0, // MOV SS, AX
            // ... more code to switch to protected mode, long mode
            0xF4, // HLT (placeholder)
            0xEB, 0xFD, // JMP $-1 (loop)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Copy trampoline code to low memory
        let trampoline_ptr = TRAMPOLINE_BASE as *mut u8;
        core::ptr::copy_nonoverlapping(
            TRAMPOLINE_CODE.as_ptr(),
            trampoline_ptr,
            TRAMPOLINE_CODE.len(),
        );

        Ok(())
    }}

    /// Start a single AP
    pub fn start_ap(&self, ap_index: usize, apic_id: u32) -> Result<(), &'static str> {
        let info = self.ap_info.get(ap_index).ok_or("Invalid AP index")?;

        crate::log!("[SMP] Starting AP {} (APIC ID: {})\n", ap_index, apic_id);

        // Setup boot info
        info.set_state(ApState::InitSent);

        // Send INIT IPI
        self.lapic.send_init(apic_id);

        // Wait 10ms
        self.delay_ms(10);

        // Send first SIPI
        info.set_state(ApState::SipiSent);
        let vector = (TRAMPOLINE_BASE / 0x1000) as u8;
        self.lapic.send_sipi(apic_id, vector);

        // Wait 200us
        self.delay_us(200);

        // Send second SIPI (required by spec)
        self.lapic.send_sipi(apic_id, vector);

        // Wait for AP to start (timeout 100ms)
        let timeout = 100_000; // microseconds
        let mut waited = 0u64;

        while !info.started.load(Ordering::Acquire) && waited < timeout {
            self.delay_us(100);
            waited += 100;
        }

        if info.started.load(Ordering::Acquire) {
            info.set_state(ApState::Online);
            self.aps_started.fetch_add(1, Ordering::Relaxed);
            crate::log!("[SMP] AP {} online\n", ap_index);
            Ok(())
        } else {
            info.set_state(ApState::Failed);
            Err("AP startup timeout")
        }
    }

    /// Start all APs
    pub fn start_all_aps(&self, apic_ids: &[u32]) -> u32 {
        let mut started = 0;

        for (i, &apic_id) in apic_ids.iter().enumerate() {
            match self.start_ap(i, apic_id) {
                Ok(()) => started += 1,
                Err(e) => crate::log!("[SMP] Failed to start AP {}: {}\n", i, e),
            }
        }

        started
    }

    /// Get number of started APs
    pub fn aps_online(&self) -> u32 {
        self.aps_started.load(Ordering::Relaxed)
    }

    /// Busy-wait delay in milliseconds
    fn delay_ms(&self, ms: u64) {
        self.delay_us(ms * 1000);
    }

    /// Busy-wait delay in microseconds
    fn delay_us(&self, us: u64) {
        // Simple delay loop (inaccurate but functional)
        // In real code, would use PIT or APIC timer
        let iterations = us * 1000;
        for _ in 0..iterations {
            core::hint::spin_loop();
        }
    }
}

/// Global AP bootstrap instance
static AP_BOOTSTRAP: Mutex<Option<ApBootstrap>> = Mutex::new(None);

/// Initialize SMP bootstrap
///
/// # Safety
/// Modifies low memory and sends IPIs
pub unsafe fn init(lapic_base: u64, num_aps: u32) -> Result<(), &'static str> { unsafe {
    let bootstrap = ApBootstrap::new(lapic_base, num_aps);
    bootstrap.setup_trampoline()?;
    *AP_BOOTSTRAP.lock() = Some(bootstrap);
    Ok(())
}}

/// Start all APs
pub fn start_aps(apic_ids: &[u32]) -> u32 {
    AP_BOOTSTRAP
        .lock()
        .as_ref()
        .map(|b| b.start_all_aps(apic_ids))
        .unwrap_or(0)
}

/// Get number of online APs
pub fn online_aps() -> u32 {
    AP_BOOTSTRAP
        .lock()
        .as_ref()
        .map(|b| b.aps_online())
        .unwrap_or(0)
}

/// AP entry point (called from trampoline)
///
/// This function is called by each AP after the trampoline code
/// has switched to long mode and set up a stack.
#[unsafe(no_mangle)]
pub extern "C" fn ap_entry(ap_index: u32) {
    crate::log!("[SMP] AP {} entered kernel\n", ap_index);

    // Mark as started
    if let Some(bootstrap) = AP_BOOTSTRAP.lock().as_ref() {
        if let Some(info) = bootstrap.get_ap_info(ap_index as usize) {
            info.started.store(true, Ordering::Release);
            info.set_state(ApState::Initializing);
        }
    }

    // Initialize per-CPU structures
    // - Set up GDT/TSS for this CPU
    // - Set up local IDT copy
    // - Enable local APIC
    // - Initialize per-core executor

    fence(Ordering::SeqCst);

    // Mark as online
    if let Some(bootstrap) = AP_BOOTSTRAP.lock().as_ref() {
        if let Some(info) = bootstrap.get_ap_info(ap_index as usize) {
            info.set_state(ApState::Online);
        }
    }

    // Enter scheduler loop
    crate::log!("[SMP] AP {} entering scheduler\n", ap_index);

    loop {
        // Run executor for this core
        core::hint::spin_loop();
    }
}

/// Send IPI to specific CPU
pub fn send_ipi(target_apic_id: u32, vector: u8) {
    if let Some(bootstrap) = AP_BOOTSTRAP.lock().as_ref() {
        bootstrap.lapic.send_ipi(target_apic_id, vector);
    }
}

/// Broadcast IPI to all CPUs (excluding self)
pub fn broadcast_ipi(vector: u8) {
    if let Some(bootstrap) = AP_BOOTSTRAP.lock().as_ref() {
        bootstrap.lapic.broadcast_ipi(vector);
    }
}
