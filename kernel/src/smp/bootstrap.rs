//! SMP Bootstrap Module for ExoRust Kernel
//!
//! Implements Application Processor (AP) startup sequence using
//! INIT-SIPI-SIPI protocol and per-CPU initialization.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate alloc;

use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::vec::Vec;
use ap_trampoline::{
    ApBootFlags, ApTrampolineMailbox, LAYOUT_VERSION, MAILBOX_OFFSET, TRAMPOLINE_SIZE,
};
use boot_proto::ExoBootInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering, fence};

static AP_BOOT_PROBE: u8 = 0x5A;
const PAGE_SIZE: u64 = 4096;
const AP_RUNTIME_STACK_PAGES: usize = 256;
const AP_RUNTIME_STACK_SIZE: usize = AP_RUNTIME_STACK_PAGES * PAGE_SIZE as usize;

#[repr(C, align(4096))]
struct PageAlignedApRuntimeStack([u8; AP_RUNTIME_STACK_SIZE]);

struct ApRuntimeStack {
    _backing: Box<PageAlignedApRuntimeStack>,
    top: u64,
}

fn log_ap_mapping_probe(label: &str, virt: u64) {
    let mapper = crate::mm::virt::higher_half::PhysicalMemoryMapper::new(
        crate::memory::physical_memory_offset(),
    );
    let walker =
        unsafe { crate::mm::virt::higher_half::PageTableWalker::from_current_cr3(&mapper) };
    let virt_addr = crate::mm::virt::higher_half::VirtAddr::new(virt);
    match walker.translate(virt_addr) {
        Some(phys) => log::info!(
            "[SMP] Page-walk {}: virt {:#x} -> phys {:#x}\n",
            label,
            virt,
            phys.as_u64()
        ),
        None => log::info!("[SMP] Page-walk {}: virt {:#x} -> unmapped\n", label, virt),
    }
}

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
    /// IA32_APIC_BASE MSR
    const APIC_BASE_MSR: u32 = 0x1B;
    /// IA32_APIC_BASE[11] = global enable
    const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
    /// LAPIC ID register
    const ID: u32 = 0x20;
    /// LAPIC version
    const VERSION: u32 = 0x30;
    /// End of Interrupt
    const EOI: u32 = 0xB0;
    /// Spurious Interrupt Vector
    const SPURIOUS: u32 = 0xF0;
    /// Task Priority Register
    const TPR: u32 = 0x80;
    /// Interrupt Command Register (low)
    const ICR_LOW: u32 = 0x300;
    /// Interrupt Command Register (high)
    const ICR_HIGH: u32 = 0x310;
    /// Timer register
    const TIMER_LVT: u32 = 0x320;
    /// Thermal sensor LVT
    const THERMAL_LVT: u32 = 0x330;
    /// Performance monitoring counter LVT
    const PMC_LVT: u32 = 0x340;
    /// LINT0
    const LINT0_LVT: u32 = 0x350;
    /// LINT1
    const LINT1_LVT: u32 = 0x360;
    /// Error LVT
    const ERROR_LVT: u32 = 0x370;
    /// Timer initial count
    const TIMER_INIT: u32 = 0x380;
    /// Timer current count
    const TIMER_CURRENT: u32 = 0x390;
    /// Timer divide config
    const TIMER_DIVIDE: u32 = 0x3E0;
    /// Error status register
    const ESR: u32 = 0x280;

    /// Common LVT mask bit
    const LVT_MASKED: u32 = 1 << 16;

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
    #[inline]
    pub fn read(&self, reg: u32) -> u32 {
        let addr = (self.base_address + reg as u64) as usize;
        crate::io::mmio::mmio_read_u32(addr)
    }

    /// Write LAPIC register
    #[inline]
    pub fn write(&self, reg: u32, value: u32) {
        let addr = (self.base_address + reg as u64) as usize;
        crate::io::mmio::mmio_write_u32(addr, value);
    }

    #[inline]
    unsafe fn read_msr(msr: u32) -> u64 {
        let low: u32;
        let high: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
        ((high as u64) << 32) | low as u64
    }

    #[inline]
    unsafe fn write_msr(msr: u32, value: u64) {
        let low = value as u32;
        let high = (value >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }

    /// Get LAPIC ID
    pub fn id(&self) -> u32 {
        self.read(Self::ID) >> 24
    }

    /// Send End of Interrupt
    pub fn eoi(&self) {
        self.write(Self::EOI, 0);
    }

    #[inline]
    pub fn set_task_priority(&self, priority: u8) {
        self.write(Self::TPR, priority as u32);
    }

    /// Enable LAPIC
    pub fn enable(&self) {
        let spurious = self.read(Self::SPURIOUS);
        self.write(Self::SPURIOUS, spurious | 0x100);
    }

    /// Minimal per-CPU LAPIC initialization for AP bring-up.
    pub fn init_current_cpu(&self) {
        unsafe {
            let apic_base = Self::read_msr(Self::APIC_BASE_MSR);
            if (apic_base & Self::APIC_GLOBAL_ENABLE) == 0 {
                Self::write_msr(Self::APIC_BASE_MSR, apic_base | Self::APIC_GLOBAL_ENABLE);
            }
        }

        // Mirror BSP LAPIC safety defaults so APs do not inherit firmware or
        // reset-time local interrupt delivery state on timer/LINT/error sources.
        self.write(Self::SPURIOUS, 0xFF | 0x100);
        self.write(Self::TPR, 0);
        self.write(Self::TIMER_LVT, Self::LVT_MASKED);
        self.write(Self::THERMAL_LVT, Self::LVT_MASKED);
        self.write(Self::PMC_LVT, Self::LVT_MASKED);
        self.write(Self::LINT0_LVT, Self::LVT_MASKED);
        self.write(Self::LINT1_LVT, Self::LVT_MASKED);
        self.write(Self::ERROR_LVT, Self::LVT_MASKED);
        self.write(Self::ESR, 0);
        self.write(Self::ESR, 0);
        self.eoi();
    }

    /// Send INIT IPI to target AP
    pub fn send_init(&self, target_apic_id: u32) {
        crate::io::log::early_print("[SMP] send_init: target=");
        crate::io::log::early_print_dec(target_apic_id as u64);
        crate::io::log::early_print("\n");

        // Set destination
        self.write(Self::ICR_HIGH, target_apic_id << 24);

        // Send INIT assert
        self.write(
            Self::ICR_LOW,
            Self::DELIVERY_INIT | Self::LEVEL_ASSERT | Self::TRIGGER_LEVEL,
        );

        // Wait for delivery
        unsafe {
            if !self.wait_for_delivery("init-assert", target_apic_id) {
                return;
            }
        }

        // Send INIT deassert
        self.write(
            Self::ICR_LOW,
            Self::DELIVERY_INIT | Self::LEVEL_DEASSERT | Self::TRIGGER_LEVEL,
        );

        unsafe {
            let _ = self.wait_for_delivery("init-deassert", target_apic_id);
        }
    }

    /// Send SIPI (Startup IPI) to target AP
    pub fn send_sipi(&self, target_apic_id: u32, vector: u8) {
        crate::io::log::early_print("[SMP] send_sipi: target=");
        crate::io::log::early_print_dec(target_apic_id as u64);
        crate::io::log::early_print(" vector=");
        crate::io::log::early_print_hex(vector as u64);
        crate::io::log::early_print("\n");

        // Set destination
        self.write(Self::ICR_HIGH, target_apic_id << 24);

        // Send SIPI with vector (address = vector * 0x1000)
        self.write(Self::ICR_LOW, Self::DELIVERY_STARTUP | (vector as u32));

        unsafe {
            let _ = self.wait_for_delivery("sipi", target_apic_id);
        }
    }

    /// Wait for IPI delivery
    unsafe fn wait_for_delivery(&self, phase: &str, target_apic_id: u32) -> bool {
        const MAX_SPINS: usize = 1_000_000;
        // Bit 12 = Delivery Status (0 = idle, 1 = pending)
        // LOOP_PROOF: mode=condition; reason=Delivery wait loop exits as soon as LAPIC delivery-status pending bit clears or the bounded diagnostic spin limit is reached.;
        let mut spins = 0usize;
        while (self.read(Self::ICR_LOW) & (1 << 12)) != 0 {
            if spins >= MAX_SPINS {
                crate::io::log::early_print("[SMP] APIC delivery timeout phase=");
                crate::io::log::early_print(phase);
                crate::io::log::early_print(" target=");
                crate::io::log::early_print_dec(target_apic_id as u64);
                crate::io::log::early_print(" icr_low=");
                crate::io::log::early_print_hex(self.read(Self::ICR_LOW) as u64);
                crate::io::log::early_print("\n");
                return false;
            }
            core::hint::spin_loop();
            spins += 1;
        }
        true
    }

    /// Send IPI to specific CPU
    pub fn send_ipi(&self, target_apic_id: u32, vector: u8) {
        self.write(Self::ICR_HIGH, target_apic_id << 24);
        self.write(Self::ICR_LOW, vector as u32);
        unsafe {
            let _ = self.wait_for_delivery("ipi", target_apic_id);
        }
    }

    /// Broadcast IPI (excluding self)
    pub fn broadcast_ipi(&self, vector: u8) {
        // All excluding self
        self.write(Self::ICR_LOW, (vector as u32) | (3 << 18));
        unsafe {
            let _ = self.wait_for_delivery("broadcast", u32::MAX);
        }
    }
}

/// AP Bootstrap manager
pub struct ApBootstrap {
    /// LAPIC instance
    lapic: LocalApic,
    /// Boot info for each AP
    ap_info: Vec<ApBootInfo>,
    /// Long-lived runtime stacks for AP workers after bootstrap handoff
    runtime_stacks: Vec<ApRuntimeStack>,
    /// Physical address of the low-memory trampoline area provided by the bootloader
    trampoline_base: u64,
    /// Number of APs started
    aps_started: AtomicU32,
    /// Expected number of APs
    expected_aps: u32,
}

impl ApBootstrap {
    /// Create new AP bootstrap manager
    pub fn new(
        lapic_base: u64,
        boot_info: &ExoBootInfo,
        num_aps: u32,
    ) -> Result<Self, &'static str> {
        let current_page_table = crate::mm::virt::higher_half::get_cr3().as_u64();
        if current_page_table != boot_info.page_table_base {
            log::info!(
                "[SMP] BSP CR3 updated after boot: using current {:#x} instead of boot info {:#x}\n",
                current_page_table,
                boot_info.page_table_base
            );
        }
        log_ap_mapping_probe("ap_entry_stub", ap_entry_stub as *const () as usize as u64);
        log_ap_mapping_probe("ap_boot_probe", core::ptr::addr_of!(AP_BOOT_PROBE) as u64);
        log_ap_mapping_probe("ap_bootstrap", core::ptr::addr_of!(AP_BOOTSTRAP) as u64);

        let mut runtime_stacks = Vec::with_capacity(num_aps as usize);
        for _ in 0..num_aps as usize {
            runtime_stacks.push(allocate_ap_runtime_stack()?);
        }

        let mut ap_info = Vec::with_capacity(num_aps as usize);
        for ap_index in 0..num_aps as usize {
            let mut info = ApBootInfo::new();
            info.stack_ptr = map_ap_stack_window(&boot_info.ap_boot, ap_index)?;
            info.page_table = current_page_table;
            info.entry_point = ap_entry_stub as *const () as usize as u64;
            ap_info.push(info);
        }

        Ok(ApBootstrap {
            lapic: LocalApic::new(lapic_base),
            ap_info,
            runtime_stacks,
            trampoline_base: boot_info.ap_boot.trampoline_addr,
            aps_started: AtomicU32::new(0),
            expected_aps: num_aps,
        })
    }

    /// Get boot info for AP
    pub fn get_ap_info(&self, index: usize) -> Option<&ApBootInfo> {
        self.ap_info.get(index)
    }

    pub fn runtime_stack_top(&self, index: usize) -> Option<u64> {
        self.runtime_stacks.get(index).map(|stack| stack.top)
    }

    unsafe fn mailbox_ptr(&self) -> *mut ApTrampolineMailbox {
        let trampoline_virt =
            crate::memory::phys_to_virt(x86_64::PhysAddr::new(self.trampoline_base)).as_u64();
        (trampoline_virt as *mut u8).add(MAILBOX_OFFSET) as *mut ApTrampolineMailbox
    }

    /// Start a single AP
    pub fn start_ap(&self, ap_index: usize, apic_id: u32) -> Result<(), &'static str> {
        let info = self.ap_info.get(ap_index).ok_or("Invalid AP index")?;
        let cpu_id = u32::try_from(ap_index)
            .ok()
            .and_then(|id| id.checked_add(1))
            .ok_or("AP logical CPU ID overflow")?;

        if info.stack_ptr == 0 {
            return Err("missing AP stack allocation");
        }
        if info.page_table >> 32 != 0 {
            return Err("AP bootstrap requires CR3 below 4GiB");
        }

        log::info!("[SMP] Starting AP {} (APIC ID: {})\n", ap_index, apic_id);

        unsafe {
            core::ptr::write_volatile(
                self.mailbox_ptr(),
                ApTrampolineMailbox {
                    ap_slot: ap_index as u32,
                    cpu_id,
                    page_table: info.page_table,
                    stack_ptr: info.stack_ptr,
                    entry_point: info.entry_point,
                    probe_addr: core::ptr::addr_of!(AP_BOOT_PROBE) as u64,
                },
            );
        }
        fence(Ordering::SeqCst);

        self.lapic.enable();
        info.set_state(ApState::InitSent);
        self.lapic.send_init(apic_id);
        self.delay_ms(10);

        info.set_state(ApState::SipiSent);
        let vector = (self.trampoline_base / 0x1000) as u8;
        self.lapic.send_sipi(apic_id, vector);
        self.delay_us(200);
        self.lapic.send_sipi(apic_id, vector);

        let timeout = 100_000;
        let mut waited = 0u64;

        // LOOP_PROOF: mode=condition; reason=Startup wait loop is timeout-bounded and exits early when AP started flag becomes true.;
        while !info.started.load(Ordering::Acquire) && waited < timeout {
            self.delay_us(100);
            waited += 100;
        }

        if info.started.load(Ordering::Acquire) {
            info.set_state(ApState::Online);
            crate::smp::register_cpu_apic_mapping(cpu_id as usize, apic_id);
            self.aps_started.fetch_add(1, Ordering::Relaxed);
            log::info!("[SMP] AP {} online\n", ap_index);
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
                Err(e) => log::info!("[SMP] Failed to start AP {}: {}\n", i, e),
            }
        }
        started
    }

    /// Get number of started APs
    pub fn aps_online(&self) -> u32 {
        self.aps_started.load(Ordering::Relaxed)
    }

    fn delay_ms(&self, ms: u64) {
        self.delay_us(ms * 1000);
    }

    fn delay_us(&self, us: u64) {
        let iterations = us * 1000;
        for _ in 0..iterations {
            core::hint::spin_loop();
        }
    }
}

/// Global AP bootstrap instance.
///
/// The bootstrap manager is created once during early boot and intentionally
/// leaked for the kernel lifetime so BSP/AP coordination never needs to hold
/// the global lock across long-running startup paths.
static AP_BOOTSTRAP: PoisonLock<Option<&'static ApBootstrap>> = PoisonLock::new(None);

fn bootstrap_ref() -> Option<&'static ApBootstrap> {
    *AP_BOOTSTRAP.lock().unwrap_or_else(|e| e.into_inner())
}

/// Initialize SMP bootstrap
pub unsafe fn init(
    lapic_base: u64,
    boot_info: &ExoBootInfo,
    num_aps: u32,
) -> Result<(), &'static str> {
    validate_trampoline_handoff(&boot_info.ap_boot)?;
    let bootstrap = Box::leak(Box::new(ApBootstrap::new(lapic_base, boot_info, num_aps)?));
    log::info!(
        "[SMP] Prepared {} AP stack guard page(s) in dedicated virtual windows",
        bootstrap.ap_info.len()
    );
    *AP_BOOTSTRAP.lock().unwrap_or_else(|e| e.into_inner()) = Some(bootstrap);
    Ok(())
}

/// Start all APs
pub fn start_aps(apic_ids: &[u32]) -> u32 {
    bootstrap_ref()
        .map(|bootstrap| bootstrap.start_all_aps(apic_ids))
        .unwrap_or(0)
}

/// Get number of online APs
pub fn online_aps() -> u32 {
    bootstrap_ref()
        .map(|bootstrap| bootstrap.aps_online())
        .unwrap_or(0)
}

fn ap_stack_base(ap_boot: &boot_proto::ApBootInfo, ap_index: usize) -> u64 {
    if ap_boot.stack_base == 0
        || ap_boot.stack_size == 0
        || ap_index >= ap_boot.stack_count as usize
    {
        return 0;
    }

    ap_boot.stack_base + (ap_index * ap_boot.stack_size as usize) as u64
}

fn ap_stack_top(ap_boot: &boot_proto::ApBootInfo, ap_index: usize) -> u64 {
    let stack_base = ap_stack_base(ap_boot, ap_index);
    if stack_base == 0 {
        return 0;
    }

    stack_base + ap_boot.stack_size
}

fn ap_stack_window_size(ap_boot: &boot_proto::ApBootInfo) -> Result<u64, &'static str> {
    if ap_boot.stack_size == 0 || ap_boot.stack_size % PAGE_SIZE != 0 {
        return Err("AP stack size must be page aligned");
    }

    if ap_boot.stack_size <= PAGE_SIZE {
        return Err("AP stack size must include one mapped page above the guard");
    }

    Ok(ap_boot.stack_size)
}

fn map_ap_stack_window(
    ap_boot: &boot_proto::ApBootInfo,
    ap_index: usize,
) -> Result<u64, &'static str> {
    let stack_phys_base = ap_stack_base(ap_boot, ap_index);
    if stack_phys_base == 0 {
        return Err("missing AP stack allocation");
    }

    let window_size = ap_stack_window_size(ap_boot)?;
    let window_pages = usize::try_from(window_size / PAGE_SIZE)
        .map_err(|_| "AP stack size exceeds kernel virtual allocation limits")?;
    let window_base = crate::mm::virt::higher_half::allocate_kernel_virt(window_pages);

    let mapped_virt = window_base + PAGE_SIZE;
    let mapped_phys = crate::mm::virt::higher_half::PhysAddr::new(stack_phys_base + PAGE_SIZE);
    let mapped_size = window_size - PAGE_SIZE;

    unsafe {
        crate::mm::virt::higher_half::global_map_range(
            mapped_virt,
            mapped_phys,
            mapped_size,
            crate::mm::virt::higher_half::PageFlags::kernel_data(),
        )
    }
    .map_err(|_| "failed to map AP stack window")?;

    Ok(window_base.as_u64() + window_size)
}

fn allocate_ap_runtime_stack() -> Result<ApRuntimeStack, &'static str> {
    let layout = core::alloc::Layout::new::<PageAlignedApRuntimeStack>();
    let non_null =
        crate::util::allocate_zeroed(layout).ok_or("failed to allocate AP runtime stack")?;
    let backing = unsafe { Box::from_raw(non_null.as_ptr() as *mut PageAlignedApRuntimeStack) };
    let backing_bottom = backing.0.as_ptr() as u64;
    let backing_phys = crate::mm::virt::higher_half::global_translate(
        crate::mm::virt::higher_half::VirtAddr::new(backing_bottom),
    )
    .ok_or("failed to translate AP runtime stack backing")?;

    let window_base = crate::mm::virt::higher_half::allocate_kernel_virt(AP_RUNTIME_STACK_PAGES);
    let mapped_virt = window_base + PAGE_SIZE;
    let mapped_phys = backing_phys + PAGE_SIZE;
    let mapped_size = (AP_RUNTIME_STACK_SIZE as u64) - PAGE_SIZE;

    unsafe {
        crate::mm::virt::higher_half::global_map_range(
            mapped_virt,
            mapped_phys,
            mapped_size,
            crate::mm::virt::higher_half::PageFlags::kernel_data(),
        )
    }
    .map_err(|_| "failed to map AP runtime stack window")?;

    Ok(ApRuntimeStack {
        _backing: backing,
        top: window_base.as_u64() + AP_RUNTIME_STACK_SIZE as u64,
    })
}

#[inline]
fn ap_serial_mark(marker: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") marker,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline(never)]
fn ap_enter_executor(cpu_id: usize) -> ! {
    ap_serial_mark(b'J');
    ap_serial_mark(b'K');
    ap_serial_mark(b'L');
    crate::task::run_forever(cpu_id);
}

/// AP entry point (called from trampoline)
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn ap_entry_stub(_ap_slot: u32, _cpu_id: u32) -> ! {
    core::arch::naked_asm!(
        "jmp {inner}",
        inner = sym ap_entry_inner,
    )
}

pub extern "C" fn ap_entry_inner(ap_slot: u32, cpu_id: u32) -> ! {
    ap_serial_mark(b'B');

    let ap_probe = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(AP_BOOT_PROBE)) };
    if ap_probe == AP_BOOT_PROBE {
        ap_serial_mark(b'P');
    } else {
        ap_serial_mark(b'p');
    }

    if let Some(runtime_stack_top) =
        bootstrap_ref().and_then(|bootstrap| bootstrap.runtime_stack_top(ap_slot as usize))
    {
        unsafe {
            switch_to_ap_runtime_stack(runtime_stack_top, ap_slot, cpu_id);
        }
    }

    ap_entry_runtime(ap_slot, cpu_id)
}

#[inline(never)]
unsafe fn switch_to_ap_runtime_stack(stack_top: u64, ap_slot: u32, cpu_id: u32) -> ! {
    core::arch::asm!(
        "mov rsp, {stack_top}",
        "mov edi, {ap_slot:e}",
        "mov esi, {cpu_id:e}",
        "jmp {target}",
        stack_top = in(reg) stack_top,
        ap_slot = in(reg) ap_slot,
        cpu_id = in(reg) cpu_id,
        target = sym ap_entry_runtime,
        options(noreturn)
    );
}

#[inline(never)]
pub extern "C" fn ap_entry_runtime(ap_slot: u32, cpu_id: u32) -> ! {
    ap_serial_mark(b'S');
    ap_serial_mark(b'Q');
    if crate::interrupts::load_for_cpu(cpu_id as usize).is_err() {
        ap_serial_mark(b'X');
        loop {
            core::hint::spin_loop();
        }
    }
    ap_serial_mark(b'V');
    ap_serial_mark(b'I');

    unsafe {
        crate::per_cpu::setup_current_cpu(cpu_id as usize);
    }
    ap_serial_mark(b'C');

    crate::mm::cache::slab_cache::init_per_core_cache_for_cpu(cpu_id as usize);
    ap_serial_mark(b'D');

    let local_apic =
        LocalApic::new(crate::platform::acpi::local_apic_address().unwrap_or(0xFEE00000));
    local_apic.init_current_cpu();
    let apic_id = local_apic.id();
    ap_serial_mark(b'E');
    if apic_id < 10 {
        ap_serial_mark(b'0' + apic_id as u8);
    } else {
        ap_serial_mark(b'?');
    }
    crate::io::nvme::per_core::register_apic_mapping(apic_id, cpu_id);

    crate::interrupts::enable_interrupts();

    // Idle APs are not executing kernel work yet, so remote TLB shootdowns can
    // be deferred until they are brought into active scheduling/execution.
    crate::mm::sync::tlb_batch::enter_lazy_tlb_mode(cpu_id as usize);
    crate::smp::set_runtime_worker_stage(
        cpu_id as usize,
        crate::smp::RuntimeWorkerStage::BootstrapReady,
    );

    // Parked AP workers should only wake for the dedicated executor/TLB IPIs.
    // Mask lower-priority device IRQs until the runtime handoff completes.
    local_apic.set_task_priority(0xE0);

    if let Some(bootstrap) = bootstrap_ref() {
        if let Some(info) = bootstrap.get_ap_info(ap_slot as usize) {
            info.started.store(true, Ordering::Release);
            info.set_state(ApState::Initializing);
        }
    }
    ap_serial_mark(b'F');

    fence(Ordering::SeqCst);

    if let Some(bootstrap) = bootstrap_ref() {
        if let Some(info) = bootstrap.get_ap_info(ap_slot as usize) {
            info.set_state(ApState::Online);
        }
    }
    ap_serial_mark(b'G');

    crate::smp::set_runtime_worker_stage(cpu_id as usize, crate::smp::RuntimeWorkerStage::Parked);
    // Keep the parked wait loop in this frame so the AP does not leave a
    // long-lived return address on the boot stack while it is sleeping.
    loop {
        if crate::smp::runtime_workers_released() {
            crate::interrupts::disable_interrupts();
            break;
        }

        unsafe {
            core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
        }
    }
    crate::smp::set_runtime_worker_stage(
        cpu_id as usize,
        crate::smp::RuntimeWorkerStage::ReleaseObserved,
    );
    local_apic.set_task_priority(0);
    crate::smp::set_runtime_worker_stage(
        cpu_id as usize,
        crate::smp::RuntimeWorkerStage::HandoffIrqsMasked,
    );
    ap_serial_mark(b'R');

    let _ = crate::mm::sync::tlb_batch::exit_lazy_tlb_mode(cpu_id as usize);
    crate::smp::set_runtime_worker_stage(
        cpu_id as usize,
        crate::smp::RuntimeWorkerStage::LazyTlbExited,
    );
    ap_serial_mark(b'H');

    ap_enter_executor(cpu_id as usize);
}

/// Send IPI to specific CPU
pub fn send_ipi(target_apic_id: u32, vector: u8) {
    if let Some(bootstrap) = bootstrap_ref() {
        bootstrap.lapic.send_ipi(target_apic_id, vector);
    }
}

/// Broadcast IPI to all CPUs (excluding self)
pub fn broadcast_ipi(vector: u8) {
    if let Some(bootstrap) = bootstrap_ref() {
        bootstrap.lapic.broadcast_ipi(vector);
    }
}

/// Send EOI to the current CPU's LAPIC without taking the global APIC driver lock.
pub fn send_eoi_current_cpu() {
    let local_apic =
        LocalApic::new(crate::platform::acpi::local_apic_address().unwrap_or(0xFEE00000));
    local_apic.eoi();
}

fn validate_trampoline_handoff(ap_boot: &boot_proto::ApBootInfo) -> Result<(), &'static str> {
    if ap_boot.trampoline_addr == 0 {
        return Err("missing AP trampoline allocation");
    }
    if (ap_boot.flags & ApBootFlags::TRAMPOLINE_READY) == 0 {
        return Err("shared AP trampoline is not marked ready");
    }
    if ap_boot.trampoline_size < TRAMPOLINE_SIZE as u64 {
        return Err("shared AP trampoline allocation is smaller than expected");
    }
    if ap_boot.trampoline_layout_version != LAYOUT_VERSION {
        return Err("shared AP trampoline layout version mismatch");
    }
    if ap_boot.trampoline_mailbox_offset != MAILBOX_OFFSET as u32 {
        return Err("shared AP trampoline mailbox offset mismatch");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_ap_boot_info() -> boot_proto::ApBootInfo {
        boot_proto::ApBootInfo {
            ap_count: 2,
            stack_count: 2,
            _reserved: [0; 4],
            flags: ApBootFlags::TRAMPOLINE_READY,
            trampoline_layout_version: LAYOUT_VERSION,
            trampoline_mailbox_offset: MAILBOX_OFFSET as u32,
            _reserved2: [0; 4],
            trampoline_addr: 0x8000,
            trampoline_size: TRAMPOLINE_SIZE as u64,
            stack_base: 0x20_0000,
            stack_size: 0x10_000,
        }
    }

    #[test_case]
    fn validate_trampoline_handoff_accepts_shared_layout() {
        assert!(validate_trampoline_handoff(&valid_ap_boot_info()).is_ok());
    }

    #[test_case]
    fn validate_trampoline_handoff_rejects_missing_ready_flag() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.flags = 0;
        assert_eq!(
            validate_trampoline_handoff(&ap_boot),
            Err("shared AP trampoline is not marked ready")
        );
    }

    #[test_case]
    fn validate_trampoline_handoff_rejects_small_allocation() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.trampoline_size = (TRAMPOLINE_SIZE - 1) as u64;
        assert_eq!(
            validate_trampoline_handoff(&ap_boot),
            Err("shared AP trampoline allocation is smaller than expected")
        );
    }

    #[test_case]
    fn validate_trampoline_handoff_rejects_layout_version_mismatch() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.trampoline_layout_version = LAYOUT_VERSION + 1;
        assert_eq!(
            validate_trampoline_handoff(&ap_boot),
            Err("shared AP trampoline layout version mismatch")
        );
    }

    #[test_case]
    fn validate_trampoline_handoff_rejects_mailbox_offset_mismatch() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.trampoline_mailbox_offset = (MAILBOX_OFFSET + 8) as u32;
        assert_eq!(
            validate_trampoline_handoff(&ap_boot),
            Err("shared AP trampoline mailbox offset mismatch")
        );
    }

    #[test_case]
    fn ap_stack_base_and_top_follow_boot_stack_blocks() {
        let ap_boot = valid_ap_boot_info();
        assert_eq!(ap_stack_base(&ap_boot, 0), 0x20_0000);
        assert_eq!(ap_stack_top(&ap_boot, 0), 0x21_0000);
        assert_eq!(ap_stack_base(&ap_boot, 1), 0x21_0000);
        assert_eq!(ap_stack_top(&ap_boot, 1), 0x22_0000);
    }

    #[test_case]
    fn ap_stack_window_requires_page_aligned_stack_size() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.stack_size = 0x18_000 + 1;

        assert_eq!(
            ap_stack_window_size(&ap_boot),
            Err("AP stack size must be page aligned")
        );
    }

    #[test_case]
    fn ap_stack_window_requires_mapped_page_above_guard() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.stack_size = 0x1000;

        assert_eq!(
            ap_stack_window_size(&ap_boot),
            Err("AP stack size must include one mapped page above the guard")
        );
    }
}
