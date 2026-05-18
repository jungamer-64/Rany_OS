//! SMP Bootstrap Module for ExoRust Kernel
//!
//! Implements Application Processor (AP) startup sequence using
//! INIT-SIPI-SIPI protocol and per-CPU initialization.
extern crate alloc;

use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::vec::Vec;
use ap_trampoline::{
    ApBootFlags, ApTrampolineLaunchInfo, LAYOUT_VERSION, MAILBOX_OFFSET, PageTable32Addr,
    TRAMPOLINE_SIZE, TrampolineMailboxHandle, TrampolineMailboxReadHandle, TrampolineVirtAddr,
};
use boot_proto::{ApBootLayout, ExoBootInfo};
use core::num::{NonZeroU32, NonZeroU64};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering, fence};

use crate::drivers::apic::LocklessLocalApic;

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
        crate::mm::virt::mapping::physical_memory_offset(),
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

/// AP Bootstrap manager
pub struct ApBootstrap {
    /// LAPIC instance
    lapic: LocklessLocalApic,
    /// Boot info for each AP
    ap_info: Vec<ApBootInfo>,
    /// Long-lived runtime stacks for AP workers after bootstrap handoff
    runtime_stacks: Vec<ApRuntimeStack>,
    /// Validated AP boot handoff shared with the bootloader.
    boot_layout: ApBootLayout,
    /// Shared writable mailbox view into the trampoline page.
    mailbox: PoisonLock<TrampolineMailboxHandle>,
    /// Serialize launches because all APs share one trampoline mailbox page.
    launch_lock: PoisonLock<()>,
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
        let boot_layout = boot_info.ap_boot.layout()?;
        let trampoline_base = boot_layout.trampoline_base();
        let trampoline_virt = TrampolineVirtAddr::new(
            crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new(trampoline_base.as_u64()))
                .as_u64() as usize,
        )?;
        let mailbox = unsafe { TrampolineMailboxHandle::from_trampoline_virt(trampoline_virt) }?;
        let current_page_table = crate::mm::virt::higher_half::get_cr3().as_u64();
        if current_page_table != boot_info.page_table_base {
            log::info!(
                "[SMP] BSP CR3 updated after boot: using current {:#x} instead of boot info {:#x}\n",
                current_page_table,
                boot_info.page_table_base
            );
        }
        log_ap_mapping_probe(
            "ap_trampoline_entry",
            ap_trampoline_entry as *const () as usize as u64,
        );
        log_ap_mapping_probe("ap_boot_probe", core::ptr::addr_of!(AP_BOOT_PROBE) as u64);
        log_ap_mapping_probe("ap_bootstrap", core::ptr::addr_of!(AP_BOOTSTRAP) as u64);

        let mut runtime_stacks = Vec::with_capacity(num_aps as usize);
        for _ in 0..num_aps as usize {
            runtime_stacks.push(allocate_ap_runtime_stack()?);
        }

        let mut ap_info = Vec::with_capacity(num_aps as usize);
        for ap_index in 0..num_aps as usize {
            let mut info = ApBootInfo::new();
            info.stack_ptr = map_ap_stack_window(&boot_layout, ap_index)?;
            info.page_table = current_page_table;
            info.entry_point = ap_trampoline_entry as *const () as usize as u64;
            ap_info.push(info);
        }

        Ok(ApBootstrap {
            lapic: LocklessLocalApic::new(lapic_base),
            ap_info,
            runtime_stacks,
            boot_layout,
            mailbox: PoisonLock::new(mailbox),
            launch_lock: PoisonLock::new(()),
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

    /// Start a single AP
    pub fn start_ap(&self, ap_index: usize, apic_id: u32) -> Result<(), &'static str> {
        let info = self.ap_info.get(ap_index).ok_or("Invalid AP index")?;
        let cpu_id = NonZeroU32::new(
            u32::try_from(ap_index)
                .ok()
                .and_then(|id| id.checked_add(1))
                .ok_or("AP logical CPU ID overflow")?,
        )
        .ok_or("AP logical CPU ID overflow")?;
        // The AP trampoline mailbox encodes CR3 in a nonzero 32-bit field, so
        // bootstrap page-table roots must never use frame 0 or exceed 4 GiB.
        let page_table = PageTable32Addr::new(info.page_table)?;
        let stack_ptr = NonZeroU64::new(info.stack_ptr).ok_or("missing AP stack allocation")?;
        let entry_point =
            NonZeroU64::new(info.entry_point).ok_or("missing AP trampoline entry point")?;
        let launch_info = ApTrampolineLaunchInfo::new(
            ap_index as u32,
            cpu_id,
            page_table,
            stack_ptr,
            entry_point,
            NonZeroU64::new(core::ptr::addr_of!(AP_BOOT_PROBE) as u64),
        );
        let _launch_guard = self.launch_lock.lock_for_init("SMP AP trampoline launch");

        log::info!("[SMP] Starting AP {} (APIC ID: {})\n", ap_index, apic_id);
        crate::smp::mark_launching(cpu_id.get() as usize);

        info.started.store(false, Ordering::Release);
        self.mailbox
            .lock_for_init("SMP AP trampoline mailbox")
            .write_launch(launch_info);

        self.lapic.enable();
        info.set_state(ApState::InitSent);
        self.lapic.send_init(apic_id);
        self.delay_ms(10);

        info.set_state(ApState::SipiSent);
        let vector = self.boot_layout.trampoline_base().sipi_vector();
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
    crate::cpu::count().saturating_sub(1) as u32
}

fn map_ap_stack_window(ap_boot: &ApBootLayout, ap_index: usize) -> Result<u64, &'static str> {
    let stack_phys_base = ap_boot
        .stack_base_for(ap_index)
        .ok_or("missing AP stack allocation")?;
    let window_size = ap_boot.stack_size();
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

/// Rust-side AP trampoline handoff called after long mode is active.
#[inline(never)]
pub unsafe extern "C" fn ap_trampoline_entry(mailbox_ptr: *const u8) -> ! {
    ap_serial_mark(b'B');

    let mailbox = match unsafe { TrampolineMailboxReadHandle::from_const_ptr(mailbox_ptr) } {
        Ok(mailbox) => mailbox,
        Err(_) => {
            ap_serial_mark(b'X');
            // LOOP_PROOF: mode=halt; reason=The trampoline contract guarantees a valid verified mailbox, so any verification failure indicates unrecoverable bootstrap corruption and the AP must stop in place.
            loop {
                core::hint::spin_loop();
            }
        }
    };

    ap_trampoline_entry_inner(mailbox)
}

#[inline(never)]
fn ap_trampoline_entry_inner(mailbox: TrampolineMailboxReadHandle) -> ! {
    let mailbox = match mailbox.read_verified() {
        Ok(mailbox) => mailbox,
        Err(_) => {
            ap_serial_mark(b'X');
            // LOOP_PROOF: mode=halt; reason=The trampoline contract guarantees a valid verified mailbox, so any verification failure indicates unrecoverable bootstrap corruption and the AP must stop in place.
            loop {
                core::hint::spin_loop();
            }
        }
    };

    let ap_probe = mailbox.probe_addr().map_or(0, |probe_addr| unsafe {
        core::ptr::read_volatile(probe_addr.get() as *const u8)
    });
    if ap_probe == AP_BOOT_PROBE {
        ap_serial_mark(b'P');
    } else {
        ap_serial_mark(b'p');
    }

    if let Some(runtime_stack_top) = bootstrap_ref()
        .and_then(|bootstrap| bootstrap.runtime_stack_top(mailbox.ap_slot() as usize))
    {
        unsafe {
            switch_to_ap_runtime_stack(
                runtime_stack_top,
                mailbox.ap_slot(),
                mailbox.cpu_id().get(),
            );
        }
    }

    ap_entry_runtime(mailbox.ap_slot(), mailbox.cpu_id().get())
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
        // LOOP_PROOF: mode=halt; reason=Fatal AP bootstrap failure path intentionally halts in place after logging the unrecoverable error state.;
        loop {
            core::hint::spin_loop();
        }
    }
    ap_serial_mark(b'V');
    ap_serial_mark(b'I');

    unsafe {
        crate::per_cpu::register_current_cpu(cpu_id as usize);
    }
    ap_serial_mark(b'C');

    crate::mm::cache::slab_cache::init_per_core_cache_for_cpu(cpu_id as usize);
    ap_serial_mark(b'D');

    let local_apic =
        LocklessLocalApic::new(crate::platform::acpi::local_apic_address().unwrap_or(0xFEE00000));
    local_apic.init_current_cpu();
    let apic_id = local_apic.id();
    ap_serial_mark(b'E');
    if apic_id < 10 {
        ap_serial_mark(b'0' + apic_id as u8);
    } else {
        ap_serial_mark(b'?');
    }
    crate::interrupts::enable_interrupts();

    // Idle APs are not executing kernel work yet, so remote TLB shootdowns can
    // be deferred until they are brought into active scheduling/execution.
    crate::mm::sync::tlb_batch::enter_lazy_tlb_mode(cpu_id as usize);
    crate::cpu::set_stage(cpu_id as usize, crate::cpu::CpuStage::PerCpuReady);

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

    crate::cpu::set_stage(cpu_id as usize, crate::cpu::CpuStage::Parked);
    // Keep the parked wait loop in this frame so the AP does not leave a
    // long-lived return address on the boot stack while it is sleeping.
    // LOOP_PROOF: mode=event; reason=Parked AP loop exits only when workers are released and otherwise remains in the low-power wait path.;
    loop {
        if crate::cpu::workers_released() {
            crate::interrupts::disable_interrupts();
            break;
        }

        unsafe {
            core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
        }
    }
    crate::cpu::set_stage(cpu_id as usize, crate::cpu::CpuStage::Released);
    local_apic.set_task_priority(0);
    ap_serial_mark(b'R');

    let _ = crate::mm::sync::tlb_batch::exit_lazy_tlb_mode(cpu_id as usize);
    crate::cpu::set_stage(cpu_id as usize, crate::cpu::CpuStage::LazyTlbExited);
    ap_serial_mark(b'H');

    crate::mm::numa::topology::apply_current_cpu_locality();
    crate::cpu::set_stage(cpu_id as usize, crate::cpu::CpuStage::ExecutorRunning);

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
        bootstrap.lapic.broadcast_ipi_excluding_self(vector);
    }
}

/// Send EOI to the current CPU's LAPIC without taking the global APIC driver lock.
pub fn send_eoi_current_cpu() {
    let local_apic =
        LocklessLocalApic::new(crate::platform::acpi::local_apic_address().unwrap_or(0xFEE00000));
    local_apic.send_eoi();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mailbox_handle() -> TrampolineMailboxHandle {
        let trampoline_virt = TrampolineVirtAddr::new(0x1000_0000).unwrap();
        unsafe { TrampolineMailboxHandle::from_trampoline_virt(trampoline_virt).unwrap() }
    }

    fn test_bootstrap_with_ap_info(ap_info: ApBootInfo) -> ApBootstrap {
        ApBootstrap {
            lapic: LocklessLocalApic::new(0),
            ap_info: Vec::from([ap_info]),
            runtime_stacks: Vec::new(),
            boot_layout: valid_ap_boot_info().layout().unwrap(),
            mailbox: PoisonLock::new(test_mailbox_handle()),
            launch_lock: PoisonLock::new(()),
            aps_started: AtomicU32::new(0),
            expected_aps: 1,
        }
    }

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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_accepts_shared_layout() {
        assert!(valid_ap_boot_info().layout().is_ok());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_missing_ready_flag() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.flags = 0;
        assert_eq!(
            ap_boot.layout(),
            Err("shared AP trampoline is not marked ready")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_small_allocation() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.trampoline_size = (TRAMPOLINE_SIZE - 1) as u64;
        assert_eq!(
            ap_boot.layout(),
            Err("shared AP trampoline allocation is smaller than expected")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_high_trampoline_address() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.trampoline_addr = 0x10_0000;
        assert_eq!(
            ap_boot.layout(),
            Err("AP trampoline must reside below 1 MiB")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_unaligned_trampoline_address() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.trampoline_addr = 0x8100;
        assert_eq!(ap_boot.layout(), Err("AP trampoline must be 4 KiB aligned"));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_layout_version_mismatch() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.trampoline_layout_version = LAYOUT_VERSION + 1;
        assert_eq!(
            ap_boot.layout(),
            Err("shared AP trampoline layout version mismatch")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_mailbox_offset_mismatch() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.trampoline_mailbox_offset = (MAILBOX_OFFSET + 8) as u32;
        assert_eq!(
            ap_boot.layout(),
            Err("shared AP trampoline mailbox offset mismatch")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_short_stack_count() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.stack_count = 1;
        assert_eq!(
            ap_boot.layout(),
            Err("shared AP stack allocation count is smaller than AP count")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_unaligned_stack_base() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.stack_base += 1;
        assert_eq!(ap_boot.layout(), Err("AP stack base must be page aligned"));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn mailbox_read_handle_from_const_ptr_rejects_invalid_addresses() {
        assert_eq!(
            unsafe { TrampolineMailboxReadHandle::from_const_ptr(core::ptr::null::<u8>()) },
            Err("AP trampoline mailbox address is null")
        );

        #[repr(align(8))]
        struct Aligned([u8; 2]);

        let mut storage = Aligned([0u8; 2]);
        let misaligned = unsafe { storage.0.as_mut_ptr().add(1) } as *const u8;
        assert_eq!(
            unsafe { TrampolineMailboxReadHandle::from_const_ptr(misaligned) },
            Err("AP trampoline mailbox address is misaligned")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_info_helpers_follow_boot_stack_blocks() {
        let ap_boot = valid_ap_boot_info();
        assert_eq!(ap_boot.stack_base_for(0), Some(0x20_0000));
        assert_eq!(ap_boot.stack_top_for(0), Some(0x21_0000));
        assert_eq!(ap_boot.stack_base_for(1), Some(0x21_0000));
        assert_eq!(ap_boot.stack_top_for(1), Some(0x22_0000));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_rejects_non_page_aligned_stack_size() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.stack_size = 0x18_000 + 1;

        assert_eq!(ap_boot.layout(), Err("AP stack size must be page aligned"));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ap_boot_layout_requires_mapped_page_above_guard() {
        let mut ap_boot = valid_ap_boot_info();
        ap_boot.stack_size = 0x1000;

        assert_eq!(
            ap_boot.layout(),
            Err("AP stack size must include one mapped page above the guard")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn start_ap_rejects_invalid_page_table_before_touching_hardware() {
        let mut ap_info = ApBootInfo::new();
        ap_info.stack_ptr = 0x9000;
        ap_info.page_table = 0x2100;
        ap_info.entry_point = 0x2000;
        let bootstrap = test_bootstrap_with_ap_info(ap_info);

        assert_eq!(
            bootstrap.start_ap(0, 1),
            Err("AP page table base must be 4 KiB aligned")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn start_ap_rejects_zero_entry_point_before_touching_hardware() {
        let mut ap_info = ApBootInfo::new();
        ap_info.stack_ptr = 0x9000;
        ap_info.page_table = 0x2000;
        let bootstrap = test_bootstrap_with_ap_info(ap_info);

        assert_eq!(
            bootstrap.start_ap(0, 1),
            Err("missing AP trampoline entry point")
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn launch_lock_serializes_shared_mailbox_access() {
        let bootstrap = test_bootstrap_with_ap_info(ApBootInfo::new());
        let _guard = bootstrap.launch_lock.lock().unwrap();

        assert!(bootstrap.launch_lock.try_lock().is_err());
    }
}
