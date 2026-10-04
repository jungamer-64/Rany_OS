// src/interrupts/mod.rs - 割り込みシステム統合モジュール
//
// GDT, IDT, 例外ハンドラ、ハードウェア割り込みを統合管理
// ============================================================================
pub mod exceptions;
pub mod gdt;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use x86_64::structures::idt::InterruptDescriptorTable;

// Helper macro to coerce handler function items into the expected
// `extern "x86-interrupt" fn(...)` signatures for the IDT setup when
// building on MSVC host targets. On MSVC we compile handlers as
// `extern "C"` to avoid MSVC-specific codegen/linker alignment issues,
// so this macro uses an `unsafe` transmute at the call sites only on MSVC.
// On non-MSVC targets it expands to the function path unchanged.
#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
macro_rules! handler_to_x86 {
    ($h:path as $t:ty) => {
        // Convert function item to integer then to the desired function pointer type.
        // This avoids trying to transmute the zero-sized function item type directly.
        unsafe { core::mem::transmute::<usize, $t>($h as *const () as usize) }
    };
}

#[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
macro_rules! handler_to_x86 {
    ($h:path as $t:ty) => {
        $h
    };
}

/// Network driver poll fallback gate (enabled after bridge initialization).
static NET_DRIVER_POLL_FALLBACK_ENABLED: AtomicBool = AtomicBool::new(false);
/// Pending flag for deferred network driver polling (handled outside ISR).
static NET_DRIVER_POLL_FALLBACK_PENDING: AtomicBool = AtomicBool::new(false);

// Build and publish once on the BSP. APs only load the immutable table; no
// processor can observe or rewrite a partially configured descriptor table.
static IDT: exorust_sync::InitOnce<InterruptDescriptorTable> = exorust_sync::InitOnce::new();

#[inline]
fn record_interrupt_frame(vector: u8, stack_frame: &InterruptStackFrame) {
    if let Some(current_cpu) = crate::cpu::CurrentCpu::acquire() {
        current_cpu.record_interrupt(crate::cpu::InterruptContext {
            vector,
            instruction_pointer: stack_frame.instruction_pointer.as_u64(),
            stack_pointer: stack_frame.stack_pointer.as_u64(),
        });
    }
}

pub fn last_interrupt_vector(cpu_id: crate::cpu::CpuId) -> Option<u8> {
    last_interrupt_context(cpu_id).map(|context| context.vector)
}

pub fn last_interrupt_context(cpu_id: crate::cpu::CpuId) -> Option<crate::cpu::InterruptContext> {
    crate::cpu::try_runtime()?
        .cpu_local(cpu_id)?
        .remote()
        .last_interrupt_context()
}

/// ハードウェア割り込みのベースオフセット
pub const PIC1_OFFSET: u8 = 32;
pub const PIC2_OFFSET: u8 = 40;
pub const APIC_TIMER_VECTOR: u8 = 0xEF;
pub const EXECUTOR_WAKE_VECTOR: u8 = 0xF0;

/// 割り込みベクタ番号
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptVector {
    Timer = PIC1_OFFSET,
    Keyboard = PIC1_OFFSET + 1,
    Cascade = PIC1_OFFSET + 2, // PIC2 への接続
    Com2 = PIC1_OFFSET + 3,
    Com1 = PIC1_OFFSET + 4,
    Lpt2 = PIC1_OFFSET + 5,
    Floppy = PIC1_OFFSET + 6,
    Lpt1 = PIC1_OFFSET + 7,
    Rtc = PIC2_OFFSET, // Real Time Clock
    Free1 = PIC2_OFFSET + 1,
    Free2 = PIC2_OFFSET + 2,
    Free3 = PIC2_OFFSET + 3,
    // Mouse (PIC2+4) removed
    Fpu = PIC2_OFFSET + 5,
    PrimaryAta = PIC2_OFFSET + 6,

    SecondaryAta = PIC2_OFFSET + 7,
    /// IOMMU Fault (Vector 0x50 / 80)
    IommuFault = 0x50,
}

/// IDTを初期化する関数
fn build_idt() -> InterruptDescriptorTable {
    let mut idt = InterruptDescriptorTable::new();

    // CPU例外ハンドラの設定
    idt.divide_error.set_handler_fn(handler_to_x86!(
        exceptions::divide_error_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt.debug.set_handler_fn(handler_to_x86!(
        exceptions::debug_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt.breakpoint.set_handler_fn(handler_to_x86!(
        exceptions::breakpoint_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt.invalid_opcode.set_handler_fn(handler_to_x86!(
        exceptions::invalid_opcode_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt.device_not_available.set_handler_fn(handler_to_x86!(
        exceptions::device_not_available_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));

    // 【設計書 8.5.2】Double Fault ハンドラには IST を使用し、専用スタックを確保
    let double_fault_handler = handler_to_x86!(
        exceptions::double_fault_handler
            as extern "x86-interrupt" fn(InterruptStackFrame, u64) -> !
    );
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }

    idt.general_protection_fault.set_handler_fn(handler_to_x86!(
        exceptions::general_protection_fault_handler
            as extern "x86-interrupt" fn(InterruptStackFrame, u64)
    ));
    let page_fault_handler = handler_to_x86!(
        exceptions::page_fault_handler
            as extern "x86-interrupt" fn(
                InterruptStackFrame,
                x86_64::structures::idt::PageFaultErrorCode,
            )
    );
    unsafe {
        idt.page_fault
            .set_handler_fn(page_fault_handler)
            .set_stack_index(gdt::PAGE_FAULT_IST_INDEX);
    }
    idt.alignment_check.set_handler_fn(handler_to_x86!(
        exceptions::alignment_check_handler as extern "x86-interrupt" fn(InterruptStackFrame, u64)
    ));
    idt.machine_check.set_handler_fn(handler_to_x86!(
        exceptions::machine_check_handler as extern "x86-interrupt" fn(InterruptStackFrame) -> !
    ));
    idt.simd_floating_point.set_handler_fn(handler_to_x86!(
        exceptions::simd_floating_point_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));

    // ハードウェア割り込みハンド設定
    idt[InterruptVector::Timer as u8].set_handler_fn(handler_to_x86!(
        timer_interrupt_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    #[cfg(target_os = "none")]
    unsafe {
        // The entry saves the interrupted task's GPR and xstate before Rust
        // runs, then returns through IRET or the CPU-owned scheduler stack.
        idt[APIC_TIMER_VECTOR].set_handler_addr(x86_64::VirtAddr::new(
            rany_apic_timer_entry as *const () as u64,
        ));
    }
    #[cfg(not(target_os = "none"))]
    idt[APIC_TIMER_VECTOR].set_handler_fn(handler_to_x86!(
        apic_timer_interrupt_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[InterruptVector::Keyboard as u8].set_handler_fn(handler_to_x86!(
        keyboard_interrupt_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[InterruptVector::Com1 as u8].set_handler_fn(handler_to_x86!(
        com1_interrupt_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));

    // IOMMU Fault Handler
    idt[InterruptVector::IommuFault as u8].set_handler_fn(handler_to_x86!(
        iommu_fault_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));

    // NVMe Interrupt (Direct Callback)
    idt[crate::io::interrupt_manager::NVME_VECTOR as u8].set_handler_fn(handler_to_x86!(
        crate::io::interrupt_manager::nvme_entry_point
            as extern "x86-interrupt" fn(InterruptStackFrame)
    ));

    // External-device shared range handlers (0x60..=0x6F)
    idt[0x60].set_handler_fn(handler_to_x86!(
        external_vector_0x60_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x61].set_handler_fn(handler_to_x86!(
        external_vector_0x61_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x62].set_handler_fn(handler_to_x86!(
        external_vector_0x62_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x63].set_handler_fn(handler_to_x86!(
        external_vector_0x63_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x64].set_handler_fn(handler_to_x86!(
        external_vector_0x64_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x65].set_handler_fn(handler_to_x86!(
        external_vector_0x65_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x66].set_handler_fn(handler_to_x86!(
        external_vector_0x66_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x67].set_handler_fn(handler_to_x86!(
        external_vector_0x67_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x68].set_handler_fn(handler_to_x86!(
        external_vector_0x68_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x69].set_handler_fn(handler_to_x86!(
        external_vector_0x69_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x6A].set_handler_fn(handler_to_x86!(
        external_vector_0x6a_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x6B].set_handler_fn(handler_to_x86!(
        external_vector_0x6b_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x6C].set_handler_fn(handler_to_x86!(
        external_vector_0x6c_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x6D].set_handler_fn(handler_to_x86!(
        external_vector_0x6d_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x6E].set_handler_fn(handler_to_x86!(
        external_vector_0x6e_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));
    idt[0x6F].set_handler_fn(handler_to_x86!(
        external_vector_0x6f_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));

    // PIC2 の IRQ ハンドラ（動的デバイス用）
    // IRQ 9, 10, 11 は多くの PCI デバイスで使用される
    idt[PIC2_OFFSET + 1].set_handler_fn(handler_to_x86!(
        pci_irq9_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    )); // IRQ9 (Free1)
    idt[PIC2_OFFSET + 2].set_handler_fn(handler_to_x86!(
        pci_irq10_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    )); // IRQ10 (Free2)
    idt[PIC2_OFFSET + 3].set_handler_fn(handler_to_x86!(
        pci_irq11_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    )); // IRQ11 (Free3)
    // Mouse interrupt handler removed

    // TLB Flush IPI Vector (0xF1 = 241)
    // マルチコア環境でのTLBシュートダウンに使用
    unsafe {
        idt[crate::mm::sync::tlb::TLB_FLUSH_VECTOR]
            .set_handler_fn(handler_to_x86!(
                tlb_flush_ipi_handler as extern "x86-interrupt" fn(InterruptStackFrame)
            ))
            .set_stack_index(gdt::SMP_IPI_IST_INDEX);
    }

    // Executor Wake IPI Vector (0xF0)
    // Idle worker CPUs are woken with a lightweight EOI-only interrupt.
    unsafe {
        idt[EXECUTOR_WAKE_VECTOR]
            .set_handler_fn(handler_to_x86!(
                executor_wake_ipi_handler as extern "x86-interrupt" fn(InterruptStackFrame)
            ))
            .set_stack_index(gdt::SMP_IPI_IST_INDEX);
    }

    // Spurious Interrupt Vector (0xFF)
    // APICによって生成される偽の割り込みを処理
    // OSクラッシュ（#GP/#DF）を防ぐために必須
    idt[0xFF].set_handler_fn(handler_to_x86!(
        spurious_interrupt_handler as extern "x86-interrupt" fn(InterruptStackFrame)
    ));

    idt
}

pub fn load_idt_for_current_cpu() -> Result<(), &'static str> {
    IDT.get().ok_or("IDT not initialized")?.load();
    Ok(())
}

pub fn load_for_current_cpu() -> Result<(), &'static str> {
    gdt::load_for_current_cpu()?;
    load_idt_for_current_cpu()
}

// ============================================================================
// 割り込みシステムの初期化
// ============================================================================

/// 割り込みシステム全体の初期化
///
/// 呼び出し順序:
/// 1. GDT/TSSの初期化（ISTスタックの設定）
/// 2. PICの初期化
/// 3. IDTのロード
pub fn init() {
    // 1. GDT と TSS の初期化
    gdt::init_gdt();

    // 2. PIC の初期化（ハードウェア割り込みのリマップ）
    init_pic();

    // 3. IDT のロード
    IDT.call_once(build_idt).load();
}

/// 割り込みを有効化
///
/// # Safety
/// IDT が初期化されていないと未定義動作
pub fn enable_interrupts() {
    load_idt_for_current_cpu().unwrap_or_else(|error| panic!("cannot enable interrupts: {error}"));
    // actually enable
    x86_64::instructions::interrupts::enable();

    // Serial TX kick is global housekeeping and only needs to run on the BSP.
    // Avoid touching COM1 TX interrupt state from AP worker bring-up paths.
    if crate::cpu::CurrentCpu::acquire()
        .is_some_and(|current_cpu| current_cpu.id() == crate::cpu::CpuId::BOOTSTRAP)
    {
        crate::io::log::start_serial_tx();
    }
}

/// 割り込みを無効化
pub fn disable_interrupts() {
    x86_64::instructions::interrupts::disable();
}

/// 割り込みが有効かどうか
pub fn are_interrupts_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

/// 割り込みを無効にしてクロージャを実行
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    x86_64::instructions::interrupts::without_interrupts(f)
}

// ============================================================================
// Bootstrap PIC routing and legacy-device acknowledgement
// ============================================================================
// This platform owner reserves both PIC register pairs and the delay port.
// One IRQ-safe guard serializes initialization, mask RMW and acknowledgement;
// interrupt handlers cannot interrupt a task while it holds this protocol.
static PIC_PORTS: crate::sync::IrqPoisonLock<[hal::IoPortRange; 5]> = {
    // SAFETY: fixed platform PIC resources are retained here and all accesses
    // to them go through this owner. Construction performs no port I/O.
    let master_command = unsafe { hal::IoPortRange::single(0x20) };
    // SAFETY: the master PIC data register belongs to the same platform owner.
    let master_data = unsafe { hal::IoPortRange::single(0x21) };
    // SAFETY: the slave PIC command register belongs to the same platform owner.
    let slave_command = unsafe { hal::IoPortRange::single(0xa0) };
    // SAFETY: the slave PIC data register belongs to the same platform owner.
    let slave_data = unsafe { hal::IoPortRange::single(0xa1) };
    // SAFETY: this platform owner reserves the traditional I/O delay port.
    let delay = unsafe { hal::IoPortRange::single(0x80) };
    crate::sync::IrqPoisonLock::new([
        master_command,
        master_data,
        slave_command,
        slave_data,
        delay,
    ])
};

/// ICW1: 初期化コマンド
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
/// ICW4: 8086モード
const ICW4_8086: u8 = 0x01;

/// Remaps bootstrap IRQs. Timer IRQ0 is masked after local timer handoff;
/// keyboard and serial routing remain available for legacy devices.
fn init_pic() {
    let ports = PIC_PORTS.lock().unwrap_or_else(|error| error.into_inner());
    let [
        master_command,
        master_data,
        slave_command,
        slave_data,
        delay,
    ] = &*ports;
    let mut master_command = master_command.first::<u8>().expect("one-byte PIC port");
    let mut master_data = master_data.first::<u8>().expect("one-byte PIC port");
    let mut slave_command = slave_command.first::<u8>().expect("one-byte PIC port");
    let mut slave_data = slave_data.first::<u8>().expect("one-byte PIC port");
    let mut delay = delay.first::<u8>().expect("one-byte delay port");
    master_command.write(ICW1_INIT | ICW1_ICW4);
    delay.write(0);
    slave_command.write(ICW1_INIT | ICW1_ICW4);
    delay.write(0);
    for (master, slave) in [(PIC1_OFFSET, PIC2_OFFSET), (4, 2), (ICW4_8086, ICW4_8086)] {
        master_data.write(master);
        delay.write(0);
        slave_data.write(slave);
        delay.write(0);
    }
    master_data.write(0xe8);
    // PCI completion is deferred; legacy shared INTx lines stay masked.
    slave_data.write(0xff);
}

/// Called after handling a legacy IRQ, including LAPIC virtual-wire delivery.
fn acknowledge_legacy_irq(irq: u8) {
    {
        let ports = PIC_PORTS.lock().unwrap_or_else(|error| error.into_inner());
        if irq >= 8 {
            ports[2]
                .first::<u8>()
                .expect("one-byte PIC port")
                .write(0x20);
        }
        ports[0]
            .first::<u8>()
            .expect("one-byte PIC port")
            .write(0x20);
    }
    match crate::drivers::apic::local_apic() {
        Ok(apic) => apic.send_eoi(),
        // Early boot may use the legacy PIC before LAPIC selection.
        Err(crate::drivers::apic::LocalApicError::NotSelected) => {}
        Err(cause) => panic!("legacy IRQ acknowledgement has no LAPIC backend: {cause}"),
    }
}

fn mask_legacy_timer() {
    let ports = PIC_PORTS.lock().unwrap_or_else(|error| error.into_inner());
    let mut master_data = ports[1].first::<u8>().expect("one-byte PIC port");
    let mask = master_data.read();
    master_data.write(mask | 1);
}

#[cfg(any(test, feature = "qemu-test-export"))]
fn read_pic_irq_masked(irq: u8) -> bool {
    let ports = PIC_PORTS.lock().unwrap_or_else(|error| error.into_inner());
    let (index, bit) = if irq < 8 { (1, irq) } else { (3, irq - 8) };
    (ports[index]
        .first::<u8>()
        .expect("one-byte PIC port")
        .read()
        & (1 << bit))
        != 0
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn pit_irq0_masked() -> bool {
    read_pic_irq_masked(0)
}

// ============================================================================
// Hardware Interrupt Handlers
// ============================================================================

use x86_64::structures::idt::InterruptStackFrame;

/// タイマー割り込みカウンタ
pub static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);
static RUNTIME_LOCAL_TIMERS_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTimerError {
    RuntimeModeDisabled,
    CpuLocalUnavailable,
    CalibrationRequiresBootstrapCpu,
    LocalApicDisabled,
    LocalApic(crate::drivers::apic::LocalApicError),
}

#[inline]
fn is_global_timekeeping_cpu(cpu_id: crate::cpu::CpuId) -> bool {
    cpu_id == crate::cpu::CpuId::BOOTSTRAP
}

pub fn runtime_local_timers_enabled() -> bool {
    RUNTIME_LOCAL_TIMERS_ENABLED.load(Ordering::Acquire)
}

fn ensure_runtime_timer_calibrated() -> Result<(), RuntimeTimerError> {
    let current_cpu =
        crate::cpu::CurrentCpu::acquire().ok_or(RuntimeTimerError::CpuLocalUnavailable)?;
    if current_cpu.id() != crate::cpu::CpuId::BOOTSTRAP {
        return Err(RuntimeTimerError::CalibrationRequiresBootstrapCpu);
    }
    let apic = crate::drivers::apic::local_apic().map_err(RuntimeTimerError::LocalApic)?;
    if apic.ticks_per_ms() == 0 {
        crate::time::calibrate_apic_timer(apic).map_err(RuntimeTimerError::LocalApic)?;
    }
    Ok(())
}

/// Calibrates the shared local-APIC timer rate before application CPUs start.
///
/// The PIT channel used as the reference clock is global, so calibration is
/// owned by the bootstrap CPU and published before any application CPU is
/// admitted to `Online`.
///
/// # Errors
///
/// Returns a typed error when the executing CPU is not the bootstrap CPU or
/// the local APIC timer cannot be calibrated against the PIT reference.
pub(crate) fn prepare_runtime_local_timer_source() -> Result<(), RuntimeTimerError> {
    ensure_runtime_timer_calibrated()
}

fn arm_current_runtime_timer() -> Result<(), RuntimeTimerError> {
    let apic = crate::drivers::apic::local_apic().map_err(RuntimeTimerError::LocalApic)?;
    if !apic.is_enabled() {
        return Err(RuntimeTimerError::LocalApicDisabled);
    }
    let current_cpu =
        crate::cpu::CurrentCpu::acquire().ok_or(RuntimeTimerError::CpuLocalUnavailable)?;
    if current_cpu.arm_runtime_timer_once() {
        if let Err(error) = crate::drivers::apic::start_apic_timer_on_vector(APIC_TIMER_VECTOR, 1) {
            current_cpu.disarm_runtime_timer();
            return Err(RuntimeTimerError::LocalApic(error));
        }
    }
    Ok(())
}

pub(crate) fn prepare_current_cpu_runtime_timer() -> Result<(), RuntimeTimerError> {
    arm_current_runtime_timer()
}

pub(crate) fn stop_current_cpu_runtime_timer() -> Result<(), RuntimeTimerError> {
    let apic = crate::drivers::apic::local_apic().map_err(RuntimeTimerError::LocalApic)?;
    let current_cpu =
        crate::cpu::CurrentCpu::acquire().ok_or(RuntimeTimerError::CpuLocalUnavailable)?;
    apic.stop_timer();
    current_cpu.disarm_runtime_timer();
    Ok(())
}

pub(crate) fn retire_current_cpu_timer_event() -> bool {
    let current_cpu = crate::cpu::CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("timer-event retirement requires CPU-local state"));
    assert!(
        !current_cpu.runtime_timer_armed(),
        "timer event retired while the local runtime timer remained armed"
    );
    current_cpu.take_timer_event()
}

/// Arms the periodic local APIC timer on the executing CPU once.
///
/// # Errors
///
/// Returns a typed error when runtime timer mode is inactive, CPU-local state
/// is unavailable, or the selected APIC backend cannot start its timer.
pub fn ensure_runtime_local_timer_started() -> Result<(), RuntimeTimerError> {
    if !runtime_local_timers_enabled() {
        return Err(RuntimeTimerError::RuntimeModeDisabled);
    }
    arm_current_runtime_timer()
}

/// Commits the bootstrap CPU from the PIT to periodic local APIC timers.
///
/// # Errors
///
/// Returns a typed error when the local APIC is disabled, CPU-local state is
/// unavailable, or the timer cannot be armed. The PIT remains unmasked when
/// the transition fails.
pub fn transition_to_runtime_local_timers() -> Result<(), RuntimeTimerError> {
    ensure_runtime_timer_calibrated()?;
    arm_current_runtime_timer()?;
    RUNTIME_LOCAL_TIMERS_ENABLED.store(true, Ordering::Release);
    mask_legacy_timer();
    Ok(())
}

/// - Wakerを起床させるだけ
// タイマー割り込みハンドラ
//
// 仕様書 4.2: プリエンプション制御との統合
// 設計書 4.2: ISR内では重い処理を行わない。単にタスクをReady状態にするだけ。
// - タイマーティックの管理
// - フラグ設定のみで重い処理は遅延
// - Wakerを起床させるだけ
// simple counter for timer debug logging
static TIMER_LOGGED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[inline]
fn handle_timer_interrupt_common() {
    // log first tick to confirm handler firing
    if !TIMER_LOGGED.swap(true, core::sync::atomic::Ordering::Relaxed) {
        // use early_print to avoid acquiring the logger lock inside ISR
        crate::io::log::early_print("[INT] timer interrupt handler entered\n");
    }

    let Some(current_cpu) = crate::cpu::CurrentCpu::acquire() else {
        crate::io::log::early_print("[INT] ERROR: timer interrupt without CPU-local state\n");
        return;
    };
    let is_global_tick_cpu = is_global_timekeeping_cpu(current_cpu.id());

    // Global timekeeping advances on the bootstrap CPU only.
    let global_tick = if is_global_tick_cpu {
        let tick = TIMER_TICKS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let tick_nanos = crate::time::timer_tick_nanos();
        if tick_nanos != 0 {
            crate::time::tick(tick_nanos);
        }
        crate::drivers::time::handle_timer_interrupt();
        tick
    } else {
        TIMER_TICKS.load(Ordering::Relaxed)
    };

    current_cpu.request_timer_event();

    // Wake the deferred timer path without doing executor work in the ISR.
    if is_global_tick_cpu {
        crate::io::interrupt_manager::push_interrupt_event(InterruptVector::Timer as u8);
    }

    // IRQが届かない環境向けのcompletionフォールバック:
    if is_global_tick_cpu
        && (global_tick & 0x3) == 0
        && NET_DRIVER_POLL_FALLBACK_ENABLED.load(Ordering::Acquire)
    {
        NET_DRIVER_POLL_FALLBACK_PENDING.store(true, Ordering::Release);
    }
}

define_interrupt!(
    fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
        record_interrupt_frame(InterruptVector::Timer as u8, &_stack_frame);
        handle_timer_interrupt_common();
        acknowledge_legacy_irq(InterruptVector::Timer as u8 - PIC1_OFFSET);
    }
);

define_interrupt!(
    fn apic_timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
        record_interrupt_frame(APIC_TIMER_VECTOR, &_stack_frame);
        handle_timer_interrupt_common();
        crate::io::interrupt_manager::send_eoi();
    }
);

#[cfg(target_os = "none")]
#[repr(C)]
struct HardwareInterruptFrame {
    rip: u64,
    _cs: u64,
    _rflags: u64,
    rsp: u64,
    _ss: u64,
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn rany_apic_timer_entry();
}

/// Returns the active task context only after the handler, EOI, and interrupt
/// ownership guard have all completed. The assembly entry then switches back
/// to the scheduler stack; no Future or queue is touched in interrupt context.
#[cfg(target_os = "none")]
extern "C" fn apic_timer_dispatch(frame: *const HardwareInterruptFrame) -> usize {
    let Some(current) = crate::cpu::CurrentCpu::acquire() else {
        handle_timer_interrupt_common();
        crate::io::interrupt_manager::send_eoi();
        return 0;
    };
    {
        let frame = unsafe { &*frame };
        current.record_interrupt(crate::cpu::InterruptContext {
            vector: APIC_TIMER_VECTOR,
            instruction_pointer: frame.rip,
            stack_pointer: frame.rsp,
        });
        let _interrupt = current.enter_interrupt();
        handle_timer_interrupt_common();
        crate::io::interrupt_manager::send_eoi();
    }
    let current = crate::cpu::CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("timer interrupt lost CPU binding"));
    let state = current.preemption_state();
    let quantum_ticks = (crate::task::config::SCHEDULER_CONFIG.quantum_ns / 1_000_000) as u32;
    if state.timer_tick(quantum_ticks.max(1)) {
        return state.active_context();
    }
    0
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .global rany_apic_timer_entry
    rany_apic_timer_entry:
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        mov r11, gs:[{active_context}]
        test r11, r11
        jz 40f
        add r11, {task_xstate}
        jmp 41f
    40:
        mov r11, gs:[{scheduler_xstate}]
    41:
        mov r10, gs:[{xstate_mask}]
        test r10, r10
        jz 42f
        mov eax, r10d
        shr r10, 32
        mov edx, r10d
        xsave64 [r11]
        jmp 43f
    42:
        fxsave64 [r11]
    43:
        cld
        lea rdi, [rsp + 120]
        call {dispatch}
        mov r12, rax
        test r12, r12
        jz 50f
        mov [r12 + {interrupted_rsp}], rsp
        mov r11, gs:[{scheduler_xstate}]
        jmp 51f
    50:
        mov r11, gs:[{active_context}]
        test r11, r11
        jz 52f
        add r11, {task_xstate}
        jmp 51f
    52:
        mov r11, gs:[{scheduler_xstate}]
    51:
        mov r10, gs:[{xstate_mask}]
        test r10, r10
        jz 53f
        mov eax, r10d
        shr r10, 32
        mov edx, r10d
        xrstor64 [r11]
        jmp 54f
    53:
        fxrstor64 [r11]
    54:
        test r12, r12
        jz 55f
        mov rsp, [r12 + {scheduler_rsp}]
        mov eax, 1
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        ret
    55:
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        iretq
    "#,
    active_context = const hal::preemption::ACTIVE_CONTEXT_OFFSET,
    scheduler_xstate = const hal::preemption::SCHEDULER_XSTATE_OFFSET,
    xstate_mask = const hal::preemption::XSTATE_MASK_OFFSET,
    task_xstate = const crate::task::context::XSTATE_OFFSET,
    interrupted_rsp = const crate::task::context::INTERRUPTED_RSP_OFFSET,
    scheduler_rsp = const crate::task::context::SCHEDULER_RSP_OFFSET,
    dispatch = sym apic_timer_dispatch,
);

/// タイマーイベントをポーリング（非ISRコンテキストから呼び出し）
///
/// 設計書 4.2: 重い処理は非ISRコンテキストで実行
pub fn poll_timer_events() {
    let Some(current_cpu) = crate::cpu::CurrentCpu::acquire() else {
        return;
    };
    if !current_cpu.take_timer_event() {
        return;
    }

    if is_global_timekeeping_cpu(current_cpu.id()) {
        // Interrupt-Wakerブリッジの処理
        crate::task::interrupt_waker::handle_timer_interrupt_waker();

        // Deferred network driver completion fallback (non-ISR context).
        // Queue a generic poll event for each registered port so the
        // executor-side worker drains queues outside interrupt context.
        if NET_DRIVER_POLL_FALLBACK_ENABLED.load(Ordering::Acquire)
            && NET_DRIVER_POLL_FALLBACK_PENDING.swap(false, Ordering::AcqRel)
        {
            let runtime = crate::net::runtime::default_runtime();
            for port_id in crate::net::runtime::device::list_port_ids_in(runtime) {
                let _ = crate::net::runtime::device::enqueue_event_in(
                    runtime,
                    port_id,
                    kernel_api::service::netdev::NetDriverEvent::Poll,
                );
            }
        }
    }
}

// キーボード割り込みハンドラ
// Interrupt-Wakerブリッジとの連携
define_interrupt!(
    fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
        // Feed scancodes into the async KeyboardStream driver used by ConsoleFrontend.
        crate::drivers::hid::keyboard::keyboard_interrupt_handler();

        // Interrupt-Wakerブリッジにキーボード割り込みを通知（設計書 4.2）
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::Keyboard,
        );

        // Interrupt-Waker Bridge（設計書 4.2: 2段階Wake方式）
        crate::io::interrupt_manager::push_interrupt_event(InterruptVector::Keyboard as u8);

        // EOI を送信
        acknowledge_legacy_irq(InterruptVector::Keyboard as u8 - PIC1_OFFSET);
    }
);

// COM1 (Serial) 割り込みハンドラ
// シリアルポートからのデータ受信時に呼ばれる
define_interrupt!(
    fn com1_interrupt_handler(_stack_frame: InterruptStackFrame) {
        record_interrupt_frame(InterruptVector::Com1 as u8, &_stack_frame);
        crate::io::log::handle_serial_interrupt();

        // Interrupt-Wakerブリッジに通知
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::Serial,
        );

        // Interrupt-Waker Bridge（設計書 4.2: 2段階Wake方式）
        crate::io::interrupt_manager::push_interrupt_event(InterruptVector::Com1 as u8);

        // EOI を送信 (IRQ4 = COM1)
        acknowledge_legacy_irq(InterruptVector::Com1 as u8 - PIC1_OFFSET);
    }
);

// IOMMU Fault Handler
//
// Handles faults reported by the IOMMU (DMA remapping errors, etc.)
// Also wakes any pending async invalidation waiters.
define_interrupt!(
    fn iommu_fault_handler(_stack_frame: InterruptStackFrame) {
        // Intel VT-d uses the same vector (0x50) for faults and QI completion.
        // Actual fault details are logged by the fault_handler_task drain.
        // Process faults (reads fault recording registers if PPF is set)
        crate::io::iommu::api::handle_fault();

        // Wake any pending async invalidation waiters
        // Intel VT-d uses the same interrupt for both faults and invalidation completion
        crate::io::iommu::api::wake_invalidation_waiters();

        // Send EOI to Local APIC (IOMMU uses MSI/APIC delivery)
        // We use the unified interrupt manager's EOI helper which targets LAPIC
        crate::io::interrupt_manager::send_eoi();
    }
);

#[inline]
fn handle_external_vector(vector: u8) {
    crate::task::interrupt_waker::wake_from_interrupt(
        crate::task::interrupt_waker::InterruptSource::Irq(vector),
    );
    if !crate::io::interrupt_manager::try_dispatch_direct(vector) {
        crate::io::interrupt_manager::push_interrupt_event(vector);
    }
    crate::io::interrupt_manager::send_eoi();
}

macro_rules! define_external_vector_handler {
    ($name:ident, $vector:expr) => {
        define_interrupt!(
            fn $name(_stack_frame: InterruptStackFrame) {
                handle_external_vector($vector);
            }
        );
    };
}

define_external_vector_handler!(external_vector_0x60_handler, 0x60);
define_external_vector_handler!(external_vector_0x61_handler, 0x61);
define_external_vector_handler!(external_vector_0x62_handler, 0x62);
define_external_vector_handler!(external_vector_0x63_handler, 0x63);
define_external_vector_handler!(external_vector_0x64_handler, 0x64);
define_external_vector_handler!(external_vector_0x65_handler, 0x65);
define_external_vector_handler!(external_vector_0x66_handler, 0x66);
define_external_vector_handler!(external_vector_0x67_handler, 0x67);
define_external_vector_handler!(external_vector_0x68_handler, 0x68);
define_external_vector_handler!(external_vector_0x69_handler, 0x69);
define_external_vector_handler!(external_vector_0x6a_handler, 0x6A);
define_external_vector_handler!(external_vector_0x6b_handler, 0x6B);
define_external_vector_handler!(external_vector_0x6c_handler, 0x6C);
define_external_vector_handler!(external_vector_0x6d_handler, 0x6D);
define_external_vector_handler!(external_vector_0x6e_handler, 0x6E);
define_external_vector_handler!(external_vector_0x6f_handler, 0x6F);

// ============================================================================
// PCI IRQ Handlers (IRQ 9, 10, 11)
// ============================================================================

// IRQ 9 ハンドラ (PCI デバイス用)
define_interrupt!(
    fn pci_irq9_handler(_stack_frame: InterruptStackFrame) {
        dispatch_pci_interrupt(9);
        acknowledge_legacy_irq(9);
    }
);

// IRQ 10 ハンドラ (PCI デバイス用)
define_interrupt!(
    fn pci_irq10_handler(_stack_frame: InterruptStackFrame) {
        dispatch_pci_interrupt(10);
        acknowledge_legacy_irq(10);
    }
);

// IRQ 11 ハンドラ (PCI デバイス用)
define_interrupt!(
    fn pci_irq11_handler(_stack_frame: InterruptStackFrame) {
        dispatch_pci_interrupt(11);
        acknowledge_legacy_irq(11);
    }
);

// TLB Flush IPI Handler (0xF1 = 241)
// マルチコア環境でのTLBシュートダウン用割り込みハンドラ
// 他CPUからのTLBフラッシュ要求を処理
define_interrupt!(
    fn executor_wake_ipi_handler(_stack_frame: InterruptStackFrame) {
        record_interrupt_frame(EXECUTOR_WAKE_VECTOR, &_stack_frame);
        crate::io::interrupt_manager::send_eoi();
    }
);

define_interrupt!(
    fn tlb_flush_ipi_handler(_stack_frame: InterruptStackFrame) {
        record_interrupt_frame(crate::mm::sync::tlb::TLB_FLUSH_VECTOR, &_stack_frame);
        // TLBフラッシュ処理を実行
        // Safety: 割り込みハンドラとして呼び出されている
        unsafe {
            crate::mm::sync::tlb::handle_shootdown_ipi();
        }

        // Local APICにEOIを送信
        // IPIはLocal APICから来るのでLocal APICにEOIを送る
        crate::io::interrupt_manager::send_eoi();
    }
);

// Spurious Interrupt Handler (0xFF)
// APICノイズによる偽の割り込みを処理
// 何もせず単にリターンする（EOIも送らないのが一般的だが、ISR上はiretが必要）
// For debug we log the *first* occurrence.
static SPURIOUS_LOGGED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
define_interrupt!(
    fn spurious_interrupt_handler(_stack_frame: InterruptStackFrame) {
        record_interrupt_frame(0xFF, &_stack_frame);
        if !SPURIOUS_LOGGED.swap(true, core::sync::atomic::Ordering::Relaxed) {
            // log once to avoid flooding
            crate::io::log::early_print("[INT] spurious interrupt received\n");
        }
        // 偽割り込みに対してはEOIを送らないのがIntel仕様での推奨
        // (ただし、Local APICのSIVRのビット8がクリアされている場合などは挙動が異なるが、
        // ここではSoft Enableされている前提)
        // ログも出さない（頻発すると遅くなるため）
    }
);

/// PCI 割り込みをディスパッチ
///
/// 同じ IRQ を共有する可能性のある複数のデバイスをチェックする
fn dispatch_pci_interrupt(irq: u8) {
    let vector = PIC1_OFFSET + irq;
    if crate::io::interrupt_manager::try_dispatch_direct(vector) {
        return;
    }
    // Shared PCI driver work is deferred to non-ISR context to avoid lock inversion
    // with driver paths that may hold allocator/device locks while interrupts fire.
    dispatch_shared_pci_handlers();

    // 将来的には他の PCI デバイスもここに追加
    // 例: NVMe, ネットワークカードなど
}

/// 共有PCIデバイス割り込み処理
pub fn dispatch_shared_pci_handlers() {
    // Keep ISR path lock-free and defer shared driver work.
    NET_DRIVER_POLL_FALLBACK_PENDING.store(true, Ordering::Release);
}

/// Enable timer-driven network driver interrupt fallback processing.
pub fn enable_net_driver_poll_fallback() {
    NET_DRIVER_POLL_FALLBACK_ENABLED.store(true, Ordering::Release);
}

/// 現在のタイマーティック数を取得
pub fn get_timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::SeqCst)
}

// ============================================================================
// テスト用ヘルパー
// ============================================================================

/// ブレークポイントをトリガー（デバッグ用）
pub fn trigger_breakpoint() {
    x86_64::instructions::interrupts::int3();
}

/// 割り込みシステムの状態をダンプ
pub fn dump_interrupt_state() {
    log::info!("[INT] === Interrupt System State ===\n");
    log::info!("  IDT Initialized: {}\n", IDT.get().is_some());
    log::info!("  Interrupts Enabled: {}\n", are_interrupts_enabled());
    log::info!("  Timer Ticks: {}\n", get_timer_ticks());

    let (pf, gpf, df, bp, ud, de) = exceptions::get_exception_stats();
    log::info!("  Exception Stats:\n");
    log::info!("    Page Faults: {}\n", pf);
    log::info!("    GP Faults: {}\n", gpf);
    log::info!("    Double Faults: {}\n", df);
    log::info!("    Breakpoints: {}\n", bp);
    log::info!("    Invalid Opcodes: {}\n", ud);
    log::info!("    Divide Errors: {}\n", de);
}
