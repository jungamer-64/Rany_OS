#![allow(unused_doc_comments)]
// ============================================================================
// src/interrupts/mod.rs - 割り込みシステム統合モジュール
//
// GDT, IDT, 例外ハンドラ、ハードウェア割り込みを統合管理
// ============================================================================
#![allow(dead_code)]

pub mod exceptions;
pub mod gdt;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
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

/// IDT初期化完了フラグ
static IDT_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// IDTコンテナ（Sync実装のため）
struct IdtContainer(UnsafeCell<MaybeUninit<InterruptDescriptorTable>>);
unsafe impl Sync for IdtContainer {}

static IDT_CONTAINER: IdtContainer = IdtContainer(UnsafeCell::new(MaybeUninit::uninit()));

/// ハードウェア割り込みのベースオフセット
pub const PIC1_OFFSET: u8 = 32;
pub const PIC2_OFFSET: u8 = 40;

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
    Mouse = PIC2_OFFSET + 4,
    Fpu = PIC2_OFFSET + 5,
    PrimaryAta = PIC2_OFFSET + 6,

    SecondaryAta = PIC2_OFFSET + 7,
    /// IOMMU Fault (Vector 0x50 / 80)
    IommuFault = 0x50,
}

/// IDTを初期化する関数
fn init_idt() {
    crate::io::log::early_print("[IDT] init\n");

    let idt = unsafe {
        let idt_ptr = (*IDT_CONTAINER.0.get()).as_mut_ptr();

        // IDTをゼロクリア（大きなstructなので慎重に）
        crate::io::log::early_print("[IDT] zero start\n");
        let idt_bytes = idt_ptr as *mut u8;
        let idt_size = core::mem::size_of::<InterruptDescriptorTable>();
        // 小さなチャンクで初期化
        for i in 0..idt_size {
            crate::io::mmio::volatile_write::<u8>(idt_bytes.add(i) as usize, 0);
        }
        crate::io::log::early_print("[IDT] zeroed\n");

        // IDTはすでにゼロ初期化されているので、ハンドラだけ設定
        // InterruptDescriptorTable::new()を呼ばずに直接設定
        &mut *(idt_ptr as *mut InterruptDescriptorTable)
    };

        crate::io::log::early_print("[IDT] handlers\n");

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
            exceptions::device_not_available_handler
                as extern "x86-interrupt" fn(InterruptStackFrame)
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
        idt.page_fault.set_handler_fn(handler_to_x86!(
            exceptions::page_fault_handler
                as extern "x86-interrupt" fn(
                    InterruptStackFrame,
                    x86_64::structures::idt::PageFaultErrorCode,
                )
        ));
        idt.alignment_check.set_handler_fn(handler_to_x86!(
            exceptions::alignment_check_handler
                as extern "x86-interrupt" fn(InterruptStackFrame, u64)
        ));
        idt.machine_check.set_handler_fn(handler_to_x86!(
            exceptions::machine_check_handler
                as extern "x86-interrupt" fn(InterruptStackFrame) -> !
        ));
        idt.simd_floating_point.set_handler_fn(handler_to_x86!(
            exceptions::simd_floating_point_handler
                as extern "x86-interrupt" fn(InterruptStackFrame)
        ));

        crate::io::log::early_print("[IDT] hw int\n");

        // ハードウェア割り込みハンド設定
        idt[InterruptVector::Timer as u8].set_handler_fn(handler_to_x86!(
            timer_interrupt_handler as extern "x86-interrupt" fn(InterruptStackFrame)
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
        idt[InterruptVector::Mouse as u8].set_handler_fn(handler_to_x86!(
            mouse_interrupt_handler as extern "x86-interrupt" fn(InterruptStackFrame)
        )); // IRQ12 (Mouse)

        // TLB Flush IPI Vector (0xF1 = 241)
        // マルチコア環境でのTLBシュートダウンに使用
        idt[crate::mm::tlb_batch::TLB_FLUSH_VECTOR].set_handler_fn(handler_to_x86!(
            tlb_flush_ipi_handler as extern "x86-interrupt" fn(InterruptStackFrame)
        ));

        // Spurious Interrupt Vector (0xFF)
        // APICによって生成される偽の割り込みを処理
        // OSクラッシュ（#GP/#DF）を防ぐために必須
        idt[0xFF].set_handler_fn(handler_to_x86!(
            spurious_interrupt_handler as extern "x86-interrupt" fn(InterruptStackFrame)
        ));

        crate::io::log::early_print("[IDT] load\n");

        // IDTをロード
        idt.load();
        crate::io::log::early_print("[IDT] done\n");

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
    crate::io::log::early_print("[INT] init\n");

    // 1. GDT と TSS の初期化
    gdt::init_gdt();
    crate::io::log::early_print("[INT] GDT done\n");

    // 2. PIC の初期化（ハードウェア割り込みのリマップ）
    crate::io::log::early_print("[INT] PIC\n");
    init_pic();
    crate::io::log::early_print("[INT] PIC done\n");

    // 3. IDT のロード
    crate::io::log::early_print("[INT] IDT init\n");
    init_idt();
    IDT_INITIALIZED.store(true, Ordering::SeqCst);
    crate::io::log::early_print("[INT] ready\n");
}

/// 割り込みを有効化
///
/// # Safety
/// IDT が初期化されていないと未定義動作
pub fn enable_interrupts() {
    if !IDT_INITIALIZED.load(Ordering::SeqCst) {
        panic!("Cannot enable interrupts: IDT not initialized");
    }
    x86_64::instructions::interrupts::enable();
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
// PIC (8259A) 無効化 - APIC専用設計
// ============================================================================
// 設計理念: レガシーPICはモダンx86_64では不要
// - pic8259クレートを削除し、直接I/Oポート操作で無効化
// - 全ての割り込みはAPIC/IO APICで処理
// ============================================================================

// use hal::port_io::PortU8; // previously used x86_64 Port, replaced by crate::io::inb/outb usage

/// PICのI/Oポートアドレス
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// ICW1: 初期化コマンド
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
/// ICW4: 8086モード
const ICW4_8086: u8 = 0x01;

/// PICを完全に無効化（APICモードへ移行）
///
/// これは設計理念に基づく重要な処理：
/// - レガシーPICはシングルコア時代の遺物
/// - 現代のx86_64ではAPIC/MSI-Xを使用すべき
/// - PICは初期化後に全マスクして無効化
fn init_pic() {
    // unsafe block removed based on lint check
    {
        // Intentionally keep creation of Port inside unsafe, but use wrapper functions
        // for the actual read/write operations to minimize scattered unsafe usage.

        // PICの初期化シーケンス（リマップ）
        // これは必要: BIOSがPIC割り込みをCPU例外と衝突する位置に設定するため

        // ICW1: 初期化開始
        crate::io::outb(PIC1_COMMAND, ICW1_INIT | ICW1_ICW4);
        io_wait();
        crate::io::outb(PIC2_COMMAND, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: ベクタオフセット設定（例外との衝突を回避）
        crate::io::outb(PIC1_DATA, PIC1_OFFSET);
        io_wait();
        crate::io::outb(PIC2_DATA, PIC2_OFFSET);
        io_wait();

        // ICW3: カスケード設定
        crate::io::outb(PIC1_DATA, 4); // IRQ2にスレーブ接続
        io_wait();
        crate::io::outb(PIC2_DATA, 2); // カスケードID
        io_wait();

        // ICW4: 8086モード
        crate::io::outb(PIC1_DATA, ICW4_8086);
        io_wait();
        crate::io::outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // 割り込みマスク設定
        // PIC1: IRQ0(timer), IRQ1(keyboard), IRQ2(cascade), IRQ4(COM1) を有効化
        // ビット0=IRQ0, ビット1=IRQ1, ビット2=IRQ2(cascade), ビット4=IRQ4
        // 0=有効, 1=マスク
        // ~(0x01 | 0x02 | 0x04 | 0x10) = 0xE8
        crate::io::outb(PIC1_DATA, 0b11101000); // Timer(0), Keyboard(1), Cascade(2), COM1(4) を有効

        // PIC2: IRQ9, IRQ10, IRQ11, IRQ12 を有効化（PCI デバイス用 + マウス）
        // IRQ8=RTC, IRQ9, IRQ10, IRQ11, IRQ12=Mouse
        // ビット1=IRQ9, ビット2=IRQ10, ビット3=IRQ11, ビット4=IRQ12
        // 0=有効, 1=マスク
        // ~(0x02 | 0x04 | 0x08 | 0x10) = 0xE1
        crate::io::outb(PIC2_DATA, 0b11100001); // IRQ9, IRQ10, IRQ11, IRQ12(Mouse) を有効
    }
}

/// I/O待機（PICは遅いデバイス）
#[inline]
fn io_wait() {
    // unsafe block removed based on lint check
    {
        // 未使用ポートへのI/Oで遅延を発生
        crate::io::outb(0x80, 0);
    }
}

/// EOI送信（タイマー/キーボード用 - APICへの移行までの暫定）
///
/// # Safety
/// 割り込みハンドラ内でのみ呼び出すこと
pub unsafe fn send_eoi(irq: u8) {
    if irq >= 8 {
        crate::io::outb(PIC2_COMMAND, 0x20); // スレーブPICにEOI
    }
    crate::io::outb(PIC1_COMMAND, 0x20); // マスターPICにEOI
}

/// 特定の割り込みをアンマスク（APIC移行までの暫定）
pub fn unmask_irq(irq: u8) {
    // unsafe block removed based on lint check
    {
        if irq < 8 {
            let mask = crate::io::inb(PIC1_DATA);
            crate::io::outb(PIC1_DATA, mask & !(1 << irq));
        } else {
            let mask = crate::io::inb(PIC2_DATA);
            crate::io::outb(PIC2_DATA, mask & !(1 << (irq - 8)));
        }
    }
}

/// 特定の割り込みをマスク
pub fn mask_irq(irq: u8) {
    // unsafe block removed based on lint check
    {
        if irq < 8 {
            let mask = crate::io::inb(PIC1_DATA);
            crate::io::outb(PIC1_DATA, mask | (1 << irq));
        } else {
            let mask = crate::io::inb(PIC2_DATA);
            crate::io::outb(PIC2_DATA, mask | (1 << (irq - 8)));
        }
    }
}

// ============================================================================
// Hardware Interrupt Handlers
// ============================================================================

use core::sync::atomic::AtomicU64;
use x86_64::structures::idt::InterruptStackFrame;

/// タイマー割り込みカウンタ
pub static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// - Wakerを起床させるだけ
// タイマー割り込みハンドラ
//
// 仕様書 4.2: プリエンプション制御との統合
// 設計書 4.2: ISR内では重い処理を行わない。単にタスクをReady状態にするだけ。
// - タイマーティックの管理
// - フラグ設定のみで重い処理は遅延
// - Wakerを起床させるだけ
define_interrupt!(
    fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
        // 1. タイマーティックを増加（Relaxedで十分、順序は重要でない）
        let _tick = TIMER_TICKS.fetch_add(1, Ordering::Relaxed);

        // 2. 軽量なフラグ設定のみ（重い処理は遅延）
        // タイマーイベントペンディングフラグを設定
        TIMER_EVENT_PENDING.store(true, Ordering::Release);

        // 3. プリエンプションカウンタを更新（軽量な操作のみ）
        crate::task::preemption::decrement_time_slice();

        // 4. Wakerを起床させる（軽量）
        crate::task::interrupt_waker::wake_timer_task();

        // 4.5. Interrupt-Waker Bridge（設計書 4.2: 2段階Wake方式）
        crate::io::interrupt_manager::push_interrupt_event(InterruptVector::Timer as u8);

        // 5. EOI (End Of Interrupt) を送信
        unsafe {
            send_eoi(InterruptVector::Timer as u8 - PIC1_OFFSET);
        }

        // 6. プリエンプションフラグのみ設定（実際のyieldは遅延）
        if crate::task::preemption::should_preempt() {
            crate::task::preemption::set_preemption_pending();
        }
    }
);

/// タイマーイベントペンディングフラグ
static TIMER_EVENT_PENDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// タイマーイベントをポーリング（非ISRコンテキストから呼び出し）
///
/// 設計書 4.2: 重い処理は非ISRコンテキストで実行
pub fn poll_timer_events() {
    if TIMER_EVENT_PENDING.swap(false, Ordering::Acquire) {
        let tick = TIMER_TICKS.load(Ordering::Relaxed);

        // タイマーベースのスリープを処理
        crate::task::timer::handle_timer_interrupt();

        // プリエンプションシステムにタイマーティックを通知
        crate::task::preemption::handle_timer_tick(tick);

        // Interrupt-Wakerブリッジの処理
        crate::task::interrupt_waker::handle_timer_interrupt_waker();

        // PMMメンテナンス (非ISRコンテキスト)
        crate::mm::pmm_maintenance_tick(tick);

        // ペンディングのプリエンプションを処理
        if crate::task::preemption::is_preemption_pending() {
            crate::task::preemption::request_yield();
        }
    }
}

// キーボード割り込みハンドラ
// Interrupt-Wakerブリッジとの連携
define_interrupt!(
    fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
        // Delegate to the PS/2 controller handler which reads status/data itself.
        crate::io::hid::ps2::keyboard_interrupt_handler();

        // Interrupt-Wakerブリッジにキーボード割り込みを通知（設計書 4.2）
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::Keyboard,
        );

        // Interrupt-Waker Bridge（設計書 4.2: 2段階Wake方式）
        crate::io::interrupt_manager::push_interrupt_event(InterruptVector::Keyboard as u8);

        // EOI を送信
        unsafe {
            send_eoi(InterruptVector::Keyboard as u8 - PIC1_OFFSET);
        }
    }
);

// マウス割り込みハンドラ (IRQ12)
// PS/2マウスからのデータ受信時に呼ばれる
define_interrupt!(
    fn mouse_interrupt_handler(_stack_frame: InterruptStackFrame) {
        // Port import not needed; use crate::io::inb for port reads

        // マウスデータポートから読み取り（これをしないと次の割り込みが来ない）
        let data: u8 = crate::io::inb(0x60);

        // データをhidモジュールに渡して処理
        crate::io::hid::handle_mouse_packet(data);

        // Interrupt-Wakerブリッジにマウス割り込みを通知
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::Mouse,
        );

        // Interrupt-Waker Bridge（設計書 4.2: 2段階Wake方式）
        crate::io::interrupt_manager::push_interrupt_event(InterruptVector::Mouse as u8);

        // EOI を送信 (IRQ12はPIC2のIRQ4)
        unsafe {
            send_eoi(InterruptVector::Mouse as u8 - PIC1_OFFSET);
        }
    }
);

// COM1 (Serial) 割り込みハンドラ
// シリアルポートからのデータ受信時に呼ばれる
define_interrupt!(
    fn com1_interrupt_handler(_stack_frame: InterruptStackFrame) {
        // シリアルポートドライバの割り込みハンドラを呼び出し
        crate::io::serial::dispatch_interrupt();

        // Interrupt-Wakerブリッジに通知
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::Serial,
        );

        // Interrupt-Waker Bridge（設計書 4.2: 2段階Wake方式）
        crate::io::interrupt_manager::push_interrupt_event(InterruptVector::Com1 as u8);

        // EOI を送信 (IRQ4 = COM1)
        unsafe {
            send_eoi(InterruptVector::Com1 as u8 - PIC1_OFFSET);
        }
    }
);

// IOMMU Fault Handler
//
// Handles faults reported by the IOMMU (DMA remapping errors, etc.)
// Also wakes any pending async invalidation waiters.
define_interrupt!(
    fn iommu_fault_handler(_stack_frame: InterruptStackFrame) {
        // Process faults
        crate::io::iommu::api::handle_fault();

        // Wake any pending async invalidation waiters
        // Intel VT-d uses the same interrupt for both faults and invalidation completion
        crate::io::iommu::api::wake_invalidation_waiters();

        // Send EOI to Local APIC (IOMMU uses MSI/APIC delivery)
        // We use the unified interrupt manager's EOI helper which targets LAPIC
        crate::io::interrupt_manager::send_eoi();
    }
);

// ============================================================================
// PCI IRQ Handlers (IRQ 9, 10, 11)
// ============================================================================

// IRQ 9 ハンドラ (PCI デバイス用)
define_interrupt!(
    fn pci_irq9_handler(_stack_frame: InterruptStackFrame) {
        dispatch_pci_interrupt(9);
        unsafe {
            send_eoi(9);
        }
    }
);

// IRQ 10 ハンドラ (PCI デバイス用)
define_interrupt!(
    fn pci_irq10_handler(_stack_frame: InterruptStackFrame) {
        dispatch_pci_interrupt(10);
        unsafe {
            send_eoi(10);
        }
    }
);

// IRQ 11 ハンドラ (PCI デバイス用)
define_interrupt!(
    fn pci_irq11_handler(_stack_frame: InterruptStackFrame) {
        dispatch_pci_interrupt(11);
        unsafe {
            send_eoi(11);
        }
    }
);

// TLB Flush IPI Handler (0xF1 = 241)
// マルチコア環境でのTLBシュートダウン用割り込みハンドラ
// 他CPUからのTLBフラッシュ要求を処理
define_interrupt!(
    fn tlb_flush_ipi_handler(_stack_frame: InterruptStackFrame) {
        // TLBフラッシュ処理を実行
        // Safety: 割り込みハンドラとして呼び出されている
        unsafe {
            crate::mm::tlb_batch::tlb_flush_ipi_handler();
        }
        
        // Local APICにEOIを送信
        // IPIはLocal APICから来るのでLocal APICにEOIを送る
        crate::io::interrupt_manager::send_eoi();
    }
);

// Spurious Interrupt Handler (0xFF)
// APICノイズによる偽の割り込みを処理
// 何もせず単にリターンする（EOIも送らないのが一般的だが、ISR上はiretが必要）
define_interrupt!(
    fn spurious_interrupt_handler(_stack_frame: InterruptStackFrame) {
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
    // HDA ドライバをチェック
    let hda_irq = crate::io::audio::hda::get_irq();
    if hda_irq == irq {
        crate::io::audio::hda::handle_interrupt();
    }

    // 将来的には他の PCI デバイスもここに追加
    // 例: NVMe, ネットワークカードなど
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
    log::info!(
        "  IDT Initialized: {}\n",
        IDT_INITIALIZED.load(Ordering::SeqCst)
    );
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
