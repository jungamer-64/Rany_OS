// ============================================================================
// src/io/apic.rs - Local APIC and I/O APIC Support
// 設計書 フェーズ2: 8259 PICからAPICへの移行
// ============================================================================
//!
//! # Advanced Programmable Interrupt Controller (APIC)
//!
//! マルチコア対応のための割り込みコントローラ実装。
//! Local APICとI/O APICの両方をサポート。
//!
//! ## 設計原則
//! - メモリマップドI/Oによるレジスタアクセス
//! - Per-CPU Local APICの初期化
//! - I/O APICによる外部割り込みルーティング
//! - APICタイマーによる高精度タイマー
//!
//! ## 使用方法
//! 
//! **推奨**: ドライバからは [`interrupt_manager`](super::interrupt_manager) を使用してください。
//! このモジュールは低レベルのハードウェアアクセスを提供しますが、
//! 直接使用すると他のサブシステムとの競合が発生する可能性があります。
//!
//! ```ignore
//! // 推奨: interrupt_manager経由で使用
//! use crate::io::interrupt_manager::{interrupt_manager, DeliveryMode};
//! 
//! let alloc = interrupt_manager().allocate_msi_vector(bdf, "my_device".into(), None)?;
//! ```
//!
//! ## 内部API（interrupt_manager向け）
//! 
//! このモジュールの関数は主に `interrupt_manager` から呼び出されます。
//! 直接使用する場合は、ベクタ管理との整合性に注意してください。

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

// ============================================================================
// APIC定数
// ============================================================================

/// Local APICのデフォルトベースアドレス
const LOCAL_APIC_BASE: u64 = 0xFEE0_0000;

/// I/O APICのデフォルトベースアドレス
const IO_APIC_BASE: u64 = 0xFEC0_0000;

// Local APICレジスタオフセット
mod lapic_reg {
    pub const ID: u32 = 0x020;
    pub const VERSION: u32 = 0x030;
    pub const TPR: u32 = 0x080; // Task Priority Register
    pub const APR: u32 = 0x090; // Arbitration Priority Register
    pub const PPR: u32 = 0x0A0; // Processor Priority Register
    pub const EOI: u32 = 0x0B0; // End of Interrupt
    pub const RRD: u32 = 0x0C0; // Remote Read Register
    pub const LDR: u32 = 0x0D0; // Logical Destination Register
    pub const DFR: u32 = 0x0E0; // Destination Format Register
    pub const SIVR: u32 = 0x0F0; // Spurious Interrupt Vector Register
    pub const ISR_BASE: u32 = 0x100; // In-Service Register (8 registers)
    pub const TMR_BASE: u32 = 0x180; // Trigger Mode Register (8 registers)
    pub const IRR_BASE: u32 = 0x200; // Interrupt Request Register (8 registers)
    pub const ESR: u32 = 0x280; // Error Status Register
    pub const LVT_CMCI: u32 = 0x2F0; // LVT CMCI
    pub const ICR_LOW: u32 = 0x300; // Interrupt Command Register (低32bit)
    pub const ICR_HIGH: u32 = 0x310; // Interrupt Command Register (高32bit)
    pub const LVT_TIMER: u32 = 0x320; // LVT Timer
    pub const LVT_THERMAL: u32 = 0x330; // LVT Thermal Sensor
    pub const LVT_PMC: u32 = 0x340; // LVT Performance Counter
    pub const LVT_LINT0: u32 = 0x350; // LVT LINT0
    pub const LVT_LINT1: u32 = 0x360; // LVT LINT1
    pub const LVT_ERROR: u32 = 0x370; // LVT Error
    pub const TIMER_ICR: u32 = 0x380; // Timer Initial Count Register
    pub const TIMER_CCR: u32 = 0x390; // Timer Current Count Register
    pub const TIMER_DCR: u32 = 0x3E0; // Timer Divide Configuration Register
}

// I/O APICレジスタ
mod ioapic_reg {
    pub const IOREGSEL: u32 = 0x00; // I/O Register Select
    pub const IOWIN: u32 = 0x10; // I/O Window

    // 間接レジスタ
    pub const IOAPICID: u8 = 0x00;
    pub const IOAPICVER: u8 = 0x01;
    pub const IOAPICARB: u8 = 0x02;
    pub const IOREDTBL_BASE: u8 = 0x10; // Redirection Table (24 entries, each 64-bit)
}

// LVTエントリのビットフィールド
mod lvt_flags {
    pub const MASKED: u32 = 1 << 16;
    pub const LEVEL_TRIGGERED: u32 = 1 << 15;
    pub const REMOTE_IRR: u32 = 1 << 14;
    pub const LOW_POLARITY: u32 = 1 << 13;
    pub const DELIVERY_STATUS: u32 = 1 << 12;

    pub const DELIVERY_MODE_FIXED: u32 = 0b000 << 8;
    pub const DELIVERY_MODE_SMI: u32 = 0b010 << 8;
    pub const DELIVERY_MODE_NMI: u32 = 0b100 << 8;
    pub const DELIVERY_MODE_INIT: u32 = 0b101 << 8;
    pub const DELIVERY_MODE_EXTINT: u32 = 0b111 << 8;

    pub const TIMER_MODE_ONESHOT: u32 = 0b00 << 17;
    pub const TIMER_MODE_PERIODIC: u32 = 0b01 << 17;
    pub const TIMER_MODE_TSC_DEADLINE: u32 = 0b10 << 17;
}

// タイマー分周器
mod timer_divisor {
    pub const DIV_1: u32 = 0b1011;
    pub const DIV_2: u32 = 0b0000;
    pub const DIV_4: u32 = 0b0001;
    pub const DIV_8: u32 = 0b0010;
    pub const DIV_16: u32 = 0b0011;
    pub const DIV_32: u32 = 0b1000;
    pub const DIV_64: u32 = 0b1001;
    pub const DIV_128: u32 = 0b1010;
}

// ============================================================================
// Local APIC
// ============================================================================

/// Local APICインスタンス
pub struct LocalApic {
    base_address: u64,
    is_enabled: AtomicBool,
    ticks_per_ms: AtomicU64,
}

impl LocalApic {
    /// 新しいLocal APICを作成
    pub const fn new() -> Self {
        Self {
            base_address: LOCAL_APIC_BASE,
            is_enabled: AtomicBool::new(false),
            ticks_per_ms: AtomicU64::new(0),
        }
    }

    /// ベースアドレスを設定
    pub fn set_base_address(&mut self, addr: u64) {
        self.base_address = addr;
    }

    /// レジスタを読み取り
    unsafe fn read(&self, reg: u32) -> u32 { unsafe {
        let addr = self.base_address + reg as u64;
        core::ptr::read_volatile(addr as *const u32)
    }}

    /// レジスタに書き込み
    unsafe fn write(&self, reg: u32, value: u32) { unsafe {
        let addr = self.base_address + reg as u64;
        core::ptr::write_volatile(addr as *mut u32, value);
    }}

    /// Local APICを初期化
    pub fn init(&self) {
        unsafe {
            // Spurious Interrupt Vectorを設定してAPICを有効化
            // ベクタ0xFF、APICソフトウェア有効化ビット
            self.write(lapic_reg::SIVR, 0xFF | (1 << 8));

            // タスク優先度を0に設定（すべての割り込みを許可）
            self.write(lapic_reg::TPR, 0);

            // LVTエントリをマスク
            self.write(lapic_reg::LVT_TIMER, lvt_flags::MASKED);
            self.write(lapic_reg::LVT_LINT0, lvt_flags::MASKED);
            self.write(lapic_reg::LVT_LINT1, lvt_flags::MASKED);
            self.write(lapic_reg::LVT_ERROR, lvt_flags::MASKED);
            self.write(lapic_reg::LVT_PMC, lvt_flags::MASKED);
            self.write(lapic_reg::LVT_THERMAL, lvt_flags::MASKED);

            // エラーステータスをクリア
            self.write(lapic_reg::ESR, 0);
            self.write(lapic_reg::ESR, 0);

            // 保留中の割り込みをEOIでクリア
            self.write(lapic_reg::EOI, 0);

            self.is_enabled.store(true, Ordering::SeqCst);
        }

        crate::log!(
            "[APIC] Local APIC initialized at 0x{:X}\n",
            self.base_address
        );
    }

    /// APICタイマーを較正
    pub fn calibrate_timer(&self) {
        unsafe {
            // PITを使用して較正（1/100秒 = 10ms）
            // ここでは簡易的に固定値を使用
            // 実際の実装ではPITまたはACPI PMタイマーで較正する

            // 分周器を16に設定
            self.write(lapic_reg::TIMER_DCR, timer_divisor::DIV_16);

            // 初期カウントを最大値に設定
            self.write(lapic_reg::TIMER_ICR, 0xFFFFFFFF);

            // 簡易的なビジーウェイト（約10ms）
            for _ in 0..10_000_000 {
                core::hint::spin_loop();
            }

            // 経過カウントを取得
            let elapsed = 0xFFFFFFFF - self.read(lapic_reg::TIMER_CCR);

            // タイマーを停止
            self.write(lapic_reg::LVT_TIMER, lvt_flags::MASKED);

            // 1msあたりのティック数を計算（10msで測定したので/10）
            let ticks_per_ms = elapsed / 10;
            self.ticks_per_ms
                .store(ticks_per_ms as u64, Ordering::SeqCst);

            crate::log!("[APIC] Timer calibrated: {} ticks/ms\n", ticks_per_ms);
        }
    }

    /// APICタイマーを設定（周期的割り込み）
    pub fn start_timer(&self, vector: u8, interval_ms: u32) {
        let ticks_per_ms = self.ticks_per_ms.load(Ordering::SeqCst);
        if ticks_per_ms == 0 {
            crate::log!("[APIC] Warning: Timer not calibrated\n");
            return;
        }

        let count = ticks_per_ms as u32 * interval_ms;

        unsafe {
            // 分周器を設定
            self.write(lapic_reg::TIMER_DCR, timer_divisor::DIV_16);

            // LVTタイマーを設定（周期モード）
            self.write(
                lapic_reg::LVT_TIMER,
                vector as u32 | lvt_flags::TIMER_MODE_PERIODIC,
            );

            // 初期カウントを設定（タイマー開始）
            self.write(lapic_reg::TIMER_ICR, count);
        }

        crate::log!(
            "[APIC] Timer started: vector={}, interval={}ms\n",
            vector,
            interval_ms
        );
    }

    /// APICタイマーを停止
    pub fn stop_timer(&self) {
        unsafe {
            self.write(lapic_reg::LVT_TIMER, lvt_flags::MASKED);
            self.write(lapic_reg::TIMER_ICR, 0);
        }
    }

    /// End of Interruptを送信
    pub fn end_of_interrupt(&self) {
        unsafe {
            self.write(lapic_reg::EOI, 0);
        }
    }

    /// Local APIC IDを取得
    pub fn id(&self) -> u8 {
        unsafe { ((self.read(lapic_reg::ID) >> 24) & 0xFF) as u8 }
    }

    /// Local APICバージョンを取得
    pub fn version(&self) -> u8 {
        unsafe { (self.read(lapic_reg::VERSION) & 0xFF) as u8 }
    }

    /// IPIを送信
    pub fn send_ipi(&self, target_apic_id: u8, vector: u8) {
        unsafe {
            // 送信先を設定
            self.write(lapic_reg::ICR_HIGH, (target_apic_id as u32) << 24);

            // 割り込みコマンドを発行
            self.write(
                lapic_reg::ICR_LOW,
                vector as u32 | lvt_flags::DELIVERY_MODE_FIXED,
            );

            // 送信完了を待機
            while (self.read(lapic_reg::ICR_LOW) & lvt_flags::DELIVERY_STATUS) != 0 {
                core::hint::spin_loop();
            }
        }
    }

    /// ブロードキャストIPI（自分以外）
    pub fn send_ipi_all_excluding_self(&self, vector: u8) {
        unsafe {
            self.write(lapic_reg::ICR_HIGH, 0);
            self.write(
                lapic_reg::ICR_LOW,
                vector as u32 | (0b11 << 18) | lvt_flags::DELIVERY_MODE_FIXED,
            );
        }
    }

    /// INIT IPIを送信
    pub fn send_init(&self, target_apic_id: u8) {
        unsafe {
            self.write(lapic_reg::ICR_HIGH, (target_apic_id as u32) << 24);
            self.write(
                lapic_reg::ICR_LOW,
                lvt_flags::DELIVERY_MODE_INIT | lvt_flags::LEVEL_TRIGGERED,
            );

            while (self.read(lapic_reg::ICR_LOW) & lvt_flags::DELIVERY_STATUS) != 0 {
                core::hint::spin_loop();
            }
        }
    }

    /// SIPI (Startup IPI)を送信
    pub fn send_sipi(&self, target_apic_id: u8, vector: u8) {
        unsafe {
            self.write(lapic_reg::ICR_HIGH, (target_apic_id as u32) << 24);
            self.write(
                lapic_reg::ICR_LOW,
                vector as u32 | (0b110 << 8), // Startup delivery mode
            );

            while (self.read(lapic_reg::ICR_LOW) & lvt_flags::DELIVERY_STATUS) != 0 {
                core::hint::spin_loop();
            }
        }
    }
}

// ============================================================================
// I/O APIC
// ============================================================================

/// I/O APICインスタンス
pub struct IoApic {
    base_address: u64,
    global_irq_base: u32,
}

impl IoApic {
    /// 新しいI/O APICを作成
    pub const fn new() -> Self {
        Self {
            base_address: IO_APIC_BASE,
            global_irq_base: 0,
        }
    }

    /// ベースアドレスを設定
    pub fn set_base_address(&mut self, addr: u64, irq_base: u32) {
        self.base_address = addr;
        self.global_irq_base = irq_base;
    }

    /// レジスタを選択
    unsafe fn select(&self, reg: u8) { unsafe {
        let addr = self.base_address + ioapic_reg::IOREGSEL as u64;
        core::ptr::write_volatile(addr as *mut u32, reg as u32);
    }}

    /// 選択したレジスタを読み取り
    unsafe fn read(&self, reg: u8) -> u32 { unsafe {
        self.select(reg);
        let addr = self.base_address + ioapic_reg::IOWIN as u64;
        core::ptr::read_volatile(addr as *const u32)
    }}

    /// 選択したレジスタに書き込み
    unsafe fn write(&self, reg: u8, value: u32) { unsafe {
        self.select(reg);
        let addr = self.base_address + ioapic_reg::IOWIN as u64;
        core::ptr::write_volatile(addr as *mut u32, value);
    }}

    /// I/O APICを初期化
    pub fn init(&self) {
        let max_entries = self.max_redirection_entries();

        // すべてのリダイレクションエントリをマスク
        for i in 0..=max_entries {
            self.set_irq_mask(i, true);
        }

        crate::log!(
            "[APIC] I/O APIC initialized at 0x{:X}, {} entries\n",
            self.base_address,
            max_entries + 1
        );
    }

    /// I/O APIC IDを取得
    pub fn id(&self) -> u8 {
        unsafe { ((self.read(ioapic_reg::IOAPICID) >> 24) & 0xF) as u8 }
    }

    /// I/O APICバージョンを取得
    pub fn version(&self) -> u8 {
        unsafe { (self.read(ioapic_reg::IOAPICVER) & 0xFF) as u8 }
    }

    /// 最大リダイレクションエントリ数を取得
    pub fn max_redirection_entries(&self) -> u8 {
        unsafe { ((self.read(ioapic_reg::IOAPICVER) >> 16) & 0xFF) as u8 }
    }

    /// IRQをCPUにルーティング
    pub fn route_irq(
        &self,
        irq: u8,
        vector: u8,
        apic_id: u8,
        level_triggered: bool,
        low_active: bool,
    ) {
        let mut entry: u64 = vector as u64;

        if level_triggered {
            entry |= 1 << 15;
        }
        if low_active {
            entry |= 1 << 13;
        }

        // 送信先APIC IDを設定
        entry |= (apic_id as u64) << 56;

        self.write_redirection_entry(irq, entry);
    }

    /// リダイレクションエントリを書き込み
    fn write_redirection_entry(&self, irq: u8, entry: u64) {
        let reg = ioapic_reg::IOREDTBL_BASE + irq * 2;

        unsafe {
            self.write(reg, entry as u32);
            self.write(reg + 1, (entry >> 32) as u32);
        }
    }

    /// リダイレクションエントリを読み取り
    pub fn read_redirection_entry(&self, irq: u8) -> u64 {
        let reg = ioapic_reg::IOREDTBL_BASE + irq * 2;

        unsafe {
            let low = self.read(reg) as u64;
            let high = self.read(reg + 1) as u64;
            low | (high << 32)
        }
    }

    /// IRQをマスク/アンマスク
    pub fn set_irq_mask(&self, irq: u8, masked: bool) {
        let mut entry = self.read_redirection_entry(irq);

        if masked {
            entry |= 1 << 16;
        } else {
            entry &= !(1 << 16);
        }

        self.write_redirection_entry(irq, entry);
    }
}

// ============================================================================
// グローバルAPICインスタンス
// ============================================================================

/// グローバルLocal APIC
static LOCAL_APIC: Mutex<LocalApic> = Mutex::new(LocalApic::new());

/// グローバルI/O APIC
static IO_APIC: Mutex<IoApic> = Mutex::new(IoApic::new());

/// APICが有効かどうか
static APIC_ENABLED: AtomicBool = AtomicBool::new(false);

/// Local APICにアクセス
pub fn local_apic() -> spin::MutexGuard<'static, LocalApic> {
    LOCAL_APIC.lock()
}

/// I/O APICにアクセス
pub fn io_apic() -> spin::MutexGuard<'static, IoApic> {
    IO_APIC.lock()
}

/// APICが有効かどうか
pub fn is_apic_enabled() -> bool {
    APIC_ENABLED.load(Ordering::SeqCst)
}

// ============================================================================
// APIC初期化
// ============================================================================

/// CPUがAPICをサポートしているか確認
pub fn check_apic_support() -> bool {
    // CPUID命令でAPICサポートを確認
    // CPUID(1)のEDXビット9がAPICサポートを示す
    unsafe {
        let edx: u32;
        let rbx_save: u64;

        core::arch::asm!(
            // rbxを保存（LLVMが使用するため）
            "mov {0}, rbx",
            "mov eax, 1",
            "xor ecx, ecx",
            "cpuid",
            "mov {1:e}, edx",
            "mov rbx, {0}",
            out(reg) rbx_save,
            out(reg) edx,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );

        let _ = rbx_save;

        // EDXのビット9がAPICサポート
        let apic_supported = (edx & (1 << 9)) != 0;

        crate::log!("[APIC] CPUID: APIC supported = {}\n", apic_supported);
        apic_supported
    }
}

/// APICを初期化
pub fn init() {
    if !check_apic_support() {
        crate::log!("[APIC] APIC not supported, using legacy PIC\n");
        return;
    }

    // 8259 PICを無効化
    disable_pic();

    // Local APICを初期化
    local_apic().init();

    // I/O APICを初期化
    io_apic().init();

    // タイマーを較正
    local_apic().calibrate_timer();

    // キーボード割り込みをルーティング（IRQ1 -> vector 0x21）
    io_apic().route_irq(1, 0x21, local_apic().id(), false, false);
    io_apic().set_irq_mask(1, false);

    APIC_ENABLED.store(true, Ordering::SeqCst);

    crate::log!("[APIC] APIC system initialized\n");
}

/// 8259 PICを無効化
fn disable_pic() {
    unsafe {
        use x86_64::instructions::port::Port;

        let mut pic1_data: Port<u8> = Port::new(0x21);
        let mut pic2_data: Port<u8> = Port::new(0xA1);

        // すべての割り込みをマスク
        pic1_data.write(0xFF);
        pic2_data.write(0xFF);
    }

    crate::log!("[APIC] Legacy PIC disabled\n");
}

/// APICタイマーを開始
pub fn start_apic_timer(interval_ms: u32) {
    // タイマー割り込みベクタ: 0x20
    local_apic().start_timer(0x20, interval_ms);
}

/// End of Interrupt（割り込み完了）
pub fn end_of_interrupt() {
    if is_apic_enabled() {
        local_apic().end_of_interrupt();
    }
}

/// APIC統計情報
pub struct ApicStats {
    pub local_apic_id: u8,
    pub local_apic_version: u8,
    pub io_apic_id: u8,
    pub io_apic_version: u8,
    pub max_redirection_entries: u8,
    pub ticks_per_ms: u64,
}

/// 統計情報を取得
pub fn get_stats() -> ApicStats {
    let lapic = local_apic();
    let ioapic = io_apic();

    ApicStats {
        local_apic_id: lapic.id(),
        local_apic_version: lapic.version(),
        io_apic_id: ioapic.id(),
        io_apic_version: ioapic.version(),
        max_redirection_entries: ioapic.max_redirection_entries(),
        ticks_per_ms: lapic.ticks_per_ms.load(Ordering::Relaxed),
    }
}
