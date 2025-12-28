// ============================================================================
// src/io/apic.rs - Local APIC and I/O APIC Support
// 設計書 フェーズ2: 8259 PICからAPICへの移行
// ============================================================================
//!
#![no_std]
#![allow(dead_code)]

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

// ============================================================================
// Local APIC Register Enum (Type-Safe)
// ============================================================================

/// Local APICレジスタ（型安全なEnum）
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LapicRegister {
    /// APIC ID Register
    Id = 0x020,
    /// APIC Version Register
    Version = 0x030,
    /// Task Priority Register
    Tpr = 0x080,
    /// Arbitration Priority Register
    Apr = 0x090,
    /// Processor Priority Register
    Ppr = 0x0A0,
    /// End of Interrupt Register
    Eoi = 0x0B0,
    /// Remote Read Register
    Rrd = 0x0C0,
    /// Logical Destination Register
    Ldr = 0x0D0,
    /// Destination Format Register
    Dfr = 0x0E0,
    /// Spurious Interrupt Vector Register
    Sivr = 0x0F0,
    /// Error Status Register
    Esr = 0x280,
    /// LVT CMCI Register
    LvtCmci = 0x2F0,
    /// Interrupt Command Register (Low 32-bit)
    IcrLow = 0x300,
    /// Interrupt Command Register (High 32-bit)
    IcrHigh = 0x310,
    /// LVT Timer Register
    LvtTimer = 0x320,
    /// LVT Thermal Sensor Register
    LvtThermal = 0x330,
    /// LVT Performance Counter Register
    LvtPmc = 0x340,
    /// LVT LINT0 Register
    LvtLint0 = 0x350,
    /// LVT LINT1 Register
    LvtLint1 = 0x360,
    /// LVT Error Register
    LvtError = 0x370,
    /// Timer Initial Count Register
    TimerIcr = 0x380,
    /// Timer Current Count Register
    TimerCcr = 0x390,
    /// Timer Divide Configuration Register
    TimerDcr = 0x3E0,
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

// ============================================================================
// LVT Flags (Type-Safe Bitflags)
// ============================================================================

use bitflags::bitflags;

bitflags! {
    /// LVT (Local Vector Table) エントリのフラグ
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LvtFlags: u32 {
        /// 割り込みマスク（1 = マスク済み）
        const MASKED = 1 << 16;
        /// レベルトリガー（1 = レベル, 0 = エッジ）
        const LEVEL_TRIGGERED = 1 << 15;
        /// Remote IRR（読み取り専用）
        const REMOTE_IRR = 1 << 14;
        /// 極性（1 = Low Active, 0 = High Active）
        const LOW_POLARITY = 1 << 13;
        /// 配送ステータス（読み取り専用）
        const DELIVERY_STATUS = 1 << 12;

        // Delivery Mode (bits 10:8)
        /// Fixed delivery mode
        const DELIVERY_FIXED = 0b000 << 8;
        /// SMI delivery mode
        const DELIVERY_SMI = 0b010 << 8;
        /// NMI delivery mode
        const DELIVERY_NMI = 0b100 << 8;
        /// INIT delivery mode
        const DELIVERY_INIT = 0b101 << 8;
        /// ExtINT delivery mode
        const DELIVERY_EXTINT = 0b111 << 8;

        // Timer Mode (bits 18:17)
        /// One-shot timer mode
        const TIMER_ONESHOT = 0b00 << 17;
        /// Periodic timer mode
        const TIMER_PERIODIC = 0b01 << 17;
        /// TSC-Deadline timer mode
        const TIMER_TSC_DEADLINE = 0b10 << 17;
    }
}

impl LvtFlags {
    /// ベクタ番号をフラグに設定（下位8ビット）
    #[inline]
    pub fn with_vector(self, vector: u8) -> u32 {
        self.bits() | (vector as u32)
    }
}

// ============================================================================
// Interrupt Trigger and Polarity (Type-Safe Enums)
// ============================================================================

/// 割り込みトリガーモード
///
/// `bool` 引数の代わりに使用することで、コードの可読性が向上します。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriggerMode {
    /// エッジトリガー（立ち上がり/立ち下がりで割り込み発生）
    #[default]
    Edge,
    /// レベルトリガー（信号がアクティブな間割り込み状態を維持）
    Level,
}

impl TriggerMode {
    /// レベルトリガーかどうか
    #[inline]
    pub const fn is_level(self) -> bool {
        matches!(self, Self::Level)
    }
}

/// 割り込み極性
///
/// `bool` 引数の代わりに使用することで、コードの可読性が向上します。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Polarity {
    /// アクティブハイ（信号がHighで割り込みアクティブ）
    #[default]
    HighActive,
    /// アクティブロー（信号がLowで割り込みアクティブ）
    LowActive,
}

impl Polarity {
    /// ローアクティブかどうか
    #[inline]
    pub const fn is_low_active(self) -> bool {
        matches!(self, Self::LowActive)
    }
}

// ============================================================================
// Timer Divisor Enum (Type-Safe)
// ============================================================================

/// APICタイマー分周器（型安全なEnum）
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerDivisor {
    /// Divide by 1
    Div1 = 0b1011,
    /// Divide by 2
    Div2 = 0b0000,
    /// Divide by 4
    Div4 = 0b0001,
    /// Divide by 8
    Div8 = 0b0010,
    /// Divide by 16
    Div16 = 0b0011,
    /// Divide by 32
    Div32 = 0b1000,
    /// Divide by 64
    Div64 = 0b1001,
    /// Divide by 128
    Div128 = 0b1010,
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

    // ========================================================================
    // Type-Safe Register Access (Using MmioReg - Safe API)
    // ========================================================================

    /// レジスタアクセサを取得
    #[inline]
    fn reg(&self, reg: LapicRegister) -> hal::MmioReg<u32> {
        hal::MmioReg::new(self.base_address as usize, reg as usize)
    }

    /// レジスタを読み取り
    #[inline]
    fn read_reg(&self, reg: LapicRegister) -> u32 {
        self.reg(reg).read()
    }

    /// レジスタに書き込み
    #[inline]
    fn write_reg(&self, reg: LapicRegister, value: u32) {
        self.reg(reg).write(value);
    }

    /// LVTレジスタにフラグ付きで書き込み
    #[inline]
    fn write_lvt(&self, reg: LapicRegister, flags: LvtFlags) {
        self.write_reg(reg, flags.bits());
    }

    /// LVTレジスタにフラグとベクタを書き込み
    #[inline]
    fn write_lvt_vector(&self, reg: LapicRegister, flags: LvtFlags, vector: u8) {
        self.write_reg(reg, flags.with_vector(vector));
    }

    /// 分周器を設定
    #[inline]
    fn set_timer_divisor(&self, divisor: TimerDivisor) {
        self.write_reg(LapicRegister::TimerDcr, divisor as u32);
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Local APICを初期化
    pub fn init(&self) {
        // Spurious Interrupt Vectorを設定してAPICを有効化
        // ベクタ0xFF、APICソフトウェア有効化ビット
        self.write_reg(LapicRegister::Sivr, 0xFF | (1 << 8));

        // タスク優先度を0に設定（すべての割り込みを許可）
        self.write_reg(LapicRegister::Tpr, 0);

        // LVTエントリをマスク
        let mask_targets = [
            LapicRegister::LvtTimer,
            LapicRegister::LvtLint0,
            LapicRegister::LvtLint1,
            LapicRegister::LvtError,
            LapicRegister::LvtPmc,
            LapicRegister::LvtThermal,
        ];
        for reg in mask_targets {
            self.write_lvt(reg, LvtFlags::MASKED);
        }

        // エラーステータスをクリア
        self.write_reg(LapicRegister::Esr, 0);
        self.write_reg(LapicRegister::Esr, 0);

        // 保留中の割り込みをEOIでクリア
        self.send_eoi();

        self.is_enabled.store(true, Ordering::SeqCst);

        log::info!(
            "[APIC] Local APIC initialized at 0x{:X}\n",
            self.base_address
        );
    }

    /// End of Interruptを送信（専用メソッド）
    #[inline]
    pub fn send_eoi(&self) {
        self.write_reg(LapicRegister::Eoi, 0);
    }

    /// APICタイマーを較正
    pub fn calibrate_timer(&self) {
        use hal::port_io::PortU8;

        // PIT (Legacy Programmable Interval Timer) を使用して較正
        // Note: PIT port I/O requires unsafe
        let (gate_val, elapsed) = unsafe {
            let mut pit_cmd = PortU8::new(0x43);
            let mut pit_data = PortU8::new(0x42);
            let mut pit_gate = PortU8::new(0x61);

            // Channel 2 Gate High (カウント有効化)
            let gate_val = pit_gate.read();
            pit_gate.write(gate_val | 1);

            // 0xB0 = Channel 2, Access Lo/Hi, Mode 0, Binary
            pit_cmd.write(0xB0);

            // 10ms 待機用カウント設定 (1.193182 MHz / 100 = 11932)
            let count = 11932_u16;
            pit_data.write((count & 0xFF) as u8);
            pit_data.write((count >> 8) as u8);

            // APICタイマー準備 (safe - uses MmioReg)
            self.set_timer_divisor(TimerDivisor::Div16);
            self.write_reg(LapicRegister::TimerIcr, 0xFFFFFFFF);

            // PITのカウント終了を待つ
            while (pit_gate.read() & 0x20) == 0 {
                core::hint::spin_loop();
            }

            // APICタイマーの現在値を読む (safe - uses MmioReg)
            let current_count = self.read_reg(LapicRegister::TimerCcr);
            let elapsed = 0xFFFFFFFF - current_count;

            // Gate Low (無効化)
            pit_gate.write(gate_val & !1);

            (gate_val, elapsed)
        };

        // タイマー停止 (safe - uses MmioReg)
        self.write_lvt(LapicRegister::LvtTimer, LvtFlags::MASKED);

        // 1msあたりのティック数 (10ms計測なので /10)
        let ticks_per_ms = elapsed / 10;
        self.ticks_per_ms
            .store(ticks_per_ms as u64, Ordering::SeqCst);

        let _ = gate_val; // suppress unused warning
        log::info!(
            "[APIC] Timer calibrated using PIT: {} ticks/ms\n",
            ticks_per_ms
        );
    }

    /// APICタイマーを設定（周期的割り込み）
    pub fn start_timer(&self, vector: u8, interval_ms: u32) {
        let ticks_per_ms = self.ticks_per_ms.load(Ordering::SeqCst);
        if ticks_per_ms == 0 {
            log::warn!("[APIC] Timer not calibrated\n");
            return;
        }

        let count = ticks_per_ms as u32 * interval_ms;

        self.set_timer_divisor(TimerDivisor::Div16);
        self.write_lvt_vector(LapicRegister::LvtTimer, LvtFlags::TIMER_PERIODIC, vector);
        self.write_reg(LapicRegister::TimerIcr, count);

        log::info!(
            "[APIC] Timer started: vector={}, interval={}ms\n",
            vector,
            interval_ms
        );
    }

    /// APICタイマーを停止
    pub fn stop_timer(&self) {
        self.write_lvt(LapicRegister::LvtTimer, LvtFlags::MASKED);
        self.write_reg(LapicRegister::TimerIcr, 0);
    }

    /// End of Interruptを送信（後方互換性のためのエイリアス）
    #[inline]
    pub fn end_of_interrupt(&self) {
        self.send_eoi();
    }

    /// Local APIC IDを取得
    pub fn id(&self) -> u8 {
        ((self.read_reg(LapicRegister::Id) >> 24) & 0xFF) as u8
    }

    /// Local APICバージョンを取得
    pub fn version(&self) -> u8 {
        (self.read_reg(LapicRegister::Version) & 0xFF) as u8
    }

    /// IPIを送信
    pub fn send_ipi(&self, target_apic_id: u8, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, (target_apic_id as u32) << 24);
        self.write_reg(
            LapicRegister::IcrLow,
            LvtFlags::DELIVERY_FIXED.with_vector(vector),
        );

        // 送信完了を待機
        while (self.read_reg(LapicRegister::IcrLow) & LvtFlags::DELIVERY_STATUS.bits()) != 0 {
            core::hint::spin_loop();
        }
    }

    /// ブロードキャストIPI（自分以外）
    pub fn send_ipi_all_excluding_self(&self, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, 0);
        self.write_reg(
            LapicRegister::IcrLow,
            (vector as u32) | (0b11 << 18) | LvtFlags::DELIVERY_FIXED.bits(),
        );
    }

    /// INIT IPIを送信
    pub fn send_init(&self, target_apic_id: u8) {
        self.write_reg(LapicRegister::IcrHigh, (target_apic_id as u32) << 24);
        self.write_reg(
            LapicRegister::IcrLow,
            (LvtFlags::DELIVERY_INIT | LvtFlags::LEVEL_TRIGGERED).bits(),
        );

        while (self.read_reg(LapicRegister::IcrLow) & LvtFlags::DELIVERY_STATUS.bits()) != 0 {
            core::hint::spin_loop();
        }
    }

    /// SIPI (Startup IPI)を送信
    pub fn send_sipi(&self, target_apic_id: u8, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, (target_apic_id as u32) << 24);
        self.write_reg(
            LapicRegister::IcrLow,
            (vector as u32) | (0b110 << 8), // Startup delivery mode
        );

        while (self.read_reg(LapicRegister::IcrLow) & LvtFlags::DELIVERY_STATUS.bits()) != 0 {
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// I/O APIC Redirection Entry (Type-Safe)
// ============================================================================

bitflags! {
    /// I/O APIC Redirection Entry フラグ（下位32ビット用）
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RedirectionFlags: u32 {
        /// 割り込みマスク（1 = マスク済み）
        const MASKED = 1 << 16;
        /// レベルトリガー（1 = レベル, 0 = エッジ）
        const LEVEL_TRIGGERED = 1 << 15;
        /// Remote IRR（読み取り専用）
        const REMOTE_IRR = 1 << 14;
        /// 極性（1 = Low Active, 0 = High Active）
        const LOW_POLARITY = 1 << 13;
        /// 配送ステータス（読み取り専用）
        const DELIVERY_STATUS = 1 << 12;
        /// 送信先モード（1 = Logical, 0 = Physical）
        const DESTINATION_LOGICAL = 1 << 11;

        // Delivery Mode (bits 10:8)
        /// Fixed delivery mode
        const DELIVERY_FIXED = 0b000 << 8;
        /// Lowest priority delivery mode
        const DELIVERY_LOWEST = 0b001 << 8;
        /// SMI delivery mode
        const DELIVERY_SMI = 0b010 << 8;
        /// NMI delivery mode
        const DELIVERY_NMI = 0b100 << 8;
        /// INIT delivery mode
        const DELIVERY_INIT = 0b101 << 8;
        /// ExtINT delivery mode
        const DELIVERY_EXTINT = 0b111 << 8;
    }
}

/// I/O APIC Redirection Table Entry（型安全）
///
/// ビルダーパターンを使用して、割り込みルーティングを設定。
///
/// # Example
/// ```ignore
/// let entry = RedirectionEntry::new(0x21)
///     .destination(cpu_apic_id)
///     .level_triggered()
///     .low_active();
/// io_apic.write_entry(irq, entry);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RedirectionEntry {
    low: u32,
    high: u32,
}

impl RedirectionEntry {
    /// 新しいRedirectionEntryを作成（ベクタ指定）
    #[inline]
    pub const fn new(vector: u8) -> Self {
        Self {
            low: vector as u32,
            high: 0,
        }
    }

    /// マスク済みの空エントリを作成
    #[inline]
    pub const fn masked() -> Self {
        Self {
            low: RedirectionFlags::MASKED.bits(),
            high: 0,
        }
    }

    /// 64ビット値から復元
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self {
            low: raw as u32,
            high: (raw >> 32) as u32,
        }
    }

    /// 64ビット値に変換
    #[inline]
    pub const fn to_raw(self) -> u64 {
        (self.low as u64) | ((self.high as u64) << 32)
    }

    /// 送信先APIC IDを設定（Physical mode）
    #[inline]
    pub const fn destination(mut self, apic_id: u8) -> Self {
        self.high = (apic_id as u32) << 24;
        self
    }

    /// レベルトリガーを設定
    #[inline]
    pub const fn level_triggered(mut self) -> Self {
        self.low |= RedirectionFlags::LEVEL_TRIGGERED.bits();
        self
    }

    /// エッジトリガーを設定（デフォルト）
    #[inline]
    pub const fn edge_triggered(mut self) -> Self {
        self.low &= !RedirectionFlags::LEVEL_TRIGGERED.bits();
        self
    }

    /// Low Activeを設定
    #[inline]
    pub const fn low_active(mut self) -> Self {
        self.low |= RedirectionFlags::LOW_POLARITY.bits();
        self
    }

    /// High Activeを設定（デフォルト）
    #[inline]
    pub const fn high_active(mut self) -> Self {
        self.low &= !RedirectionFlags::LOW_POLARITY.bits();
        self
    }

    /// マスクを設定
    #[inline]
    pub const fn mask(mut self) -> Self {
        self.low |= RedirectionFlags::MASKED.bits();
        self
    }

    /// マスクを解除
    #[inline]
    pub const fn unmask(mut self) -> Self {
        self.low &= !RedirectionFlags::MASKED.bits();
        self
    }

    /// マスク状態を取得
    #[inline]
    pub const fn is_masked(self) -> bool {
        (self.low & RedirectionFlags::MASKED.bits()) != 0
    }

    /// ベクタを取得
    #[inline]
    pub const fn vector(self) -> u8 {
        (self.low & 0xFF) as u8
    }

    /// 下位32ビットを取得
    #[inline]
    pub const fn low(self) -> u32 {
        self.low
    }

    /// 上位32ビットを取得
    #[inline]
    pub const fn high(self) -> u32 {
        self.high
    }

    /// トリガーモードを設定（enum版）
    #[inline]
    #[must_use]
    pub const fn with_trigger_mode(self, mode: TriggerMode) -> Self {
        match mode {
            TriggerMode::Edge => self.edge_triggered(),
            TriggerMode::Level => self.level_triggered(),
        }
    }

    /// 極性を設定（enum版）
    #[inline]
    #[must_use]
    pub const fn with_polarity(self, polarity: Polarity) -> Self {
        match polarity {
            Polarity::HighActive => self.high_active(),
            Polarity::LowActive => self.low_active(),
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

    // ========================================================================
    // Type-Safe Register Access (Using MmioReg - Safe API)
    // ========================================================================

    /// IOREGSELレジスタアクセサ
    #[inline]
    fn select_reg(&self) -> hal::MmioReg<u32> {
        hal::MmioReg::from_addr(self.base_address as usize + ioapic_reg::IOREGSEL as usize)
    }

    /// IOWINレジスタアクセサ
    #[inline]
    fn data_reg(&self) -> hal::MmioReg<u32> {
        hal::MmioReg::from_addr(self.base_address as usize + ioapic_reg::IOWIN as usize)
    }

    /// レジスタを読み取り
    #[inline]
    fn read(&self, reg: u8) -> u32 {
        self.select_reg().write(reg as u32);
        self.data_reg().read()
    }

    /// レジスタに書き込み
    #[inline]
    fn write(&self, reg: u8, value: u32) {
        self.select_reg().write(reg as u32);
        self.data_reg().write(value);
    }

    /// I/O APICを初期化
    pub fn init(&self) {
        let max_entries = self.max_redirection_entries();

        // すべてのリダイレクションエントリをマスク
        for i in 0..=max_entries {
            self.set_irq_mask(i, true);
        }

        log::info!(
            "[APIC] I/O APIC initialized at 0x{:X}, {} entries\n",
            self.base_address,
            max_entries + 1
        );
    }

    /// I/O APIC IDを取得
    pub fn id(&self) -> u8 {
        ((self.read(ioapic_reg::IOAPICID) >> 24) & 0xF) as u8
    }

    /// I/O APICバージョンを取得
    pub fn version(&self) -> u8 {
        (self.read(ioapic_reg::IOAPICVER) & 0xFF) as u8
    }

    /// 最大リダイレクションエントリ数を取得
    pub fn max_redirection_entries(&self) -> u8 {
        ((self.read(ioapic_reg::IOAPICVER) >> 16) & 0xFF) as u8
    }

    // ========================================================================
    // Type-Safe Redirection Entry API
    // ========================================================================

    /// RedirectionEntryを書き込み（型安全版）
    pub fn write_entry(&self, irq: u8, entry: RedirectionEntry) {
        let reg = ioapic_reg::IOREDTBL_BASE + irq * 2;

        // アトミック性を高めるため、64bit書き込みの手順を遵守
        // 1. マスクビット(bit 16)をセットしてエントリを無効化 (Low)
        self.write(reg, entry.low() | RedirectionFlags::MASKED.bits());
        // 2. 上位32bitを書き込み (High)
        self.write(reg + 1, entry.high());
        // 3. 元の値（マスク解除されている可能性あり）で下位32bitを書き込み (Low)
        self.write(reg, entry.low());
    }

    /// RedirectionEntryを読み取り（型安全版）
    pub fn read_entry(&self, irq: u8) -> RedirectionEntry {
        let reg = ioapic_reg::IOREDTBL_BASE + irq * 2;

        unsafe {
            let low = self.read(reg);
            let high = self.read(reg + 1);
            RedirectionEntry::from_raw((low as u64) | ((high as u64) << 32))
        }
    }

    /// IRQをCPUにルーティング（bool版、後方互換）
    pub fn route_irq(
        &self,
        irq: u8,
        vector: u8,
        apic_id: u8,
        level_triggered: bool,
        low_active: bool,
    ) {
        let mut entry = RedirectionEntry::new(vector).destination(apic_id);

        if level_triggered {
            entry = entry.level_triggered();
        }
        if low_active {
            entry = entry.low_active();
        }

        self.write_entry(irq, entry);
    }

    /// IRQをCPUにルーティング（enum版、推奨API）
    ///
    /// # Example
    /// ```ignore
    /// io_apic.route_irq_typed(1, 0x21, 0, TriggerMode::Edge, Polarity::HighActive);
    /// ```
    pub fn route_irq_typed(
        &self,
        irq: u8,
        vector: u8,
        apic_id: u8,
        trigger_mode: TriggerMode,
        polarity: Polarity,
    ) {
        let entry = RedirectionEntry::new(vector)
            .destination(apic_id)
            .with_trigger_mode(trigger_mode)
            .with_polarity(polarity);

        self.write_entry(irq, entry);
    }

    /// IRQをマスク/アンマスク（型安全版）
    pub fn set_irq_mask(&self, irq: u8, masked: bool) {
        let entry = self.read_entry(irq);
        let new_entry = if masked { entry.mask() } else { entry.unmask() };
        self.write_entry(irq, new_entry);
    }

    // ========================================================================
    // Legacy API (後方互換性のため)
    // ========================================================================

    /// リダイレクションエントリを書き込み（u64版、後方互換）
    #[deprecated(note = "Use write_entry with RedirectionEntry instead")]
    fn write_redirection_entry(&self, irq: u8, entry: u64) {
        self.write_entry(irq, RedirectionEntry::from_raw(entry));
    }

    /// リダイレクションエントリを読み取り（u64版、後方互換）
    pub fn read_redirection_entry(&self, irq: u8) -> u64 {
        self.read_entry(irq).to_raw()
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
// GSI to I/O APIC Mapping
// ============================================================================

/// GSI (Global System Interrupt) を担当するI/O APICを特定
///
/// 複数のI/O APICが存在する場合、各I/O APICはgsi_baseから始まる
/// 連続したGSI範囲を担当する。この関数は指定されたGSIを
/// 担当するI/O APICのインデックスと、そのI/O APIC内での
/// ローカルIRQ番号を返す。
///
/// # Returns
/// - `Some((ioapic_index, local_irq))` - 担当するI/O APICが見つかった場合
/// - `None` - 該当するI/O APICが見つからない場合
pub fn map_gsi_to_ioapic(gsi: u32) -> Option<(usize, u8)> {
    let io_apics = acpi_driver::io_apics();

    if io_apics.is_empty() {
        // ACPIが初期化されていない場合、デフォルトのI/O APICを使用
        return Some((0, gsi as u8));
    }

    // イテレータを使用した関数型スタイル
    io_apics.iter().enumerate().find_map(|(index, ioapic)| {
        // 次のI/O APICのgsi_baseを取得、なければu32::MAX
        let gsi_end = io_apics
            .get(index + 1)
            .map(|next| next.gsi_base)
            .unwrap_or(u32::MAX);

        // 範囲チェックにRustの範囲パターンを使用
        (ioapic.gsi_base..gsi_end).contains(&gsi).then(|| {
            let local_irq = (gsi - ioapic.gsi_base) as u8;
            (index, local_irq)
        })
    })
}

/// ISA IRQからGSIへの変換（Interrupt Source Override考慮）
///
/// ACPIのInterrupt Source Overrideテーブルを参照し、
/// 標準のISA IRQ番号を実際のGSI番号に変換する。
/// オーバーライドが存在しない場合、ISA IRQはそのままGSIとして扱う。
///
/// # Returns
/// - `(gsi, trigger_mode, polarity)` - 変換後のGSIと割り込み属性
pub fn isa_irq_to_gsi(irq: u8) -> (u32, TriggerMode, Polarity) {
    let overrides = acpi_driver::interrupt_overrides();

    // イテレータを使用した関数型スタイル
    overrides
        .iter()
        .find(|ov| ov.source == irq && ov.bus == 0)
        .map(|ov| {
            let trigger = if ov.trigger_mode == 3 {
                TriggerMode::Level
            } else {
                TriggerMode::Edge
            };
            let polarity = if ov.polarity == 3 {
                Polarity::LowActive
            } else {
                Polarity::HighActive
            };
            (ov.gsi, trigger, polarity)
        })
        .unwrap_or((irq as u32, TriggerMode::Edge, Polarity::HighActive))
}

/// GSIをCPUにルーティング（マルチI/O APIC対応）
///
/// 指定されたGSIを、ACPIテーブルの情報に基づいて適切なI/O APICに
/// ルーティングする。現在の実装では最初のI/O APICのみサポート。
///
/// # Arguments
/// - `gsi` - Global System Interrupt番号
/// - `vector` - 割り込みベクタ
/// - `apic_id` - 送信先CPUのLocal APIC ID
pub fn route_gsi(gsi: u32, vector: u8, apic_id: u8) {
    if let Some((ioapic_index, local_irq)) = map_gsi_to_ioapic(gsi) {
        if ioapic_index == 0 {
            // 現在は最初のI/O APICのみサポート
            let (_, trigger_mode, polarity) = isa_irq_to_gsi(local_irq);
            io_apic().route_irq_typed(local_irq, vector, apic_id, trigger_mode, polarity);
        } else {
            log::warn!(
                "[APIC] GSI {} requires I/O APIC {}, but only I/O APIC 0 is supported\n",
                gsi,
                ioapic_index
            );
        }
    } else {
        log::warn!("[APIC] No I/O APIC found for GSI {}\n", gsi);
    }
}

/// GSIをマスク/アンマスク（マルチI/O APIC対応）
pub fn set_gsi_mask(gsi: u32, masked: bool) {
    if let Some((ioapic_index, local_irq)) = map_gsi_to_ioapic(gsi) {
        if ioapic_index == 0 {
            io_apic().set_irq_mask(local_irq, masked);
        } else {
            log::warn!(
                "[APIC] GSI {} requires I/O APIC {}, but only I/O APIC 0 is supported\n",
                gsi,
                ioapic_index
            );
        }
    }
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

        log::info!("[APIC] CPUID: APIC supported = {}\n", apic_supported);
        apic_supported
    }
}

/// APICを初期化
pub fn init() {
    if !check_apic_support() {
        log::info!("[APIC] APIC not supported, using legacy PIC\n");
        return;
    }

    // 8259 PICを無効化
    disable_pic();

    // ACPIテーブルからAPICアドレスを取得
    let mut local_apic_addr: Option<u64> = None;
    let mut io_apic_config: Option<(u64, u32)> = None; // (address, gsi_base)

    // ACPIが既に初期化されているか確認し、情報を取得
    if let Some(lapic_addr) = acpi_driver::local_apic_address() {
        local_apic_addr = Some(lapic_addr);
        log::info!("[APIC] ACPI: Local APIC at 0x{:X}\n", lapic_addr);
    }

    let io_apics_list = acpi_driver::io_apics();
    if !io_apics_list.is_empty() {
        // 最初のIO APICを使用（一般的なケース）
        let first_io_apic = &io_apics_list[0];
        io_apic_config = Some((first_io_apic.address, first_io_apic.gsi_base));
        log::info!(
            "[APIC] ACPI: I/O APIC at 0x{:X}, GSI base {}\n",
            first_io_apic.address,
            first_io_apic.gsi_base
        );
    }

    // Local APICを初期化（ACPIアドレスまたはデフォルト）
    {
        let mut lapic = local_apic();
        if let Some(addr) = local_apic_addr {
            lapic.set_base_address(addr);
        }
        lapic.init();
    }

    // I/O APICを初期化（ACPIアドレスまたはデフォルト）
    {
        let mut ioapic = io_apic();
        if let Some((addr, gsi_base)) = io_apic_config {
            ioapic.set_base_address(addr, gsi_base);
        }
        ioapic.init();
    }

    // タイマーを較正
    local_apic().calibrate_timer();

    // キーボード割り込みをルーティング（IRQ1 -> vector 0x21）
    io_apic().route_irq(1, 0x21, local_apic().id(), false, false);
    io_apic().set_irq_mask(1, false);

    APIC_ENABLED.store(true, Ordering::SeqCst);

    log::info!("[APIC] APIC system initialized\n");
}

/// 8259 PICを無効化
fn disable_pic() {
    // Use our HAL port wrapper to avoid scattered unsafe usage
    use hal::port_io::PortU8;

    let mut pic1_data: PortU8 = PortU8::new(0x21);
    let mut pic2_data: PortU8 = PortU8::new(0xA1);

    // すべての割り込みをマスク
    pic1_data.write(0xFF);
    pic2_data.write(0xFF);

    log::info!("[APIC] Legacy PIC disabled\n");
}

/// APICタイマーを開始
pub fn start_apic_timer(interval_ms: u32) {
    // タイマー割り込みベクタ: 0x20
    local_apic().start_timer(0x20, interval_ms);
}

/// End of Interrupt（割り込み完了）
pub fn end_of_interrupt() {
    if is_apic_enabled() {
        // Deadlock回避:
        // 割り込みハンドラ内で呼ばれるが、メインスレッドがLocalApicをロックしている間に
        // 割り込みが入るとデッドロックする可能性がある。
        // without_interrupts で囲むことで、ロック取得中の割り込みを防ぐ
        // (注: 本来ISR内はIF=0だが、ネスト許可設定時等の安全策)
        x86_64::instructions::interrupts::without_interrupts(|| {
            local_apic().end_of_interrupt();
        });
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
