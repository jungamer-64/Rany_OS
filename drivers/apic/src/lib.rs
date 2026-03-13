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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use exorust_sync::{IrqPoisonLock, IrqPoisonLockGuard};

// ============================================================================
// APIC定数
// ============================================================================

/// Local APICのデフォルトベースアドレス
const LOCAL_APIC_BASE: u64 = 0xFEE0_0000;

/// I/O APICのデフォルトベースアドレス
const IO_APIC_BASE: u64 = 0xFEC0_0000;

const APIC_PIT_GATE_WAIT_SPINS: usize = 1_000_000;
const APIC_IPI_DELIVERY_WAIT_SPINS: usize = 1_000_000;

fn spin_until<F>(mut ready: F, max_spins: usize) -> bool
where
    F: FnMut() -> bool,
{
    for _ in 0..max_spins {
        if ready() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

// ============================================================================
// Local APIC Register Enum (Type-Safe)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LapicRegister {
    Id = 0x020,
    Version = 0x030,
    Tpr = 0x080,
    Apr = 0x090,
    Ppr = 0x0A0,
    Eoi = 0x0B0,
    Rrd = 0x0C0,
    Ldr = 0x0D0,
    Dfr = 0x0E0,
    Sivr = 0x0F0,
    Esr = 0x280,
    LvtCmci = 0x2F0,
    IcrLow = 0x300,
    IcrHigh = 0x310,
    LvtTimer = 0x320,
    LvtThermal = 0x330,
    LvtPmc = 0x340,
    LvtLint0 = 0x350,
    LvtLint1 = 0x360,
    LvtError = 0x370,
    TimerIcr = 0x380,
    TimerCcr = 0x390,
    TimerDcr = 0x3E0,
}

mod ioapic_reg {
    pub const IOREGSEL: u32 = 0x00;
    pub const IOWIN: u32 = 0x10;
    pub const IOAPICID: u8 = 0x00;
    pub const IOAPICVER: u8 = 0x01;
    pub const IOAPICARB: u8 = 0x02;
    pub const IOREDTBL_BASE: u8 = 0x10;
}

// ============================================================================
// LVT Flags (Type-Safe Bitflags)
// ============================================================================

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LvtFlags: u32 {
        const MASKED = 1 << 16;
        const LEVEL_TRIGGERED = 1 << 15;
        const REMOTE_IRR = 1 << 14;
        const LOW_POLARITY = 1 << 13;
        const DELIVERY_STATUS = 1 << 12;
        const DELIVERY_FIXED = 0b000 << 8;
        const DELIVERY_SMI = 0b010 << 8;
        const DELIVERY_NMI = 0b100 << 8;
        const DELIVERY_INIT = 0b101 << 8;
        const DELIVERY_EXTINT = 0b111 << 8;
        const TIMER_ONESHOT = 0b00 << 17;
        const TIMER_PERIODIC = 0b01 << 17;
        const TIMER_TSC_DEADLINE = 0b10 << 17;
    }
}

impl LvtFlags {
    #[inline]
    pub fn with_vector(self, vector: u8) -> u32 {
        self.bits() | (vector as u32)
    }
}

pub struct LocklessLocalApic {
    base_address: u64,
}

impl LocklessLocalApic {
    const APIC_BASE_MSR: u32 = 0x1B;
    const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
    const ICR_LEVEL_ASSERT: u32 = 1 << 14;
    const ICR_TRIGGER_LEVEL: u32 = 1 << 15;
    const ICR_DEST_ALL_EXCLUDING_SELF: u32 = 0b11 << 18;
    const DELIVERY_STARTUP: u32 = 0b110 << 8;

    pub const fn new(base_address: u64) -> Self {
        Self { base_address }
    }

    #[inline]
    fn reg(&self, reg: LapicRegister) -> hal::MmioReg<u32> {
        hal::MmioReg::new(self.base_address as usize, reg as usize)
    }

    #[inline]
    pub fn read_reg(&self, reg: LapicRegister) -> u32 {
        self.reg(reg).read()
    }

    #[inline]
    pub fn write_reg(&self, reg: LapicRegister, value: u32) {
        self.reg(reg).write(value);
    }

    #[inline]
    unsafe fn read_msr(msr: u32) -> u64 {
        let low: u32;
        let high: u32;
        unsafe {
            core::arch::asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags)
            );
        }
        ((high as u64) << 32) | low as u64
    }

    #[inline]
    unsafe fn write_msr(msr: u32, value: u64) {
        let low = value as u32;
        let high = (value >> 32) as u32;
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") low,
                in("edx") high,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    fn wait_for_delivery(&self, target_apic_id: u32, label: &str) -> bool {
        if !spin_until(
            || (self.read_reg(LapicRegister::IcrLow) & LvtFlags::DELIVERY_STATUS.bits()) == 0,
            APIC_IPI_DELIVERY_WAIT_SPINS,
        ) {
            log::warn!(
                "[APIC] {} delivery timed out for target {} after {} spins",
                label,
                target_apic_id,
                APIC_IPI_DELIVERY_WAIT_SPINS
            );
            return false;
        }
        true
    }

    pub fn id(&self) -> u32 {
        (self.read_reg(LapicRegister::Id) >> 24) & 0xFF
    }

    #[inline]
    pub fn send_eoi(&self) {
        self.write_reg(LapicRegister::Eoi, 0);
    }

    #[inline]
    pub fn set_task_priority(&self, priority: u8) {
        self.write_reg(LapicRegister::Tpr, priority as u32);
    }

    pub fn enable(&self) {
        let spurious = self.read_reg(LapicRegister::Sivr);
        self.write_reg(LapicRegister::Sivr, spurious | 0x100);
    }

    pub fn init_current_cpu(&self) {
        unsafe {
            let apic_base = Self::read_msr(Self::APIC_BASE_MSR);
            if (apic_base & Self::APIC_GLOBAL_ENABLE) == 0 {
                Self::write_msr(Self::APIC_BASE_MSR, apic_base | Self::APIC_GLOBAL_ENABLE);
            }
        }

        self.write_reg(LapicRegister::Sivr, 0xFF | 0x100);
        self.write_reg(LapicRegister::Tpr, 0);
        self.write_reg(LapicRegister::LvtTimer, LvtFlags::MASKED.bits());
        self.write_reg(LapicRegister::LvtThermal, LvtFlags::MASKED.bits());
        self.write_reg(LapicRegister::LvtPmc, LvtFlags::MASKED.bits());
        self.write_reg(LapicRegister::LvtLint0, LvtFlags::MASKED.bits());
        self.write_reg(LapicRegister::LvtLint1, LvtFlags::MASKED.bits());
        self.write_reg(LapicRegister::LvtError, LvtFlags::MASKED.bits());
        self.write_reg(LapicRegister::Esr, 0);
        self.write_reg(LapicRegister::Esr, 0);
        self.send_eoi();
    }

    pub fn send_init(&self, target_apic_id: u32) {
        self.write_reg(LapicRegister::IcrHigh, target_apic_id << 24);
        self.write_reg(
            LapicRegister::IcrLow,
            LvtFlags::DELIVERY_INIT.bits() | Self::ICR_LEVEL_ASSERT | Self::ICR_TRIGGER_LEVEL,
        );
        if !self.wait_for_delivery(target_apic_id, "init-assert") {
            return;
        }

        self.write_reg(
            LapicRegister::IcrLow,
            LvtFlags::DELIVERY_INIT.bits() | Self::ICR_TRIGGER_LEVEL,
        );
        let _ = self.wait_for_delivery(target_apic_id, "init-deassert");
    }

    pub fn send_sipi(&self, target_apic_id: u32, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, target_apic_id << 24);
        self.write_reg(
            LapicRegister::IcrLow,
            Self::DELIVERY_STARTUP | (vector as u32),
        );
        let _ = self.wait_for_delivery(target_apic_id, "sipi");
    }

    pub fn send_ipi(&self, target_apic_id: u32, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, target_apic_id << 24);
        self.write_reg(
            LapicRegister::IcrLow,
            LvtFlags::DELIVERY_FIXED.with_vector(vector),
        );
        let _ = self.wait_for_delivery(target_apic_id, "ipi");
    }

    pub fn broadcast_ipi_excluding_self(&self, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, 0);
        self.write_reg(
            LapicRegister::IcrLow,
            (vector as u32) | Self::ICR_DEST_ALL_EXCLUDING_SELF | LvtFlags::DELIVERY_FIXED.bits(),
        );
        let _ = self.wait_for_delivery(u32::MAX, "broadcast");
    }
}

// ============================================================================
// Interrupt Trigger and Polarity
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriggerMode {
    #[default]
    Edge,
    Level,
}

impl TriggerMode {
    #[inline]
    pub const fn is_level(self) -> bool {
        matches!(self, Self::Level)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Polarity {
    #[default]
    HighActive,
    LowActive,
}

impl Polarity {
    #[inline]
    pub const fn is_low_active(self) -> bool {
        matches!(self, Self::LowActive)
    }
}

// ============================================================================
// Timer Divisor Enum
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerDivisor {
    Div1 = 0b1011,
    Div2 = 0b0000,
    Div4 = 0b0001,
    Div8 = 0b0010,
    Div16 = 0b0011,
    Div32 = 0b1000,
    Div64 = 0b1001,
    Div128 = 0b1010,
}

// ============================================================================
// Local APIC
// ============================================================================

pub struct LocalApic {
    base_address: u64,
    is_enabled: AtomicBool,
    ticks_per_ms: AtomicU64,
}

impl LocalApic {
    pub const fn new() -> Self {
        Self {
            base_address: LOCAL_APIC_BASE,
            is_enabled: AtomicBool::new(false),
            ticks_per_ms: AtomicU64::new(0),
        }
    }

    pub fn set_base_address(&mut self, addr: u64) {
        self.base_address = addr;
    }

    #[inline]
    fn reg(&self, reg: LapicRegister) -> hal::MmioReg<u32> {
        hal::MmioReg::new(self.base_address as usize, reg as usize)
    }

    #[inline]
    fn read_reg(&self, reg: LapicRegister) -> u32 {
        self.reg(reg).read()
    }
    #[inline]
    fn write_reg(&self, reg: LapicRegister, value: u32) {
        self.reg(reg).write(value);
    }
    #[inline]
    fn write_lvt(&self, reg: LapicRegister, flags: LvtFlags) {
        self.write_reg(reg, flags.bits());
    }
    #[inline]
    fn write_lvt_vector(&self, reg: LapicRegister, flags: LvtFlags, vector: u8) {
        self.write_reg(reg, flags.with_vector(vector));
    }
    #[inline]
    fn set_timer_divisor(&self, divisor: TimerDivisor) {
        self.write_reg(LapicRegister::TimerDcr, divisor as u32);
    }

    pub fn init(&self) {
        self.write_reg(LapicRegister::Sivr, 0xFF | (1 << 8));
        self.write_reg(LapicRegister::Tpr, 0);
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
        self.write_reg(LapicRegister::Esr, 0);
        self.write_reg(LapicRegister::Esr, 0);
        self.send_eoi();
        self.is_enabled.store(true, Ordering::SeqCst);
        log::info!(
            "[APIC] Local APIC initialized at 0x{:X}\n",
            self.base_address
        );
    }

    #[inline]
    pub fn send_eoi(&self) {
        self.write_reg(LapicRegister::Eoi, 0);
    }

    pub fn calibrate_timer(&self) {
        use hal::port_io::PortU8;
        let mut pit_cmd = PortU8::new(0x43);
        let mut pit_data = PortU8::new(0x42);
        let mut pit_gate = PortU8::new(0x61);
        let gate_val = pit_gate.read();
        pit_gate.write(gate_val | 1);
        pit_cmd.write(0xB0);
        let count = 11932_u16;
        pit_data.write((count & 0xFF) as u8);
        pit_data.write((count >> 8) as u8);
        self.set_timer_divisor(TimerDivisor::Div16);
        self.write_reg(LapicRegister::TimerIcr, 0xFFFFFFFF);
        if !spin_until(|| (pit_gate.read() & 0x20) != 0, APIC_PIT_GATE_WAIT_SPINS) {
            pit_gate.write(gate_val & !1);
            self.write_lvt(LapicRegister::LvtTimer, LvtFlags::MASKED);
            log::warn!(
                "[APIC] PIT gate wait timed out during LAPIC timer calibration after {} spins",
                APIC_PIT_GATE_WAIT_SPINS
            );
            return;
        }
        let current_count = self.read_reg(LapicRegister::TimerCcr);
        let elapsed = 0xFFFFFFFF - current_count;
        pit_gate.write(gate_val & !1);
        self.write_lvt(LapicRegister::LvtTimer, LvtFlags::MASKED);
        let ticks_per_ms = elapsed / 10;
        self.ticks_per_ms
            .store(ticks_per_ms as u64, Ordering::SeqCst);
        log::info!("[APIC] Timer calibrated: {} ticks/ms\n", ticks_per_ms);
    }

    pub fn start_timer(&self, vector: u8, interval_ms: u32) {
        let ticks_per_ms = self.ticks_per_ms.load(Ordering::SeqCst);
        if ticks_per_ms == 0 {
            return;
        }
        let count = ticks_per_ms as u32 * interval_ms;
        self.set_timer_divisor(TimerDivisor::Div16);
        self.write_lvt_vector(LapicRegister::LvtTimer, LvtFlags::TIMER_PERIODIC, vector);
        self.write_reg(LapicRegister::TimerIcr, count);
    }

    pub fn stop_timer(&self) {
        self.write_lvt(LapicRegister::LvtTimer, LvtFlags::MASKED);
        self.write_reg(LapicRegister::TimerIcr, 0);
    }
    #[inline]
    pub fn end_of_interrupt(&self) {
        self.send_eoi();
    }
    pub fn id(&self) -> u8 {
        ((self.read_reg(LapicRegister::Id) >> 24) & 0xFF) as u8
    }
    pub fn version(&self) -> u8 {
        (self.read_reg(LapicRegister::Version) & 0xFF) as u8
    }

    pub fn send_ipi(&self, target_apic_id: u8, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, (target_apic_id as u32) << 24);
        self.write_reg(
            LapicRegister::IcrLow,
            LvtFlags::DELIVERY_FIXED.with_vector(vector),
        );
        if !spin_until(
            || (self.read_reg(LapicRegister::IcrLow) & LvtFlags::DELIVERY_STATUS.bits()) == 0,
            APIC_IPI_DELIVERY_WAIT_SPINS,
        ) {
            log::warn!(
                "[APIC] IPI delivery timed out for target {} vector {} after {} spins",
                target_apic_id,
                vector,
                APIC_IPI_DELIVERY_WAIT_SPINS
            );
        }
    }

    pub fn send_ipi_all_excluding_self(&self, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, 0);
        self.write_reg(
            LapicRegister::IcrLow,
            (vector as u32) | (0b11 << 18) | LvtFlags::DELIVERY_FIXED.bits(),
        );
    }

    pub fn send_init(&self, target_apic_id: u8) {
        self.write_reg(LapicRegister::IcrHigh, (target_apic_id as u32) << 24);
        self.write_reg(
            LapicRegister::IcrLow,
            (LvtFlags::DELIVERY_INIT | LvtFlags::LEVEL_TRIGGERED).bits(),
        );
        if !spin_until(
            || (self.read_reg(LapicRegister::IcrLow) & LvtFlags::DELIVERY_STATUS.bits()) == 0,
            APIC_IPI_DELIVERY_WAIT_SPINS,
        ) {
            log::warn!(
                "[APIC] INIT delivery timed out for target {} after {} spins",
                target_apic_id,
                APIC_IPI_DELIVERY_WAIT_SPINS
            );
        }
    }

    pub fn send_sipi(&self, target_apic_id: u8, vector: u8) {
        self.write_reg(LapicRegister::IcrHigh, (target_apic_id as u32) << 24);
        self.write_reg(LapicRegister::IcrLow, (vector as u32) | (0b110 << 8));
        if !spin_until(
            || (self.read_reg(LapicRegister::IcrLow) & LvtFlags::DELIVERY_STATUS.bits()) == 0,
            APIC_IPI_DELIVERY_WAIT_SPINS,
        ) {
            log::warn!(
                "[APIC] SIPI delivery timed out for target {} vector {} after {} spins",
                target_apic_id,
                vector,
                APIC_IPI_DELIVERY_WAIT_SPINS
            );
        }
    }
}

// ============================================================================
// I/O APIC Redirection Entry
// ============================================================================

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RedirectionFlags: u32 {
        const MASKED = 1 << 16;
        const LEVEL_TRIGGERED = 1 << 15;
        const REMOTE_IRR = 1 << 14;
        const LOW_POLARITY = 1 << 13;
        const DELIVERY_STATUS = 1 << 12;
        const DESTINATION_LOGICAL = 1 << 11;
        const DELIVERY_FIXED = 0b000 << 8;
        const DELIVERY_LOWEST = 0b001 << 8;
        const DELIVERY_SMI = 0b010 << 8;
        const DELIVERY_NMI = 0b100 << 8;
        const DELIVERY_INIT = 0b101 << 8;
        const DELIVERY_EXTINT = 0b111 << 8;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RedirectionEntry {
    low: u32,
    high: u32,
}

impl RedirectionEntry {
    #[inline]
    pub const fn new(vector: u8) -> Self {
        Self {
            low: vector as u32,
            high: 0,
        }
    }
    #[inline]
    pub const fn masked() -> Self {
        Self {
            low: RedirectionFlags::MASKED.bits(),
            high: 0,
        }
    }
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self {
            low: raw as u32,
            high: (raw >> 32) as u32,
        }
    }
    #[inline]
    pub const fn to_raw(self) -> u64 {
        (self.low as u64) | ((self.high as u64) << 32)
    }
    #[inline]
    pub const fn destination(mut self, apic_id: u8) -> Self {
        self.high = (apic_id as u32) << 24;
        self
    }
    #[inline]
    pub const fn level_triggered(mut self) -> Self {
        self.low |= RedirectionFlags::LEVEL_TRIGGERED.bits();
        self
    }
    #[inline]
    pub const fn edge_triggered(mut self) -> Self {
        self.low &= !RedirectionFlags::LEVEL_TRIGGERED.bits();
        self
    }
    #[inline]
    pub const fn low_active(mut self) -> Self {
        self.low |= RedirectionFlags::LOW_POLARITY.bits();
        self
    }
    #[inline]
    pub const fn high_active(mut self) -> Self {
        self.low &= !RedirectionFlags::LOW_POLARITY.bits();
        self
    }
    #[inline]
    pub const fn mask(mut self) -> Self {
        self.low |= RedirectionFlags::MASKED.bits();
        self
    }
    #[inline]
    pub const fn unmask(mut self) -> Self {
        self.low &= !RedirectionFlags::MASKED.bits();
        self
    }
    #[inline]
    pub const fn is_masked(self) -> bool {
        (self.low & RedirectionFlags::MASKED.bits()) != 0
    }
    #[inline]
    pub const fn vector(self) -> u8 {
        (self.low & 0xFF) as u8
    }
    #[inline]
    pub const fn low(self) -> u32 {
        self.low
    }
    #[inline]
    pub const fn high(self) -> u32 {
        self.high
    }
    #[inline]
    #[must_use]
    pub const fn with_trigger_mode(self, mode: TriggerMode) -> Self {
        match mode {
            TriggerMode::Edge => self.edge_triggered(),
            TriggerMode::Level => self.level_triggered(),
        }
    }
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

pub struct IoApic {
    base_address: u64,
    global_irq_base: u32,
}

impl IoApic {
    pub const fn new() -> Self {
        Self {
            base_address: IO_APIC_BASE,
            global_irq_base: 0,
        }
    }
    pub fn set_base_address(&mut self, addr: u64, irq_base: u32) {
        self.base_address = addr;
        self.global_irq_base = irq_base;
    }
    #[inline]
    fn select_reg(&self) -> hal::MmioReg<u32> {
        hal::MmioReg::from_addr(self.base_address as usize + ioapic_reg::IOREGSEL as usize)
    }
    #[inline]
    fn data_reg(&self) -> hal::MmioReg<u32> {
        hal::MmioReg::from_addr(self.base_address as usize + ioapic_reg::IOWIN as usize)
    }
    #[inline]
    fn read(&self, reg: u8) -> u32 {
        self.select_reg().write(reg as u32);
        self.data_reg().read()
    }
    #[inline]
    fn write(&self, reg: u8, value: u32) {
        self.select_reg().write(reg as u32);
        self.data_reg().write(value);
    }
    pub fn init(&self) {
        let max = self.max_redirection_entries();
        for i in 0..=max {
            self.set_irq_mask(i, true);
        }
        log::info!("[APIC] I/O APIC initialized at 0x{:X}\n", self.base_address);
    }
    pub fn id(&self) -> u8 {
        ((self.read(ioapic_reg::IOAPICID) >> 24) & 0xF) as u8
    }
    pub fn version(&self) -> u8 {
        (self.read(ioapic_reg::IOAPICVER) & 0xFF) as u8
    }
    pub fn max_redirection_entries(&self) -> u8 {
        ((self.read(ioapic_reg::IOAPICVER) >> 16) & 0xFF) as u8
    }
    pub fn write_entry(&self, irq: u8, entry: RedirectionEntry) {
        let reg = ioapic_reg::IOREDTBL_BASE + irq * 2;
        self.write(reg, entry.low() | RedirectionFlags::MASKED.bits());
        self.write(reg + 1, entry.high());
        self.write(reg, entry.low());
    }
    pub fn read_entry(&self, irq: u8) -> RedirectionEntry {
        let reg = ioapic_reg::IOREDTBL_BASE + irq * 2;
        let low = self.read(reg);
        let high = self.read(reg + 1);
        RedirectionEntry::from_raw((low as u64) | ((high as u64) << 32))
    }
    pub fn route_irq(&self, irq: u8, vector: u8, apic_id: u8, level: bool, low: bool) {
        let mut entry = RedirectionEntry::new(vector).destination(apic_id);
        if level {
            entry = entry.level_triggered();
        }
        if low {
            entry = entry.low_active();
        }
        self.write_entry(irq, entry);
    }
    pub fn route_irq_typed(&self, irq: u8, vec: u8, id: u8, mode: TriggerMode, pol: Polarity) {
        let entry = RedirectionEntry::new(vec)
            .destination(id)
            .with_trigger_mode(mode)
            .with_polarity(pol);
        self.write_entry(irq, entry);
    }
    pub fn set_irq_mask(&self, irq: u8, masked: bool) {
        let entry = self.read_entry(irq);
        let new = if masked { entry.mask() } else { entry.unmask() };
        self.write_entry(irq, new);
    }
    pub fn read_redirection_entry(&self, irq: u8) -> u64 {
        self.read_entry(irq).to_raw()
    }
}

// ============================================================================
// グローバルAPICインスタンス
// ============================================================================

static LOCAL_APIC: IrqPoisonLock<LocalApic> = IrqPoisonLock::new(LocalApic::new());
static IO_APIC: IrqPoisonLock<IoApic> = IrqPoisonLock::new(IoApic::new());
static APIC_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn local_apic() -> IrqPoisonLockGuard<'static, LocalApic> {
    LOCAL_APIC.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn io_apic() -> IrqPoisonLockGuard<'static, IoApic> {
    IO_APIC.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn is_apic_enabled() -> bool {
    APIC_ENABLED.load(Ordering::SeqCst)
}

pub fn map_gsi_to_ioapic(gsi: u32) -> Option<(usize, u8)> {
    let io_apics = acpi_driver::io_apics();
    if io_apics.is_empty() {
        return Some((0, gsi as u8));
    }
    io_apics.iter().enumerate().find_map(|(index, ioapic)| {
        let gsi_end = io_apics
            .get(index + 1)
            .map(|next| next.gsi_base)
            .unwrap_or(u32::MAX);
        (ioapic.gsi_base..gsi_end)
            .contains(&gsi)
            .then(|| (index, (gsi - ioapic.gsi_base) as u8))
    })
}

pub fn isa_irq_to_gsi(irq: u8) -> (u32, TriggerMode, Polarity) {
    let overrides = acpi_driver::interrupt_overrides();
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

pub fn route_gsi(gsi: u32, vector: u8, apic_id: u8) {
    if let Some((ioapic_index, local_irq)) = map_gsi_to_ioapic(gsi) {
        if ioapic_index == 0 {
            let (_, trigger_mode, polarity) = isa_irq_to_gsi(local_irq);
            io_apic().route_irq_typed(local_irq, vector, apic_id, trigger_mode, polarity);
        }
    }
}

pub fn set_gsi_mask(gsi: u32, masked: bool) {
    if let Some((ioapic_index, local_irq)) = map_gsi_to_ioapic(gsi) {
        if ioapic_index == 0 {
            io_apic().set_irq_mask(local_irq, masked);
        }
    }
}

pub fn check_apic_support() -> bool {
    unsafe {
        let edx: u32;
        let rbx_save: u64;
        core::arch::asm!("mov {0}, rbx", "mov eax, 1", "xor ecx, ecx", "cpuid", "mov {1:e}, edx", "mov rbx, {0}", out(reg) rbx_save, out(reg) edx, out("eax") _, out("ecx") _, out("edx") _, options(nostack, preserves_flags));
        let _ = rbx_save;
        (edx & (1 << 9)) != 0
    }
}

pub fn init() {
    if !check_apic_support() {
        return;
    }
    disable_pic();
    let mut local_apic_addr: Option<u64> = None;
    let mut io_apic_config: Option<(u64, u32)> = None;
    if let Some(lapic_addr) = acpi_driver::local_apic_address() {
        local_apic_addr = Some(lapic_addr);
    }
    let io_apics_list = acpi_driver::io_apics();
    if !io_apics_list.is_empty() {
        let first_io_apic = &io_apics_list[0];
        io_apic_config = Some((first_io_apic.address, first_io_apic.gsi_base));
    }
    {
        let mut lapic = local_apic();
        if let Some(addr) = local_apic_addr {
            lapic.set_base_address(addr);
        }
        lapic.init();
    }
    {
        let mut ioapic = io_apic();
        if let Some((addr, gsi_base)) = io_apic_config {
            ioapic.set_base_address(addr, gsi_base);
        }
        ioapic.init();
    }
    local_apic().calibrate_timer();
    io_apic().route_irq(1, 0x21, local_apic().id(), false, false);
    io_apic().set_irq_mask(1, false);
    APIC_ENABLED.store(true, Ordering::SeqCst);
}

fn disable_pic() {
    use hal::port_io::PortU8;
    let mut pic1_data: PortU8 = PortU8::new(0x21);
    let mut pic2_data: PortU8 = PortU8::new(0xA1);
    pic1_data.write(0xFF);
    pic2_data.write(0xFF);
}

pub fn start_apic_timer_on_vector(vector: u8, interval_ms: u32) {
    local_apic().start_timer(vector, interval_ms);
}

pub fn start_apic_timer(interval_ms: u32) {
    start_apic_timer_on_vector(0x20, interval_ms);
}

pub fn end_of_interrupt() {
    if is_apic_enabled() {
        // IrqPoisonLock already handles interrupts (it disables them),
        // so we don't strictly need without_interrupts here, but keeping it
        // for extra safety if the lock is somehow already held.
        x86_64::instructions::interrupts::without_interrupts(|| {
            local_apic().end_of_interrupt();
        });
    }
}

pub struct ApicStats {
    pub local_apic_id: u8,
    pub local_apic_version: u8,
    pub io_apic_id: u8,
    pub io_apic_version: u8,
    pub max_redirection_entries: u8,
    pub ticks_per_ms: u64,
}

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
