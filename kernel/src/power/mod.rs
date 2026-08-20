//! 電源管理サブシステム
//!
//! ACPI電源管理機能を実装し、スリープ状態、シャットダウン、
//! 省電力モードなどを制御する。
use crate::io::port_io::{PortU8, PortU16, PortU32};
use crate::sync::PoisonLock;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// 電源状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerState {
    /// S0: フル稼働
    Working = 0,
    /// S1: スタンバイ (CPU停止、メモリ維持)
    Standby = 1,
    /// S2: 深いスタンバイ (CPUパワーオフ)
    DeepStandby = 2,
    /// S3: サスペンド・トゥ・RAM
    SuspendToRam = 3,
    /// S4: ハイバネート (サスペンド・トゥ・ディスク)
    Hibernate = 4,
    /// S5: ソフトオフ
    SoftOff = 5,
}

impl PowerState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Working),
            1 => Some(Self::Standby),
            2 => Some(Self::DeepStandby),
            3 => Some(Self::SuspendToRam),
            4 => Some(Self::Hibernate),
            5 => Some(Self::SoftOff),
            _ => None,
        }
    }
}

/// CPUパワー状態 (C-States)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuPowerState {
    Active = 0,
    Halt = 1,
    StopClock = 2,
    DeepSleep = 3,
}

/// デバイスパワー状態 (D-States)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DevicePowerState {
    FullOn = 0,
    LowPower1 = 1,
    LowPower2 = 2,
    SoftOff = 3,
    HardOff = 4,
}

mod pm1_control {
    pub const SCI_EN: u16 = 1 << 0;
    pub const SLP_TYP_SHIFT: u16 = 10;
    pub const SLP_EN: u16 = 1 << 13;
}

mod pm1_status {
    pub const TMR_STS: u16 = 1 << 0;
    pub const PWRBTN_STS: u16 = 1 << 8;
    pub const SLPBTN_STS: u16 = 1 << 9;
    pub const RTC_STS: u16 = 1 << 10;
}

/// ACPI電源管理設定
#[derive(Debug, Clone)]
pub struct AcpiPmConfig {
    pub pm1a_evt_blk: u16,
    pub pm1b_evt_blk: u16,
    pub pm1a_cnt_blk: u16,
    pub pm1b_cnt_blk: u16,
    pub pm2_cnt_blk: u16,
    pub pm_tmr_blk: u16,
    pub gpe0_blk: u16,
    pub gpe1_blk: u16,
    pub pm1_evt_len: u8,
    pub pm1_cnt_len: u8,
    pub pm_tmr_32bit: bool,
    pub s5_slp_typ_a: u8,
    pub s5_slp_typ_b: u8,
}

impl AcpiPmConfig {
    pub const fn default() -> Self {
        Self {
            pm1a_evt_blk: 0x600,
            pm1b_evt_blk: 0,
            pm1a_cnt_blk: 0x604,
            pm1b_cnt_blk: 0,
            pm2_cnt_blk: 0,
            pm_tmr_blk: 0x608,
            gpe0_blk: 0x620,
            gpe1_blk: 0,
            pm1_evt_len: 4,
            pm1_cnt_len: 2,
            pm_tmr_32bit: true,
            s5_slp_typ_a: 0,
            s5_slp_typ_b: 0,
        }
    }
}

/// 電源管理統計
pub struct PowerStats {
    pub current_state: AtomicU8,
    pub state_transitions: AtomicU64,
    pub last_transition: AtomicU64,
    pub power_button_presses: AtomicU64,
    pub sleep_button_presses: AtomicU64,
}

impl PowerStats {
    pub const fn new() -> Self {
        Self {
            current_state: AtomicU8::new(PowerState::Working as u8),
            state_transitions: AtomicU64::new(0),
            last_transition: AtomicU64::new(0),
            power_button_presses: AtomicU64::new(0),
            sleep_button_presses: AtomicU64::new(0),
        }
    }
}

/// 電源管理サブシステム
pub struct PowerManager {
    config: PoisonLock<AcpiPmConfig>,
    stats: PowerStats,
    sci_enabled: PoisonLock<bool>,
}

impl PowerManager {
    pub const fn new() -> Self {
        Self {
            config: PoisonLock::new(AcpiPmConfig::default()),
            stats: PowerStats::new(),
            sci_enabled: PoisonLock::new(false),
        }
    }

    pub fn set_config(&self, config: AcpiPmConfig) {
        *self.config.lock().unwrap_or_else(|e| e.into_inner()) = config;
    }

    pub fn enable_sci(&self) {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());

        if config.pm1a_cnt_blk != 0 {
            let mut port: PortU16 = PortU16::new(config.pm1a_cnt_blk);
            let value = port.read();
            port.write(value | pm1_control::SCI_EN);
        }

        *self.sci_enabled.lock().unwrap_or_else(|e| e.into_inner()) = true;
    }

    pub fn read_pm1_status(&self) -> u16 {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());

        if config.pm1a_evt_blk == 0 {
            return 0;
        }

        let mut port: PortU16 = PortU16::new(config.pm1a_evt_blk);
        port.read()
    }

    pub fn clear_pm1_status(&self, bits: u16) {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());

        if config.pm1a_evt_blk != 0 {
            let mut port: PortU16 = PortU16::new(config.pm1a_evt_blk);
            port.write(bits);
        }
    }

    pub fn read_pm_timer(&self) -> u32 {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());

        if config.pm_tmr_blk == 0 {
            return 0;
        }

        let mut port: PortU32 = PortU32::new(config.pm_tmr_blk);
        let value = port.read();

        if config.pm_tmr_32bit {
            value
        } else {
            value & 0x00FFFFFF
        }
    }

    pub fn enter_sleep_state(&self, state: PowerState) -> Result<(), &'static str> {
        match state {
            PowerState::Working => Ok(()),
            PowerState::Standby => {
                unsafe {
                    core::arch::asm!("hlt");
                }
                Ok(())
            }
            PowerState::SoftOff => self.shutdown(),
            _ => Err("Sleep state not supported"),
        }
    }

    pub fn shutdown(&self) -> Result<(), &'static str> {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());

        if config.pm1a_cnt_blk == 0 {
            return Err("PM1a control block not available");
        }

        let mut port: PortU16 = PortU16::new(0x604);
        port.write(0x2000_u16);

        let slp_typ_a = (config.s5_slp_typ_a as u16) << pm1_control::SLP_TYP_SHIFT;
        let value = slp_typ_a | pm1_control::SLP_EN;

        let mut port: PortU16 = PortU16::new(config.pm1a_cnt_blk);
        port.write(value);

        Err("Shutdown failed")
    }

    pub fn reboot(&self) -> Result<(), &'static str> {
        let mut cmd_port: PortU8 = PortU8::new(0x64);
        for _ in 0..100000 {
            if cmd_port.read() & 0x02 == 0 {
                break;
            }
        }
        cmd_port.write(0xFE);
        Err("Reboot failed")
    }

    pub fn handle_power_button(&self) {
        self.stats
            .power_button_presses
            .fetch_add(1, Ordering::Relaxed);
        self.clear_pm1_status(pm1_status::PWRBTN_STS);
    }

    pub fn handle_sleep_button(&self) {
        self.stats
            .sleep_button_presses
            .fetch_add(1, Ordering::Relaxed);
        self.clear_pm1_status(pm1_status::SLPBTN_STS);
    }

    pub fn handle_sci(&self) {
        let status = self.read_pm1_status();

        if status & pm1_status::PWRBTN_STS != 0 {
            self.handle_power_button();
        }

        if status & pm1_status::SLPBTN_STS != 0 {
            self.handle_sleep_button();
        }

        if status & pm1_status::RTC_STS != 0 {
            self.clear_pm1_status(pm1_status::RTC_STS);
        }

        if status & pm1_status::TMR_STS != 0 {
            self.clear_pm1_status(pm1_status::TMR_STS);
        }
    }

    pub fn current_state(&self) -> PowerState {
        PowerState::from_u8(self.stats.current_state.load(Ordering::Relaxed))
            .unwrap_or(PowerState::Working)
    }

    pub fn stats(&self) -> &PowerStats {
        &self.stats
    }
}

pub struct CpuIdle {
    current_state: AtomicU8,
    c1_count: AtomicU64,
    c2_count: AtomicU64,
    c3_count: AtomicU64,
}

impl CpuIdle {
    pub const fn new() -> Self {
        Self {
            current_state: AtomicU8::new(CpuPowerState::Active as u8),
            c1_count: AtomicU64::new(0),
            c2_count: AtomicU64::new(0),
            c3_count: AtomicU64::new(0),
        }
    }

    pub fn idle(&self) {
        self.current_state
            .store(CpuPowerState::Halt as u8, Ordering::Relaxed);
        self.c1_count.fetch_add(1, Ordering::Relaxed);
        unsafe {
            core::arch::asm!("sti", "hlt",);
        }
        self.current_state
            .store(CpuPowerState::Active as u8, Ordering::Relaxed);
    }

    pub fn mwait_idle(&self, _hint: u32) {
        self.current_state
            .store(CpuPowerState::Halt as u8, Ordering::Relaxed);
        self.c1_count.fetch_add(1, Ordering::Relaxed);
        unsafe {
            core::arch::asm!("sti", "hlt",);
        }
        self.current_state
            .store(CpuPowerState::Active as u8, Ordering::Relaxed);
    }

    pub fn current_state(&self) -> CpuPowerState {
        match self.current_state.load(Ordering::Relaxed) {
            0 => CpuPowerState::Active,
            1 => CpuPowerState::Halt,
            2 => CpuPowerState::StopClock,
            3 => CpuPowerState::DeepSleep,
            _ => CpuPowerState::Active,
        }
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.c1_count.load(Ordering::Relaxed),
            self.c2_count.load(Ordering::Relaxed),
            self.c3_count.load(Ordering::Relaxed),
        )
    }
}

static POWER_MANAGER: PowerManager = PowerManager::new();
static CPU_IDLE: CpuIdle = CpuIdle::new();

pub fn power_manager() -> &'static PowerManager {
    &POWER_MANAGER
}

pub fn cpu_idle() -> &'static CpuIdle {
    &CPU_IDLE
}

pub fn init() {}

pub fn shutdown() -> ! {
    let _ = POWER_MANAGER.shutdown();
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

pub fn reboot() -> ! {
    let _ = POWER_MANAGER.reboot();
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

pub fn idle() {
    CPU_IDLE.idle();
}
