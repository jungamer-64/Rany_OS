//! 温度管理システム
//!
//! CPUおよびシステムの温度監視・制御
//! - 温度センサー読み取り
//! - スロットリング制御
//! - ファン制御
//! - サーマルゾーン管理

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// =============================================================================
// 定数
// =============================================================================

/// 温度読み取りなし
mod impls;
pub use impls::*;
const TEMP_INVALID: i32 = i32::MIN;

/// デフォルトのパッシブスロットリング温度（ミリ摂氏度）
const DEFAULT_PASSIVE_TEMP: i32 = 80_000;

/// デフォルトのクリティカル温度（ミリ摂氏度）
const DEFAULT_CRITICAL_TEMP: i32 = 100_000;

/// デフォルトのホット温度（ミリ摂氏度）
const DEFAULT_HOT_TEMP: i32 = 90_000;

// =============================================================================
// サーマルエラー
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalError {
    /// センサーが見つからない
    SensorNotFound,
    /// 読み取り失敗
    ReadFailed,
    /// サポートされていない
    NotSupported,
    /// 設定エラー
    ConfigError,
    /// オーバーヒート
    Overheat,
}

pub type ThermalResult<T> = Result<T, ThermalError>;

// =============================================================================
// 温度単位
// =============================================================================

/// 温度（ミリ摂氏度）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Temperature(i32);

impl Temperature {
    pub const fn from_millicelsius(mc: i32) -> Self {
        Self(mc)
    }

    pub const fn from_celsius(c: i32) -> Self {
        Self(c * 1000)
    }

    pub const fn millicelsius(&self) -> i32 {
        self.0
    }

    pub const fn celsius(&self) -> i32 {
        self.0 / 1000
    }

    pub const fn invalid() -> Self {
        Self(TEMP_INVALID)
    }

    pub const fn is_valid(&self) -> bool {
        self.0 != TEMP_INVALID
    }
}

// =============================================================================
// 温度センサー
// =============================================================================

/// センサータイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorType {
    /// CPU温度
    Cpu,
    /// CPUパッケージ温度
    CpuPackage,
    /// CPUコア温度
    CpuCore(u8),
    /// GPU温度
    Gpu,
    /// システム温度
    System,
    /// メモリ温度
    Memory,
    /// NVMe温度
    Nvme,
    /// 電源温度
    Power,
    /// カスタム
    Custom,
}

/// 温度センサー情報
#[derive(Debug, Clone)]
pub struct ThermalSensor {
    pub id: u32,
    pub name: String,
    pub sensor_type: SensorType,
    pub current: Temperature,
    pub max_observed: Temperature,
    pub min_observed: Temperature,
    pub critical_temp: Temperature,
    pub hot_temp: Temperature,
    pub passive_temp: Temperature,
}

impl ThermalSensor {
    pub fn new(id: u32, name: String, sensor_type: SensorType) -> Self {
        Self {
            id,
            name,
            sensor_type,
            current: Temperature::invalid(),
            max_observed: Temperature::from_millicelsius(i32::MIN),
            min_observed: Temperature::from_millicelsius(i32::MAX),
            critical_temp: Temperature::from_millicelsius(DEFAULT_CRITICAL_TEMP),
            hot_temp: Temperature::from_millicelsius(DEFAULT_HOT_TEMP),
            passive_temp: Temperature::from_millicelsius(DEFAULT_PASSIVE_TEMP),
        }
    }

    pub fn update(&mut self, temp: Temperature) {
        self.current = temp;

        if temp.is_valid() {
            if temp.millicelsius() > self.max_observed.millicelsius() {
                self.max_observed = temp;
            }
            if temp.millicelsius() < self.min_observed.millicelsius() {
                self.min_observed = temp;
            }
        }
    }

    pub fn is_critical(&self) -> bool {
        self.current.is_valid() && self.current >= self.critical_temp
    }

    pub fn is_hot(&self) -> bool {
        self.current.is_valid() && self.current >= self.hot_temp
    }

    pub fn needs_throttle(&self) -> bool {
        self.current.is_valid() && self.current >= self.passive_temp
    }
}

// =============================================================================
// CPU温度読み取り
// =============================================================================

/// MSR定数
mod msr {
    pub const IA32_THERM_STATUS: u32 = 0x19C;
    pub const IA32_PACKAGE_THERM_STATUS: u32 = 0x1B1;
    pub const IA32_TEMPERATURE_TARGET: u32 = 0x1A2;
}

/// CPU温度ドライバ
pub struct CpuThermalDriver {
    tj_max: i32, // TJunction max（ミリ摂氏度）
    num_cores: u32,
}

impl CpuThermalDriver {
    pub fn new() -> Self {
        Self {
            tj_max: 100_000, // デフォルト100℃
            num_cores: 0,
        }
    }

    /// 初期化
    pub fn init(&mut self) -> ThermalResult<()> {
        // TJmaxを読み取り
        let target = self.read_msr(msr::IA32_TEMPERATURE_TARGET)?;
        let tj_target = ((target >> 16) & 0xFF) as i32;
        if tj_target > 0 {
            self.tj_max = tj_target * 1000;
        }

        // コア数を検出（CPUID使用）
        self.num_cores = self.detect_core_count();

        Ok(())
    }

    /// パッケージ温度を読み取り
    pub fn read_package_temp(&self) -> ThermalResult<Temperature> {
        let status = self.read_msr(msr::IA32_PACKAGE_THERM_STATUS)?;

        // Reading validビットをチェック
        if (status & (1 << 31)) == 0 {
            return Err(ThermalError::ReadFailed);
        }

        // デジタル読み取り値を取得
        let reading = ((status >> 16) & 0x7F) as i32;
        let temp = self.tj_max - (reading * 1000);

        Ok(Temperature::from_millicelsius(temp))
    }

    /// コア温度を読み取り
    pub fn read_core_temp(&self, _core: u32) -> ThermalResult<Temperature> {
        let status = self.read_msr(msr::IA32_THERM_STATUS)?;

        if (status & (1 << 31)) == 0 {
            return Err(ThermalError::ReadFailed);
        }

        let reading = ((status >> 16) & 0x7F) as i32;
        let temp = self.tj_max - (reading * 1000);

        Ok(Temperature::from_millicelsius(temp))
    }

    /// サーマルステータスを取得
    pub fn thermal_status(&self) -> ThermalStatus {
        let mut status = ThermalStatus::default();

        if let Ok(therm) = self.read_msr(msr::IA32_THERM_STATUS) {
            status.thermal_status = (therm & 1) != 0;
            status.thermal_log = (therm & 2) != 0;
            status.prochot = (therm & 4) != 0;
            status.prochot_log = (therm & 8) != 0;
            status.critical_temp = (therm & 0x10) != 0;
            status.critical_temp_log = (therm & 0x20) != 0;
            status.threshold1 = (therm & 0x40) != 0;
            status.threshold2 = (therm & 0x100) != 0;
            status.power_limit = (therm & 0x400) != 0;
            status.current_limit = (therm & 0x1000) != 0;
        }

        status
    }

    fn read_msr(&self, msr: u32) -> ThermalResult<u64> {
        unsafe {
            let low: u32;
            let high: u32;

            core::arch::asm!(
                "rdmsr",
                out("eax") low,
                out("edx") high,
                in("ecx") msr,
                options(nomem, nostack)
            );

            Ok(((high as u64) << 32) | (low as u64))
        }
    }

    fn detect_core_count(&self) -> u32 {
        unsafe {
            let eax: u32;
            let ebx: u32;
            let ecx: u32;
            let edx: u32;

            core::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "mov {ebx_out:e}, ebx",
                "pop rbx",
                ebx_out = out(reg) ebx,
                out("eax") eax,
                out("ecx") ecx,
                out("edx") edx,
                options(nomem)
            );
            let _ = (eax, ecx, edx); // suppress warnings

            // EBX[23:16] = 最大論理プロセッサ数
            ((ebx >> 16) & 0xFF).max(1)
        }
    }

    pub fn num_cores(&self) -> u32 {
        self.num_cores
    }

    pub fn tj_max(&self) -> Temperature {
        Temperature::from_millicelsius(self.tj_max)
    }
}

/// サーマルステータス
#[derive(Debug, Default)]
pub struct ThermalStatus {
    pub thermal_status: bool,
    pub thermal_log: bool,
    pub prochot: bool,
    pub prochot_log: bool,
    pub critical_temp: bool,
    pub critical_temp_log: bool,
    pub threshold1: bool,
    pub threshold2: bool,
    pub power_limit: bool,
    pub current_limit: bool,
}

// =============================================================================
// スロットリング制御
// =============================================================================

/// スロットリングポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottlePolicy {
    None,
    Light,
    Medium,
    Heavy,
    Emergency,
}

/// スロットリングコントローラ
pub struct ThrottleController {
    current_policy: PoisonLock<ThrottlePolicy>,
    enabled: AtomicBool,
    throttle_count: AtomicU64,
}

impl ThrottleController {
    pub fn new() -> Self {
        Self {
            current_policy: PoisonLock::new(ThrottlePolicy::None),
            enabled: AtomicBool::new(true),
            throttle_count: AtomicU64::new(0),
        }
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    pub fn calculate_policy(&self, temp: Temperature, sensor: &ThermalSensor) -> ThrottlePolicy {
        if !temp.is_valid() {
            return ThrottlePolicy::None;
        }

        let temp_mc = temp.millicelsius();
        let critical = sensor.critical_temp.millicelsius();
        let hot = sensor.hot_temp.millicelsius();
        let passive = sensor.passive_temp.millicelsius();

        if temp_mc >= critical {
            ThrottlePolicy::Emergency
        } else if temp_mc >= hot {
            ThrottlePolicy::Heavy
        } else if temp_mc >= (hot + passive) / 2 {
            ThrottlePolicy::Medium
        } else if temp_mc >= passive {
            ThrottlePolicy::Light
        } else {
            ThrottlePolicy::None
        }
    }

    pub fn apply(&self, policy: ThrottlePolicy) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let mut current = self.current_policy.lock().unwrap_or_else(|e| e.into_inner());
        if *current == policy {
            return;
        }

        match policy {
            ThrottlePolicy::None => self.clear_throttle(),
            ThrottlePolicy::Light => self.apply_light_throttle(),
            ThrottlePolicy::Medium => self.apply_medium_throttle(),
            ThrottlePolicy::Heavy => self.apply_heavy_throttle(),
            ThrottlePolicy::Emergency => self.apply_emergency_throttle(),
        }

        if policy != ThrottlePolicy::None {
            self.throttle_count.fetch_add(1, Ordering::Relaxed);
        }

        *current = policy;
    }

    fn clear_throttle(&self) {
        unsafe {
            let msr_clock_mod: u32 = 0x19A;
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr_clock_mod,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nomem, nostack)
            );
        }
    }

    fn apply_light_throttle(&self) {}

    fn apply_medium_throttle(&self) {
        unsafe {
            let msr_clock_mod: u32 = 0x19A;
            let value: u32 = 0x1C;
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr_clock_mod,
                in("eax") value,
                in("edx") 0u32,
                options(nomem, nostack)
            );
        }
    }

    fn apply_heavy_throttle(&self) {
        unsafe {
            let msr_clock_mod: u32 = 0x19A;
            let value: u32 = 0x18;
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr_clock_mod,
                in("eax") value,
                in("edx") 0u32,
                options(nomem, nostack)
            );
        }
    }

    fn apply_emergency_throttle(&self) {
        unsafe {
            let msr_clock_mod: u32 = 0x19A;
            let value: u32 = 0x12;
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr_clock_mod,
                in("eax") value,
                in("edx") 0u32,
                options(nomem, nostack)
            );
        }
    }

    pub fn current_policy(&self) -> ThrottlePolicy {
        *self.current_policy.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn throttle_count(&self) -> u64 {
        self.throttle_count.load(Ordering::Relaxed)
    }
}

// =============================================================================
// ファン制御
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanLevel {
    Auto,
    Silent,
    Low,
    Medium,
    High,
    Full,
}

#[derive(Debug, Clone)]
pub struct Fan {
    pub id: u32,
    pub name: String,
    pub rpm: u32,
    pub level: FanLevel,
    pub pwm: u8,
}

pub struct FanController {
    fans: PoisonRwLock<Vec<Fan>>,
    auto_mode: AtomicBool,
}

impl FanController {
    pub fn new() -> Self {
        Self {
            fans: PoisonRwLock::new(Vec::new()),
            auto_mode: AtomicBool::new(true),
        }
    }

    pub fn register(&self, id: u32, name: String) {
        let fan = Fan {
            id,
            name,
            rpm: 0,
            level: FanLevel::Auto,
            pwm: 128,
        };
        self.fans.write().unwrap_or_else(|e| e.into_inner()).push(fan);
    }

    pub fn update_rpm(&self, id: u32, rpm: u32) {
        let mut fans = self.fans.write().unwrap_or_else(|e| e.into_inner());
        if let Some(fan) = fans.iter_mut().find(|f| f.id == id) {
            fan.rpm = rpm;
        }
    }

    pub fn set_level(&self, id: u32, level: FanLevel) {
        let mut fans = self.fans.write().unwrap_or_else(|e| e.into_inner());
        if let Some(fan) = fans.iter_mut().find(|f| f.id == id) {
            fan.level = level;
            fan.pwm = match level {
                FanLevel::Auto => 128,
                FanLevel::Silent => 64,
                FanLevel::Low => 96,
                FanLevel::Medium => 160,
                FanLevel::High => 220,
                FanLevel::Full => 255,
            };
        }
    }

    fn temp_to_fan_level(celsius: i32) -> FanLevel {
        if celsius >= 85 {
            FanLevel::Full
        } else if celsius >= 75 {
            FanLevel::High
        } else if celsius >= 65 {
            FanLevel::Medium
        } else if celsius >= 55 {
            FanLevel::Low
        } else {
            FanLevel::Silent
        }
    }

    pub fn auto_control(&self, temp: Temperature) {
        if !self.auto_mode.load(Ordering::Relaxed) {
            return;
        }

        let level = Self::temp_to_fan_level(temp.celsius());

        let mut fans = self.fans.write().unwrap_or_else(|e| e.into_inner());
        for fan in fans.iter_mut() {
            if fan.level == FanLevel::Auto {
                fan.pwm = match level {
                    FanLevel::Auto => 128,
                    FanLevel::Silent => 64,
                    FanLevel::Low => 96,
                    FanLevel::Medium => 160,
                    FanLevel::High => 220,
                    FanLevel::Full => 255,
                };
            }
        }
    }

    pub fn fan_count(&self) -> usize {
        self.fans.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn for_each_fan<F>(&self, mut f: F)
    where
        F: FnMut(&Fan),
    {
        let fans = self.fans.read().unwrap_or_else(|e| e.into_inner());
        for fan in fans.iter() {
            f(fan);
        }
    }
}

// =============================================================================
// サーマルゾーン
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripPointType {
    Active(u8),
    Passive,
    Hot,
    Critical,
}

#[derive(Debug, Clone)]
pub struct TripPoint {
    pub trip_type: TripPointType,
    pub temperature: Temperature,
    pub hysteresis: i32,
    pub triggered: bool,
}

#[derive(Debug)]
pub struct ThermalZone {
    pub id: u32,
    pub name: String,
    pub sensors: Vec<u32>,
    pub trip_points: Vec<TripPoint>,
    pub cooling_devices: Vec<u32>,
    pub mode: ThermalZoneMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalZoneMode {
    Enabled,
    Disabled,
}
