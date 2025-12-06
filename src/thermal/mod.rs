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

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

// =============================================================================
// 定数
// =============================================================================

/// 温度読み取りなし
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
        unsafe {
            let target = self.read_msr(msr::IA32_TEMPERATURE_TARGET)?;
            let tj_target = ((target >> 16) & 0xFF) as i32;
            if tj_target > 0 {
                self.tj_max = tj_target * 1000;
            }
        }

        // コア数を検出（CPUID使用）
        self.num_cores = self.detect_core_count();

        Ok(())
    }

    /// パッケージ温度を読み取り
    pub fn read_package_temp(&self) -> ThermalResult<Temperature> {
        unsafe {
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
    }

    /// コア温度を読み取り
    pub fn read_core_temp(&self, _core: u32) -> ThermalResult<Temperature> {
        // 特定のコアへのアフィニティ設定が必要
        // ここでは現在のコアの温度を読む
        unsafe {
            let status = self.read_msr(msr::IA32_THERM_STATUS)?;

            if (status & (1 << 31)) == 0 {
                return Err(ThermalError::ReadFailed);
            }

            let reading = ((status >> 16) & 0x7F) as i32;
            let temp = self.tj_max - (reading * 1000);

            Ok(Temperature::from_millicelsius(temp))
        }
    }

    /// サーマルステータスを取得
    pub fn thermal_status(&self) -> ThermalStatus {
        let mut status = ThermalStatus::default();

        unsafe {
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
        }

        status
    }

    unsafe fn read_msr(&self, msr: u32) -> ThermalResult<u64> { unsafe {
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
    }}

    fn detect_core_count(&self) -> u32 {
        unsafe {
            let eax: u32;
            let ebx: u32;
            let ecx: u32;
            let edx: u32;

            // CPUID leaf 0x1
            // rbxはLLVMに予約されているため、pushq/popqで保存する
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
    /// スロットリングなし
    None,
    /// 軽度（P-state調整のみ）
    Light,
    /// 中度（クロック25%削減）
    Medium,
    /// 重度（クロック50%削減）
    Heavy,
    /// 緊急（最低クロック）
    Emergency,
}

/// スロットリングコントローラ
pub struct ThrottleController {
    current_policy: Mutex<ThrottlePolicy>,
    enabled: AtomicBool,
    throttle_count: AtomicU64,
}

impl ThrottleController {
    pub fn new() -> Self {
        Self {
            current_policy: Mutex::new(ThrottlePolicy::None),
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

    /// 温度に基づいてスロットリングポリシーを決定
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

    /// スロットリングを適用
    pub fn apply(&self, policy: ThrottlePolicy) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let mut current = self.current_policy.lock();
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
        // スロットリングをクリア
        unsafe {
            // IA32_CLOCK_MODULATIONをクリア
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

    fn apply_light_throttle(&self) {
        // P-state調整のみ
        // 実際にはACPIまたはIntel Speed Stepを使用
    }

    fn apply_medium_throttle(&self) {
        // 25%デューティサイクル削減
        unsafe {
            let msr_clock_mod: u32 = 0x19A;
            // Bit 4 = Enable, Bits 3:1 = Duty cycle (6 = 75%)
            let value: u32 = 0x1C; // Enable + 75% duty cycle
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
        // 50%デューティサイクル削減
        unsafe {
            let msr_clock_mod: u32 = 0x19A;
            let value: u32 = 0x18; // Enable + 50% duty cycle
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
        // 最低クロック（12.5%）
        unsafe {
            let msr_clock_mod: u32 = 0x19A;
            let value: u32 = 0x12; // Enable + 12.5% duty cycle
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
        *self.current_policy.lock()
    }

    pub fn throttle_count(&self) -> u64 {
        self.throttle_count.load(Ordering::Relaxed)
    }
}

// =============================================================================
// ファン制御
// =============================================================================

/// ファンレベル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanLevel {
    Auto,
    Silent,
    Low,
    Medium,
    High,
    Full,
}

/// ファン情報
#[derive(Debug, Clone)]
pub struct Fan {
    pub id: u32,
    pub name: String,
    pub rpm: u32,
    pub level: FanLevel,
    pub pwm: u8, // 0-255
}

/// ファンコントローラ（ACPI/SMBus経由）
pub struct FanController {
    fans: RwLock<Vec<Fan>>,
    auto_mode: AtomicBool,
}

impl FanController {
    pub fn new() -> Self {
        Self {
            fans: RwLock::new(Vec::new()),
            auto_mode: AtomicBool::new(true),
        }
    }

    /// ファンを登録
    pub fn register(&self, id: u32, name: String) {
        let fan = Fan {
            id,
            name,
            rpm: 0,
            level: FanLevel::Auto,
            pwm: 128,
        };
        self.fans.write().push(fan);
    }

    /// ファン速度を更新
    pub fn update_rpm(&self, id: u32, rpm: u32) {
        let mut fans = self.fans.write();
        if let Some(fan) = fans.iter_mut().find(|f| f.id == id) {
            fan.rpm = rpm;
        }
    }

    /// ファンレベルを設定
    pub fn set_level(&self, id: u32, level: FanLevel) {
        let mut fans = self.fans.write();
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

    /// 温度に基づいてファンを自動制御
    pub fn auto_control(&self, temp: Temperature) {
        if !self.auto_mode.load(Ordering::Relaxed) {
            return;
        }

        let level = if temp.celsius() >= 85 {
            FanLevel::Full
        } else if temp.celsius() >= 75 {
            FanLevel::High
        } else if temp.celsius() >= 65 {
            FanLevel::Medium
        } else if temp.celsius() >= 55 {
            FanLevel::Low
        } else {
            FanLevel::Silent
        };

        let mut fans = self.fans.write();
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

    /// 全ファンを取得（ガード付き参照を返す）
    ///
    /// Vec clone() を避け、参照カウント不要のゼロコスト参照を提供。
    /// 呼び出し側は RwLockReadGuard の寿命内でのみアクセス可能。
    pub fn fans(&self) -> spin::RwLockReadGuard<'_, Vec<Fan>> {
        self.fans.read()
    }

    /// ファンの数を取得（clone不要）
    #[inline]
    pub fn fan_count(&self) -> usize {
        self.fans.read().len()
    }

    /// コールバックで全ファンを処理（clone不要）
    pub fn for_each_fan<F>(&self, mut f: F)
    where
        F: FnMut(&Fan),
    {
        let fans = self.fans.read();
        for fan in fans.iter() {
            f(fan);
        }
    }
}

// =============================================================================
// サーマルゾーン
// =============================================================================

/// サーマルゾーンタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripPointType {
    /// アクティブ冷却（ファンオン）
    Active(u8),
    /// パッシブ冷却（スロットリング）
    Passive,
    /// ホット（警告）
    Hot,
    /// クリティカル（シャットダウン）
    Critical,
}

/// トリップポイント
#[derive(Debug, Clone)]
pub struct TripPoint {
    pub trip_type: TripPointType,
    pub temperature: Temperature,
    pub hysteresis: i32, // ミリ摂氏度
    pub triggered: bool,
}

/// サーマルゾーン
#[derive(Debug)]
pub struct ThermalZone {
    pub id: u32,
    pub name: String,
    pub sensors: Vec<u32>,
    pub trip_points: Vec<TripPoint>,
    pub cooling_devices: Vec<u32>,
    pub mode: ThermalZoneMode,
}

/// サーマルゾーンモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalZoneMode {
    Enabled,
    Disabled,
}

impl ThermalZone {
    pub fn new(id: u32, name: String) -> Self {
        Self {
            id,
            name,
            sensors: Vec::new(),
            trip_points: Vec::new(),
            cooling_devices: Vec::new(),
            mode: ThermalZoneMode::Enabled,
        }
    }

    /// トリップポイントを追加
    pub fn add_trip_point(&mut self, trip_type: TripPointType, temp: Temperature, hysteresis: i32) {
        let trip = TripPoint {
            trip_type,
            temperature: temp,
            hysteresis,
            triggered: false,
        };
        self.trip_points.push(trip);
    }

    /// トリップポイントをチェック
    pub fn check_trips(&mut self, current_temp: Temperature) -> Vec<TripPointType> {
        if self.mode == ThermalZoneMode::Disabled {
            return Vec::new();
        }

        let mut triggered = Vec::new();

        for trip in &mut self.trip_points {
            let threshold = if trip.triggered {
                trip.temperature.millicelsius() - trip.hysteresis
            } else {
                trip.temperature.millicelsius()
            };

            if current_temp.millicelsius() >= threshold && !trip.triggered {
                trip.triggered = true;
                triggered.push(trip.trip_type);
            } else if current_temp.millicelsius() < threshold - trip.hysteresis {
                trip.triggered = false;
            }
        }

        triggered
    }
}

// =============================================================================
// サーマルマネージャ
// =============================================================================

/// サーマルマネージャ
pub struct ThermalManager {
    cpu_driver: Mutex<CpuThermalDriver>,
    sensors: RwLock<Vec<ThermalSensor>>,
    zones: RwLock<Vec<ThermalZone>>,
    throttle: ThrottleController,
    fans: FanController,

    next_sensor_id: AtomicU32,
    next_zone_id: AtomicU32,

    // 統計
    polling_count: AtomicU64,
    trip_events: AtomicU64,
}

impl ThermalManager {
    pub fn new() -> Self {
        Self {
            cpu_driver: Mutex::new(CpuThermalDriver::new()),
            sensors: RwLock::new(Vec::new()),
            zones: RwLock::new(Vec::new()),
            throttle: ThrottleController::new(),
            fans: FanController::new(),
            next_sensor_id: AtomicU32::new(1),
            next_zone_id: AtomicU32::new(1),
            polling_count: AtomicU64::new(0),
            trip_events: AtomicU64::new(0),
        }
    }

    /// 初期化
    pub fn init(&self) -> ThermalResult<()> {
        // CPUドライバを初期化
        self.cpu_driver.lock().init()?;

        // CPUセンサーを登録
        self.register_cpu_sensors()?;

        // デフォルトのサーマルゾーンを作成
        self.create_default_zones();

        Ok(())
    }

    fn register_cpu_sensors(&self) -> ThermalResult<()> {
        let driver = self.cpu_driver.lock();

        // パッケージセンサー
        let pkg_id = self.next_sensor_id.fetch_add(1, Ordering::SeqCst);
        let pkg_sensor = ThermalSensor::new(pkg_id, "CPU Package".into(), SensorType::CpuPackage);
        self.sensors.write().push(pkg_sensor);

        // コアセンサー
        for core in 0..driver.num_cores() {
            let core_id = self.next_sensor_id.fetch_add(1, Ordering::SeqCst);
            let core_sensor = ThermalSensor::new(
                core_id,
                alloc::format!("CPU Core {}", core),
                SensorType::CpuCore(core as u8),
            );
            self.sensors.write().push(core_sensor);
        }

        Ok(())
    }

    fn create_default_zones(&self) {
        let zone_id = self.next_zone_id.fetch_add(1, Ordering::SeqCst);
        let mut zone = ThermalZone::new(zone_id, "CPU".into());

        // CPUセンサーを追加
        let sensors = self.sensors.read();
        for sensor in sensors.iter() {
            if matches!(
                sensor.sensor_type,
                SensorType::CpuPackage | SensorType::CpuCore(_)
            ) {
                zone.sensors.push(sensor.id);
            }
        }

        // トリップポイントを追加
        zone.add_trip_point(
            TripPointType::Passive,
            Temperature::from_millicelsius(DEFAULT_PASSIVE_TEMP),
            3000,
        );
        zone.add_trip_point(
            TripPointType::Hot,
            Temperature::from_millicelsius(DEFAULT_HOT_TEMP),
            3000,
        );
        zone.add_trip_point(
            TripPointType::Critical,
            Temperature::from_millicelsius(DEFAULT_CRITICAL_TEMP),
            0,
        );

        self.zones.write().push(zone);
    }

    /// センサーを更新
    pub fn poll_sensors(&self) {
        self.polling_count.fetch_add(1, Ordering::Relaxed);

        let driver = self.cpu_driver.lock();
        let mut sensors = self.sensors.write();

        for sensor in sensors.iter_mut() {
            let temp = match sensor.sensor_type {
                SensorType::CpuPackage => {
                    driver.read_package_temp().unwrap_or(Temperature::invalid())
                }
                SensorType::CpuCore(core) => driver
                    .read_core_temp(core as u32)
                    .unwrap_or(Temperature::invalid()),
                _ => Temperature::invalid(),
            };
            sensor.update(temp);
        }
    }

    /// サーマルゾーンを処理
    pub fn process_zones(&self) {
        let sensors = self.sensors.read();
        let mut zones = self.zones.write();

        for zone in zones.iter_mut() {
            // ゾーン内のセンサーから最高温度を取得
            let max_temp = zone
                .sensors
                .iter()
                .filter_map(|&id| sensors.iter().find(|s| s.id == id))
                .filter(|s| s.current.is_valid())
                .map(|s| s.current.millicelsius())
                .max()
                .map(Temperature::from_millicelsius)
                .unwrap_or(Temperature::invalid());

            if !max_temp.is_valid() {
                continue;
            }

            // トリップポイントをチェック
            let triggered = zone.check_trips(max_temp);

            for trip_type in triggered {
                self.trip_events.fetch_add(1, Ordering::Relaxed);
                self.handle_trip(trip_type, max_temp);
            }

            // スロットリングポリシーを計算
            if let Some(sensor) = zone
                .sensors
                .iter()
                .filter_map(|&id| sensors.iter().find(|s| s.id == id))
                .next()
            {
                let policy = self.throttle.calculate_policy(max_temp, sensor);
                self.throttle.apply(policy);
            }

            // ファンを自動制御
            self.fans.auto_control(max_temp);
        }
    }

    fn handle_trip(&self, trip_type: TripPointType, temp: Temperature) {
        match trip_type {
            TripPointType::Active(_) => {
                // ファン速度を上げる
            }
            TripPointType::Passive => {
                // スロットリングを開始（process_zonesで処理済み）
            }
            TripPointType::Hot => {
                // 警告ログ
            }
            TripPointType::Critical => {
                // 緊急シャットダウン
                panic!(
                    "THERMAL CRITICAL: {}°C - Emergency shutdown!",
                    temp.celsius()
                );
            }
        }
    }

    /// 定期ポーリング（タイマー割り込みから呼ぶ）
    pub fn periodic_poll(&self) {
        self.poll_sensors();
        self.process_zones();
    }

    /// 全センサーを取得（ガード付き参照）
    ///
    /// Vec clone() を避け、ゼロコスト参照を提供。
    pub fn sensors(&self) -> spin::RwLockReadGuard<'_, Vec<ThermalSensor>> {
        self.sensors.read()
    }

    /// センサー数を取得（clone不要）
    #[inline]
    pub fn sensor_count(&self) -> usize {
        self.sensors.read().len()
    }

    /// 特定のセンサーを取得
    pub fn sensor(&self, id: u32) -> Option<ThermalSensor> {
        self.sensors.read().iter().find(|s| s.id == id).cloned()
    }

    /// スロットリングコントローラを取得
    pub fn throttle_controller(&self) -> &ThrottleController {
        &self.throttle
    }

    /// ファンコントローラを取得
    pub fn fan_controller(&self) -> &FanController {
        &self.fans
    }

    /// 統計を取得
    pub fn stats(&self) -> (u64, u64) {
        (
            self.polling_count.load(Ordering::Relaxed),
            self.trip_events.load(Ordering::Relaxed),
        )
    }
}

// =============================================================================
// グローバルインスタンス
// =============================================================================

static THERMAL_MANAGER: spin::Once<ThermalManager> = spin::Once::new();

pub fn thermal_manager() -> &'static ThermalManager {
    THERMAL_MANAGER.call_once(ThermalManager::new)
}

/// 初期化
pub fn init() -> ThermalResult<()> {
    thermal_manager().init()
}

/// 定期ポーリング
pub fn periodic_poll() {
    thermal_manager().periodic_poll();
}

/// CPU温度を取得
pub fn cpu_temperature() -> Option<Temperature> {
    thermal_manager()
        .sensors()
        .iter()
        .find(|s| s.sensor_type == SensorType::CpuPackage)
        .map(|s| s.current)
        .filter(|t| t.is_valid())
}
