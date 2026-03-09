use super::*;

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
    cpu_driver: PoisonLock<CpuThermalDriver>,
    sensors: PoisonRwLock<Vec<ThermalSensor>>,
    zones: PoisonRwLock<Vec<ThermalZone>>,
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
            cpu_driver: PoisonLock::new(CpuThermalDriver::new()),
            sensors: PoisonRwLock::new(Vec::new()),
            zones: PoisonRwLock::new(Vec::new()),
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
        self.cpu_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .init()?;

        // CPUセンサーを登録
        self.register_cpu_sensors()?;

        // デフォルトのサーマルゾーンを作成
        self.create_default_zones();

        Ok(())
    }

    pub(super) fn register_cpu_sensors(&self) -> ThermalResult<()> {
        let driver = self.cpu_driver.lock().unwrap_or_else(|e| e.into_inner());

        // パッケージセンサー
        let pkg_id = self.next_sensor_id.fetch_add(1, Ordering::SeqCst);
        let pkg_sensor = ThermalSensor::new(pkg_id, "CPU Package".into(), SensorType::CpuPackage);
        self.sensors
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(pkg_sensor);

        // コアセンサー
        for core in 0..driver.num_cores() {
            let core_id = self.next_sensor_id.fetch_add(1, Ordering::SeqCst);
            let core_sensor = ThermalSensor::new(
                core_id,
                alloc::format!("CPU Core {}", core),
                SensorType::CpuCore(core as u8),
            );
            self.sensors
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .push(core_sensor);
        }

        Ok(())
    }

    pub(super) fn create_default_zones(&self) {
        let zone_id = self.next_zone_id.fetch_add(1, Ordering::SeqCst);
        let mut zone = ThermalZone::new(zone_id, "CPU".into());

        // CPUセンサーを追加
        let sensors = self.sensors.read().unwrap_or_else(|e| e.into_inner());
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

        self.zones
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(zone);
    }

    /// センサーを更新
    pub fn poll_sensors(&self) {
        self.polling_count.fetch_add(1, Ordering::Relaxed);

        let driver = self.cpu_driver.lock().unwrap_or_else(|e| e.into_inner());
        let mut sensors = self.sensors.write().unwrap_or_else(|e| e.into_inner());

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
        let sensors = self.sensors.read().unwrap_or_else(|e| e.into_inner());
        let mut zones = self.zones.write().unwrap_or_else(|e| e.into_inner());

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

    pub(super) fn handle_trip(&self, trip_type: TripPointType, temp: Temperature) {
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

    /// 全センサーを取得
    pub fn sensor_count(&self) -> usize {
        self.sensors.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// 特定のセンサーを取得
    pub fn sensor(&self, id: u32) -> Option<ThermalSensor> {
        self.sensors
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|s| s.id == id)
            .cloned()
    }

    /// 全センサーのスナップショットを取得
    pub fn sensors(&self) -> alloc::vec::Vec<ThermalSensor> {
        self.sensors
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
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

pub(crate) static THERMAL_MANAGER: spin::Once<ThermalManager> = spin::Once::new();

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
    let sensors = thermal_manager()
        .sensors
        .read()
        .unwrap_or_else(|e| e.into_inner());
    sensors
        .iter()
        .find(|s| s.sensor_type == SensorType::CpuPackage)
        .map(|s| s.current)
        .filter(|t| t.is_valid())
}
