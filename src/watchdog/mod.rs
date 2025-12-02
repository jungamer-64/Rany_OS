//! ウォッチドッグタイマー
//!
//! システムの健全性を監視するウォッチドッグタイマー
//! - ハードウェアウォッチドッグサポート (Intel TCO, 汎用ACPI)
//! - ソフトウェアウォッチドッグ
//! - デッドロック検出
//! - タスクタイムアウト監視

use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::{Mutex, RwLock};

// =============================================================================
// 定数
// =============================================================================

/// デフォルトのウォッチドッグタイムアウト（秒）
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// ハートビート間隔（ミリ秒）
const HEARTBEAT_INTERVAL_MS: u64 = 1000;

// =============================================================================
// ウォッチドッグエラー
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogError {
    /// ハードウェアが見つからない
    HardwareNotFound,
    /// 初期化失敗
    InitFailed,
    /// タイムアウト
    Timeout,
    /// 既に有効
    AlreadyEnabled,
    /// 既に無効
    AlreadyDisabled,
    /// 権限不足
    PermissionDenied,
    /// サポートされていない
    NotSupported,
}

pub type WatchdogResult<T> = Result<T, WatchdogError>;

// =============================================================================
// ウォッチドッグアクション
// =============================================================================

/// タイムアウト時のアクション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutAction {
    /// 何もしない
    None,
    /// ログを記録
    Log,
    /// パニック
    Panic,
    /// システムリセット
    Reset,
    /// NMI発行
    Nmi,
    /// カスタムハンドラを呼び出し
    Custom,
}

// =============================================================================
// ハードウェアウォッチドッグ
// =============================================================================

/// ハードウェアウォッチドッグトレイト
pub trait HardwareWatchdog: Send + Sync {
    /// ドライバ名
    fn name(&self) -> &'static str;
    
    /// サポートされる最大タイムアウト（秒）
    fn max_timeout(&self) -> u64;
    
    /// サポートされる最小タイムアウト（秒）
    fn min_timeout(&self) -> u64;
    
    /// 有効化
    fn enable(&mut self, timeout_secs: u64) -> WatchdogResult<()>;
    
    /// 無効化
    fn disable(&mut self) -> WatchdogResult<()>;
    
    /// キック（タイマーリセット）
    fn kick(&mut self) -> WatchdogResult<()>;
    
    /// タイムアウトを設定
    fn set_timeout(&mut self, secs: u64) -> WatchdogResult<()>;
    
    /// 現在のタイムアウトを取得
    fn timeout(&self) -> u64;
    
    /// 有効状態を取得
    fn is_enabled(&self) -> bool;
}

/// Intel TCO ウォッチドッグ
pub struct IntelTcoWatchdog {
    tco_base: u16,
    timeout: u64,
    enabled: bool,
}

impl IntelTcoWatchdog {
    pub const fn new(tco_base: u16) -> Self {
        Self {
            tco_base,
            timeout: DEFAULT_TIMEOUT_SECS,
            enabled: false,
        }
    }
    
    /// TCOを検出
    pub fn detect() -> Option<Self> {
        // PCI設定空間からTCOベースアドレスを取得
        // LPC Bridge (0:31.0) のTCOBASE レジスタ
        // ここでは簡略化のため固定値を使用
        Some(Self::new(0x460))
    }
    
    unsafe fn read_tco(&self, offset: u16) -> u16 {
        let port = self.tco_base + offset;
        let value: u16;
        core::arch::asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nomem, nostack)
        );
        value
    }
    
    unsafe fn write_tco(&self, offset: u16, value: u16) {
        let port = self.tco_base + offset;
        core::arch::asm!(
            "out dx, ax",
            in("ax") value,
            in("dx") port,
            options(nomem, nostack)
        );
    }
}

impl HardwareWatchdog for IntelTcoWatchdog {
    fn name(&self) -> &'static str {
        "Intel TCO Watchdog"
    }
    
    fn max_timeout(&self) -> u64 {
        613 // TCOの最大値
    }
    
    fn min_timeout(&self) -> u64 {
        1
    }
    
    fn enable(&mut self, timeout_secs: u64) -> WatchdogResult<()> {
        if self.enabled {
            return Err(WatchdogError::AlreadyEnabled);
        }
        
        self.set_timeout(timeout_secs)?;
        
        unsafe {
            // TCO1_CNTのTMR_HLTビットをクリア
            let cnt = self.read_tco(0x08);
            self.write_tco(0x08, cnt & !0x0800);
        }
        
        self.enabled = true;
        Ok(())
    }
    
    fn disable(&mut self) -> WatchdogResult<()> {
        if !self.enabled {
            return Err(WatchdogError::AlreadyDisabled);
        }
        
        unsafe {
            // TCO1_CNTのTMR_HLTビットをセット
            let cnt = self.read_tco(0x08);
            self.write_tco(0x08, cnt | 0x0800);
        }
        
        self.enabled = false;
        Ok(())
    }
    
    fn kick(&mut self) -> WatchdogResult<()> {
        if !self.enabled {
            return Err(WatchdogError::AlreadyDisabled);
        }
        
        unsafe {
            // TCO_RLDに書き込んでタイマーリロード
            self.write_tco(0x00, 0x0001);
        }
        
        Ok(())
    }
    
    fn set_timeout(&mut self, secs: u64) -> WatchdogResult<()> {
        if secs < self.min_timeout() || secs > self.max_timeout() {
            return Err(WatchdogError::NotSupported);
        }
        
        // TCOタイマーティック（0.6秒/ティック）に変換
        let ticks = (secs * 10 / 6) as u16;
        
        unsafe {
            // TCO_TMRに書き込み
            self.write_tco(0x12, ticks);
        }
        
        self.timeout = secs;
        Ok(())
    }
    
    fn timeout(&self) -> u64 {
        self.timeout
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// =============================================================================
// ソフトウェアウォッチドッグ
// =============================================================================

/// 監視対象
#[derive(Debug, Clone)]
pub struct WatchTarget {
    pub id: u64,
    pub name: String,
    pub timeout_ms: u64,
    pub last_heartbeat: u64,
    pub action: TimeoutAction,
    pub triggered: bool,
}

impl WatchTarget {
    pub fn new(id: u64, name: String, timeout_ms: u64, action: TimeoutAction) -> Self {
        Self {
            id,
            name,
            timeout_ms,
            last_heartbeat: 0,
            action,
            triggered: false,
        }
    }
    
    pub fn heartbeat(&mut self, now: u64) {
        self.last_heartbeat = now;
        self.triggered = false;
    }
    
    pub fn check(&mut self, now: u64) -> Option<TimeoutAction> {
        if self.triggered {
            return None;
        }
        
        let elapsed = now.saturating_sub(self.last_heartbeat);
        if elapsed > self.timeout_ms {
            self.triggered = true;
            Some(self.action)
        } else {
            None
        }
    }
}

/// ソフトウェアウォッチドッグ
pub struct SoftwareWatchdog {
    targets: RwLock<Vec<WatchTarget>>,
    next_id: AtomicU64,
    enabled: AtomicBool,
    check_interval_ms: u64,
    
    // 統計
    stats: WatchdogStats,
}

/// ウォッチドッグ統計
#[derive(Debug, Default)]
pub struct WatchdogStats {
    pub total_heartbeats: AtomicU64,
    pub total_timeouts: AtomicU64,
    pub total_checks: AtomicU64,
}

impl SoftwareWatchdog {
    pub fn new() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            enabled: AtomicBool::new(false),
            check_interval_ms: HEARTBEAT_INTERVAL_MS,
            stats: WatchdogStats {
                total_heartbeats: AtomicU64::new(0),
                total_timeouts: AtomicU64::new(0),
                total_checks: AtomicU64::new(0),
            },
        }
    }
    
    /// ウォッチドッグを有効化
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }
    
    /// ウォッチドッグを無効化
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
    
    /// 監視対象を登録
    pub fn register(&self, name: &str, timeout_ms: u64, action: TimeoutAction) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let target = WatchTarget::new(id, name.into(), timeout_ms, action);
        
        self.targets.write().push(target);
        id
    }
    
    /// 監視対象を解除
    pub fn unregister(&self, id: u64) {
        self.targets.write().retain(|t| t.id != id);
    }
    
    /// ハートビート送信
    pub fn heartbeat(&self, id: u64, now: u64) {
        let mut targets = self.targets.write();
        if let Some(target) = targets.iter_mut().find(|t| t.id == id) {
            target.heartbeat(now);
            self.stats.total_heartbeats.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// 全ターゲットをチェック
    pub fn check_all(&self, now: u64) -> Vec<(u64, String, TimeoutAction)> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Vec::new();
        }
        
        self.stats.total_checks.fetch_add(1, Ordering::Relaxed);
        
        let mut timeouts = Vec::new();
        let mut targets = self.targets.write();
        
        for target in targets.iter_mut() {
            if let Some(action) = target.check(now) {
                self.stats.total_timeouts.fetch_add(1, Ordering::Relaxed);
                timeouts.push((target.id, target.name.clone(), action));
            }
        }
        
        timeouts
    }
    
    /// 統計を取得
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.stats.total_heartbeats.load(Ordering::Relaxed),
            self.stats.total_timeouts.load(Ordering::Relaxed),
            self.stats.total_checks.load(Ordering::Relaxed),
        )
    }
}

// =============================================================================
// デッドロック検出器
// =============================================================================

/// ロック情報
#[derive(Debug, Clone)]
pub struct LockInfo {
    pub id: u64,
    pub name: String,
    pub holder_task: Option<u64>,
    pub waiters: Vec<u64>,
    pub acquired_at: u64,
}

/// デッドロック検出器
pub struct DeadlockDetector {
    locks: RwLock<Vec<LockInfo>>,
    enabled: AtomicBool,
    next_id: AtomicU64,
    
    // 統計
    deadlocks_detected: AtomicU64,
}

impl DeadlockDetector {
    pub fn new() -> Self {
        Self {
            locks: RwLock::new(Vec::new()),
            enabled: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            deadlocks_detected: AtomicU64::new(0),
        }
    }
    
    /// 検出を有効化
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }
    
    /// 検出を無効化
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
    
    /// ロックを登録
    pub fn register_lock(&self, name: &str) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let lock = LockInfo {
            id,
            name: name.into(),
            holder_task: None,
            waiters: Vec::new(),
            acquired_at: 0,
        };
        
        self.locks.write().push(lock);
        id
    }
    
    /// ロック取得を記録
    pub fn lock_acquired(&self, lock_id: u64, task_id: u64, timestamp: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let mut locks = self.locks.write();
        if let Some(lock) = locks.iter_mut().find(|l| l.id == lock_id) {
            lock.holder_task = Some(task_id);
            lock.acquired_at = timestamp;
            lock.waiters.retain(|&w| w != task_id);
        }
    }
    
    /// ロック解放を記録
    pub fn lock_released(&self, lock_id: u64, _task_id: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let mut locks = self.locks.write();
        if let Some(lock) = locks.iter_mut().find(|l| l.id == lock_id) {
            lock.holder_task = None;
            lock.acquired_at = 0;
        }
    }
    
    /// ロック待機を記録
    pub fn lock_waiting(&self, lock_id: u64, task_id: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let mut locks = self.locks.write();
        if let Some(lock) = locks.iter_mut().find(|l| l.id == lock_id) {
            if !lock.waiters.contains(&task_id) {
                lock.waiters.push(task_id);
            }
        }
    }
    
    /// デッドロックを検出
    pub fn detect(&self) -> Vec<Vec<u64>> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Vec::new();
        }
        
        let locks = self.locks.read();
        let mut cycles = Vec::new();
        
        // 各タスクについて、待機グラフでサイクルを探す
        for lock in locks.iter() {
            if let Some(holder) = lock.holder_task {
                for &waiter in &lock.waiters {
                    if let Some(cycle) = self.find_cycle(&locks, waiter, holder) {
                        if !cycles.contains(&cycle) {
                            cycles.push(cycle);
                            self.deadlocks_detected.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        
        cycles
    }
    
    fn find_cycle(&self, locks: &[LockInfo], start: u64, target: u64) -> Option<Vec<u64>> {
        let mut visited = Vec::new();
        let mut path = vec![start];
        
        self.dfs(locks, start, target, &mut visited, &mut path)
    }
    
    fn dfs(
        &self,
        locks: &[LockInfo],
        current: u64,
        target: u64,
        visited: &mut Vec<u64>,
        path: &mut Vec<u64>,
    ) -> Option<Vec<u64>> {
        if current == target && path.len() > 1 {
            return Some(path.clone());
        }
        
        if visited.contains(&current) {
            return None;
        }
        visited.push(current);
        
        // currentが待っているロックを探す
        for lock in locks.iter() {
            if lock.waiters.contains(&current) {
                if let Some(holder) = lock.holder_task {
                    path.push(holder);
                    if let Some(cycle) = self.dfs(locks, holder, target, visited, path) {
                        return Some(cycle);
                    }
                    path.pop();
                }
            }
        }
        
        None
    }
    
    /// 検出数を取得
    pub fn deadlocks_detected(&self) -> u64 {
        self.deadlocks_detected.load(Ordering::Relaxed)
    }
}

// =============================================================================
// 統合ウォッチドッグマネージャ
// =============================================================================

/// ウォッチドッグマネージャ
pub struct WatchdogManager {
    hardware: Mutex<Option<Box<dyn HardwareWatchdog>>>,
    software: SoftwareWatchdog,
    deadlock_detector: DeadlockDetector,
    
    // 設定
    use_hardware: AtomicBool,
    timeout_action: Mutex<TimeoutAction>,
}

impl WatchdogManager {
    pub fn new() -> Self {
        Self {
            hardware: Mutex::new(None),
            software: SoftwareWatchdog::new(),
            deadlock_detector: DeadlockDetector::new(),
            use_hardware: AtomicBool::new(false),
            timeout_action: Mutex::new(TimeoutAction::Panic),
        }
    }
    
    /// 初期化
    pub fn init(&self) -> WatchdogResult<()> {
        // ハードウェアウォッチドッグを検出
        if let Some(tco) = IntelTcoWatchdog::detect() {
            *self.hardware.lock() = Some(Box::new(tco));
            self.use_hardware.store(true, Ordering::SeqCst);
        }
        
        self.software.enable();
        self.deadlock_detector.enable();
        
        Ok(())
    }
    
    /// ハードウェアウォッチドッグを有効化
    pub fn enable_hardware(&self, timeout_secs: u64) -> WatchdogResult<()> {
        let mut hw = self.hardware.lock();
        if let Some(ref mut watchdog) = *hw {
            watchdog.enable(timeout_secs)?;
            self.use_hardware.store(true, Ordering::SeqCst);
            Ok(())
        } else {
            Err(WatchdogError::HardwareNotFound)
        }
    }
    
    /// ハードウェアウォッチドッグをキック
    pub fn kick_hardware(&self) -> WatchdogResult<()> {
        let mut hw = self.hardware.lock();
        if let Some(ref mut watchdog) = *hw {
            watchdog.kick()
        } else {
            Err(WatchdogError::HardwareNotFound)
        }
    }
    
    /// ソフトウェア監視対象を登録
    pub fn watch(&self, name: &str, timeout_ms: u64, action: TimeoutAction) -> u64 {
        self.software.register(name, timeout_ms, action)
    }
    
    /// ハートビート送信
    pub fn heartbeat(&self, id: u64, now: u64) {
        self.software.heartbeat(id, now);
    }
    
    /// 定期チェック（タイマー割り込みから呼ぶ）
    pub fn periodic_check(&self, now: u64) {
        // ハードウェアウォッチドッグをキック
        if self.use_hardware.load(Ordering::Relaxed) {
            let _ = self.kick_hardware();
        }
        
        // ソフトウェアタイムアウトをチェック
        let timeouts = self.software.check_all(now);
        for (_id, name, action) in timeouts {
            self.handle_timeout(&name, action);
        }
        
        // デッドロックをチェック
        let deadlocks = self.deadlock_detector.detect();
        if !deadlocks.is_empty() {
            self.handle_deadlocks(&deadlocks);
        }
    }
    
    fn handle_timeout(&self, name: &str, action: TimeoutAction) {
        match action {
            TimeoutAction::None => {}
            TimeoutAction::Log => {
                // ログ記録のみ
            }
            TimeoutAction::Panic => {
                panic!("Watchdog timeout: {}", name);
            }
            TimeoutAction::Reset => {
                self.system_reset();
            }
            TimeoutAction::Nmi => {
                self.send_nmi();
            }
            TimeoutAction::Custom => {
                // カスタムハンドラを呼び出し
            }
        }
    }
    
    fn handle_deadlocks(&self, deadlocks: &[Vec<u64>]) {
        for cycle in deadlocks {
            panic!("Deadlock detected! Cycle: {:?}", cycle);
        }
    }
    
    fn system_reset(&self) {
        // Triple fault でリセット
        unsafe {
            // IDTを無効化
            let null_idt: [u8; 6] = [0; 6];
            core::arch::asm!(
                "lidt [{}]",
                in(reg) &null_idt,
                options(nostack)
            );
            // 割り込みを発生させる
            core::arch::asm!("int3", options(nostack));
        }
    }
    
    fn send_nmi(&self) {
        // ローカルAPICでNMIを送信
        unsafe {
            // APIC ICR Low (0xFEE00300) にNMIを書き込み
            let apic_icr = 0xFEE00300 as *mut u32;
            core::ptr::write_volatile(apic_icr, 0x000C4500); // NMI to self
        }
    }
    
    /// ソフトウェアウォッチドッグを取得
    pub fn software(&self) -> &SoftwareWatchdog {
        &self.software
    }
    
    /// デッドロック検出器を取得
    pub fn deadlock_detector(&self) -> &DeadlockDetector {
        &self.deadlock_detector
    }
}

// =============================================================================
// グローバルインスタンス
// =============================================================================

static WATCHDOG_MANAGER: spin::Once<WatchdogManager> = spin::Once::new();

pub fn watchdog_manager() -> &'static WatchdogManager {
    WATCHDOG_MANAGER.call_once(WatchdogManager::new)
}

/// ウォッチドッグを初期化
pub fn init() -> WatchdogResult<()> {
    watchdog_manager().init()
}

/// 監視対象を登録
pub fn watch(name: &str, timeout_ms: u64, action: TimeoutAction) -> u64 {
    watchdog_manager().watch(name, timeout_ms, action)
}

/// ハートビート送信
pub fn heartbeat(id: u64, now: u64) {
    watchdog_manager().heartbeat(id, now);
}

/// 定期チェック
pub fn periodic_check(now: u64) {
    watchdog_manager().periodic_check(now);
}
