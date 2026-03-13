// ============================================================================
// src/domain/quota.rs - Domain Resource Quota Management
// 設計書 9.3: リソースアカウンティングとQoS
// ============================================================================
//!
//! # ドメインリソースクォータ
//!
//! 協調的マルチタスク環境では、悪意ある、あるいはバグを含むドメインが
//! システムリソースを独占する可能性があります。公平性と安定性を担保するため、
//! リソースアカウンティングとQoS機構を提供します。
//!
//! ## 設計書 9.3 の実装
//!
//! - **9.3.1 CPU時間クォータ**: ドメインごとのCPU時間制限
//! - **9.3.2 メモリ使用量制限**: ドメインごとのメモリ上限
//! - **9.3.3 OOMキラー戦略**: 優先度に基づくドメイン終了
//! - **9.3.4 I/O帯域制限**: トークンバケットによる帯域制限

#![allow(dead_code)]

use crate::domain_system::DomainId;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// ドメイン優先度
///
/// OOMキラーおよびスケジューリング優先度に影響します。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DomainPriority {
    /// 最低優先度 - OOMキラーの最初の対象
    Low = 0,
    /// 通常優先度
    Normal = 1,
    /// 高優先度
    High = 2,
    /// クリティカル - OOMキラー対象外、カーネルコア用
    Critical = 3,
}

impl Default for DomainPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// CPU時間クォータ（ナノ秒単位）
#[derive(Debug)]
pub struct CpuQuota {
    /// 単位時間あたりの最大CPU時間（ナノ秒）
    pub limit_per_period_ns: u64,
    /// 計測期間（ナノ秒、通常100ms = 100_000_000）
    pub period_ns: u64,
    /// 現在の期間での累計使用時間
    used_this_period: AtomicU64,
    /// 期間開始時刻
    period_start_ns: AtomicU64,
    /// クォータ超過フラグ
    exceeded: AtomicBool,
}

impl CpuQuota {
    /// 新しいCPUクォータを作成
    ///
    /// # Arguments
    /// * `limit_percent` - CPU使用率の上限（0-100）
    /// * `period_ms` - 計測期間（ミリ秒）
    pub fn new(limit_percent: u64, period_ms: u64) -> Self {
        let period_ns = period_ms * 1_000_000;
        let limit_per_period_ns = (period_ns * limit_percent) / 100;

        Self {
            limit_per_period_ns,
            period_ns,
            used_this_period: AtomicU64::new(0),
            period_start_ns: AtomicU64::new(0),
            exceeded: AtomicBool::new(false),
        }
    }

    /// 無制限のCPUクォータ
    pub fn unlimited() -> Self {
        Self {
            limit_per_period_ns: u64::MAX,
            period_ns: 100_000_000, // 100ms
            used_this_period: AtomicU64::new(0),
            period_start_ns: AtomicU64::new(0),
            exceeded: AtomicBool::new(false),
        }
    }

    /// CPU時間を消費
    ///
    /// # Arguments
    /// * `elapsed_ns` - 消費したCPU時間（ナノ秒）
    /// * `current_time_ns` - 現在時刻（ナノ秒）
    ///
    /// # Returns
    /// クォータ超過の場合 `true`
    pub fn consume(&self, elapsed_ns: u64, current_time_ns: u64) -> bool {
        let period_start = self.period_start_ns.load(Ordering::Relaxed);

        // 新しい期間の開始チェック
        if current_time_ns >= period_start + self.period_ns {
            self.period_start_ns
                .store(current_time_ns, Ordering::Relaxed);
            self.used_this_period.store(elapsed_ns, Ordering::Relaxed);
            self.exceeded.store(false, Ordering::Relaxed);
            return false;
        }

        // 累計使用時間を更新
        let used = self
            .used_this_period
            .fetch_add(elapsed_ns, Ordering::Relaxed)
            + elapsed_ns;

        if used > self.limit_per_period_ns {
            self.exceeded.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// クォータ超過しているかチェック
    pub fn is_exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Relaxed)
    }

    /// 使用率を取得（0.0-1.0）
    pub fn usage_ratio(&self) -> f64 {
        let used = self.used_this_period.load(Ordering::Relaxed);
        if self.limit_per_period_ns == 0 {
            return 0.0;
        }
        (used as f64) / (self.limit_per_period_ns as f64)
    }

    /// リセット
    pub fn reset(&self) {
        self.used_this_period.store(0, Ordering::Relaxed);
        self.exceeded.store(false, Ordering::Relaxed);
    }
}

/// メモリクォータ（バイト単位）
#[derive(Debug)]
pub struct MemoryQuota {
    /// 最大メモリ使用量（バイト）
    pub limit_bytes: u64,
    /// 現在の使用量
    used_bytes: AtomicU64,
    /// 警告閾値（リミットの何%で警告）
    pub warning_threshold_percent: u64,
}

impl MemoryQuota {
    /// 新しいメモリクォータを作成
    pub fn new(limit_mb: u64) -> Self {
        Self {
            limit_bytes: limit_mb * 1024 * 1024,
            used_bytes: AtomicU64::new(0),
            warning_threshold_percent: 80,
        }
    }

    /// 無制限のメモリクォータ
    pub fn unlimited() -> Self {
        Self {
            limit_bytes: u64::MAX,
            used_bytes: AtomicU64::new(0),
            warning_threshold_percent: 100,
        }
    }

    /// メモリ割り当てを試行
    ///
    /// # Returns
    /// 割り当て可能な場合 `Ok(())`、超過の場合 `Err(QuotaError)`
    pub fn try_allocate(&self, bytes: u64) -> Result<(), QuotaError> {
        let current = self.used_bytes.load(Ordering::Relaxed);
        let new_total = current.saturating_add(bytes);

        if new_total > self.limit_bytes {
            return Err(QuotaError::MemoryExceeded {
                requested: bytes,
                available: self.limit_bytes.saturating_sub(current),
                limit: self.limit_bytes,
            });
        }

        // CAS操作で安全に更新
        match self.used_bytes.compare_exchange(
            current,
            new_total,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => Ok(()),
            Err(_) => {
                // 競合が発生、再試行が必要
                Err(QuotaError::AllocationRace)
            }
        }
    }

    /// メモリ解放を記録
    pub fn deallocate(&self, bytes: u64) {
        self.used_bytes.fetch_sub(
            bytes.min(self.used_bytes.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
    }

    /// 現在の使用量を取得
    pub fn used(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }

    /// 使用率を取得（0.0-1.0）
    pub fn usage_ratio(&self) -> f64 {
        if self.limit_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes.load(Ordering::Relaxed) as f64) / (self.limit_bytes as f64)
    }

    /// 警告閾値を超えているかチェック
    pub fn is_warning(&self) -> bool {
        let threshold = (self.limit_bytes * self.warning_threshold_percent) / 100;
        self.used_bytes.load(Ordering::Relaxed) > threshold
    }
}

/// I/O帯域クォータ（トークンバケットアルゴリズム）
///
/// 設計書 9.3.4: バースト的なI/Oを許容しつつ、長期的な帯域を制限
#[derive(Debug)]
pub struct IoQuota {
    /// 帯域制限（バイト/秒）
    pub rate_bytes_per_sec: u64,
    /// バケットサイズ（バースト許容量）
    pub bucket_size: u64,
    /// 現在のトークン数
    tokens: AtomicU64,
    /// 最後のトークン補充時刻
    last_refill_ns: AtomicU64,
}

impl IoQuota {
    /// 新しいI/Oクォータを作成
    ///
    /// # Arguments
    /// * `rate_mbps` - 帯域制限（MB/秒）
    /// * `burst_mb` - バースト許容量（MB）
    pub fn new(rate_mbps: u64, burst_mb: u64) -> Self {
        let rate_bytes_per_sec = rate_mbps * 1024 * 1024;
        let bucket_size = burst_mb * 1024 * 1024;

        Self {
            rate_bytes_per_sec,
            bucket_size,
            tokens: AtomicU64::new(bucket_size), // 初期状態はバケット満タン
            last_refill_ns: AtomicU64::new(0),
        }
    }

    /// 無制限のI/Oクォータ
    pub fn unlimited() -> Self {
        Self {
            rate_bytes_per_sec: u64::MAX,
            bucket_size: u64::MAX,
            tokens: AtomicU64::new(u64::MAX),
            last_refill_ns: AtomicU64::new(0),
        }
    }

    /// I/O操作を試行
    ///
    /// # Arguments
    /// * `bytes` - 転送バイト数
    /// * `current_time_ns` - 現在時刻（ナノ秒）
    ///
    /// # Returns
    /// 許可される場合 `Ok(())`、制限超過の場合 `Err(QuotaError)`
    pub fn try_io(&self, bytes: u64, current_time_ns: u64) -> Result<(), QuotaError> {
        // 無制限の場合は即座に許可
        if self.rate_bytes_per_sec == u64::MAX {
            return Ok(());
        }

        // トークンを補充
        self.refill_tokens(current_time_ns);

        let current_tokens = self.tokens.load(Ordering::Relaxed);
        if bytes > current_tokens {
            return Err(QuotaError::IoBandwidthExceeded {
                requested: bytes,
                available: current_tokens,
            });
        }

        // トークンを消費
        self.tokens.fetch_sub(bytes, Ordering::Relaxed);
        Ok(())
    }

    /// トークンを補充
    fn refill_tokens(&self, current_time_ns: u64) {
        let last_refill = self.last_refill_ns.load(Ordering::Relaxed);
        if current_time_ns <= last_refill {
            return;
        }

        let elapsed_ns = current_time_ns - last_refill;
        // 1秒 = 1_000_000_000 ナノ秒
        let tokens_to_add = (self.rate_bytes_per_sec * elapsed_ns) / 1_000_000_000;

        if tokens_to_add > 0 {
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + tokens_to_add).min(self.bucket_size);
            self.tokens.store(new_tokens, Ordering::Relaxed);
            self.last_refill_ns
                .store(current_time_ns, Ordering::Relaxed);
        }
    }

    /// 利用可能なトークン数を取得
    pub fn available_tokens(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }
}

/// 【設計書 9.3】ドメインクォータ
///
/// ドメインごとのリソース制限を管理します。
#[derive(Debug)]
pub struct DomainQuota {
    /// ドメインID
    pub domain_id: DomainId,
    /// ドメイン優先度
    pub priority: DomainPriority,
    /// CPU時間クォータ
    pub cpu: CpuQuota,
    /// メモリクォータ
    pub memory: MemoryQuota,
    /// ネットワークI/Oクォータ
    pub network_io: IoQuota,
    /// ストレージI/Oクォータ
    pub storage_io: IoQuota,
    /// クォータ違反カウンタ
    violation_count: AtomicU64,
}

impl DomainQuota {
    /// 新しいドメインクォータを作成
    pub fn new(domain_id: DomainId, priority: DomainPriority) -> Self {
        Self {
            domain_id,
            priority,
            cpu: CpuQuota::new(100, 100),  // デフォルト: 100ms期間で100%
            memory: MemoryQuota::new(256), // デフォルト: 256MB
            network_io: IoQuota::new(100, 10), // デフォルト: 100MB/s, 10MBバースト
            storage_io: IoQuota::new(50, 5), // デフォルト: 50MB/s, 5MBバースト
            violation_count: AtomicU64::new(0),
        }
    }

    /// カーネルドメイン用（無制限）
    pub fn kernel() -> Self {
        Self {
            domain_id: DomainId::KERNEL,
            priority: DomainPriority::Critical,
            cpu: CpuQuota::unlimited(),
            memory: MemoryQuota::unlimited(),
            network_io: IoQuota::unlimited(),
            storage_io: IoQuota::unlimited(),
            violation_count: AtomicU64::new(0),
        }
    }

    /// 違反カウントをインクリメント
    pub fn record_violation(&self) {
        self.violation_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 違反カウントを取得
    pub fn violation_count(&self) -> u64 {
        self.violation_count.load(Ordering::Relaxed)
    }

    /// クォータビルダー
    pub fn with_cpu_limit(mut self, limit_percent: u64, period_ms: u64) -> Self {
        self.cpu = CpuQuota::new(limit_percent, period_ms);
        self
    }

    pub fn with_memory_limit(mut self, limit_mb: u64) -> Self {
        self.memory = MemoryQuota::new(limit_mb);
        self
    }

    pub fn with_network_limit(mut self, rate_mbps: u64, burst_mb: u64) -> Self {
        self.network_io = IoQuota::new(rate_mbps, burst_mb);
        self
    }

    pub fn with_storage_limit(mut self, rate_mbps: u64, burst_mb: u64) -> Self {
        self.storage_io = IoQuota::new(rate_mbps, burst_mb);
        self
    }
}

/// クォータエラー
#[derive(Debug, Clone)]
pub enum QuotaError {
    /// CPU時間超過
    CpuTimeExceeded { domain_id: DomainId },
    /// メモリ超過
    MemoryExceeded {
        requested: u64,
        available: u64,
        limit: u64,
    },
    /// I/O帯域超過
    IoBandwidthExceeded { requested: u64, available: u64 },
    /// 割り当て競合（再試行が必要）
    AllocationRace,
}

impl core::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QuotaError::CpuTimeExceeded { domain_id } => {
                write!(f, "CPU quota exceeded for domain {}", domain_id)
            }
            QuotaError::MemoryExceeded {
                requested,
                available,
                limit,
            } => {
                write!(
                    f,
                    "Memory quota exceeded: requested {} bytes, available {} of {} limit",
                    requested, available, limit
                )
            }
            QuotaError::IoBandwidthExceeded {
                requested,
                available,
            } => {
                write!(
                    f,
                    "I/O bandwidth exceeded: requested {} bytes, available {} tokens",
                    requested, available
                )
            }
            QuotaError::AllocationRace => {
                write!(f, "Allocation race condition, retry required")
            }
        }
    }
}

// ============================================================================
// OOMキラー（設計書 9.3.3）
// ============================================================================

/// OOMキラーの判断結果
#[derive(Debug)]
pub struct OomVictim {
    pub domain_id: DomainId,
    pub priority: DomainPriority,
    pub memory_usage: u64,
    pub reason: &'static str,
}

/// 【設計書 9.3.3】OOMキラー戦略に基づいて犠牲ドメインを選択
///
/// 選択優先順位:
/// 1. 優先度が低いドメインを優先
/// 2. 同一優先度内ではメモリ消費量が多いドメインを優先
/// 3. Critical優先度のドメインは対象外
pub fn select_oom_victim(quotas: &BTreeMap<DomainId, DomainQuota>) -> Option<OomVictim> {
    let mut victim: Option<(DomainId, DomainPriority, u64)> = None;

    for (domain_id, quota) in quotas.iter() {
        // Critical優先度は対象外
        if quota.priority == DomainPriority::Critical {
            continue;
        }

        let memory_usage = quota.memory.used();

        match &victim {
            None => {
                victim = Some((*domain_id, quota.priority, memory_usage));
            }
            Some((_, current_priority, current_usage)) => {
                // 優先度が低いか、同一優先度でメモリ使用量が多い場合に更新
                if quota.priority < *current_priority
                    || (quota.priority == *current_priority && memory_usage > *current_usage)
                {
                    victim = Some((*domain_id, quota.priority, memory_usage));
                }
            }
        }
    }

    victim.map(|(domain_id, priority, memory_usage)| OomVictim {
        domain_id,
        priority,
        memory_usage,
        reason: "Selected by OOM killer based on priority and memory usage",
    })
}

// ============================================================================
// グローバルクォータマネージャ
// ============================================================================

/// ドメインクォータマネージャ
pub struct QuotaManager {
    /// ドメインID -> クォータのマッピング
    quotas: PoisonLock<BTreeMap<DomainId, DomainQuota>>,
}

impl QuotaManager {
    pub const fn new() -> Self {
        Self {
            quotas: PoisonLock::new(BTreeMap::new()),
        }
    }

    /// ドメインのクォータを登録
    pub fn register(&self, quota: DomainQuota) {
        let mut quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        quotas.insert(quota.domain_id, quota);
    }

    /// ドメインのクォータを削除
    pub fn unregister(&self, domain_id: DomainId) {
        let mut quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        quotas.remove(&domain_id);
    }

    /// メモリ割り当てを試行
    pub fn try_allocate_memory(&self, domain_id: DomainId, bytes: u64) -> Result<(), QuotaError> {
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(quota) = quotas.get(&domain_id) {
            quota.memory.try_allocate(bytes)
        } else {
            // 未登録ドメインは許可（カーネルなど）
            Ok(())
        }
    }

    /// メモリ解放を記録
    pub fn deallocate_memory(&self, domain_id: DomainId, bytes: u64) {
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(quota) = quotas.get(&domain_id) {
            quota.memory.deallocate(bytes);
        }
    }

    /// CPU時間を消費
    pub fn consume_cpu_time(
        &self,
        domain_id: DomainId,
        elapsed_ns: u64,
        current_time_ns: u64,
    ) -> bool {
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(quota) = quotas.get(&domain_id) {
            let exceeded = quota.cpu.consume(elapsed_ns, current_time_ns);
            if exceeded {
                quota.record_violation();
            }
            exceeded
        } else {
            false
        }
    }

    /// I/O操作を試行
    pub fn try_network_io(
        &self,
        domain_id: DomainId,
        bytes: u64,
        current_time_ns: u64,
    ) -> Result<(), QuotaError> {
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(quota) = quotas.get(&domain_id) {
            quota.network_io.try_io(bytes, current_time_ns)
        } else {
            Ok(())
        }
    }

    pub fn try_storage_io(
        &self,
        domain_id: DomainId,
        bytes: u64,
        current_time_ns: u64,
    ) -> Result<(), QuotaError> {
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(quota) = quotas.get(&domain_id) {
            quota.storage_io.try_io(bytes, current_time_ns)
        } else {
            Ok(())
        }
    }

    /// OOMキラーによる犠牲ドメイン選択
    pub fn select_oom_victim(&self) -> Option<OomVictim> {
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        select_oom_victim(&quotas)
    }

    /// ドメインの統計情報を取得
    pub fn get_stats(&self, domain_id: DomainId) -> Option<DomainStats> {
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        quotas.get(&domain_id).map(|q| DomainStats {
            domain_id,
            priority: q.priority,
            cpu_usage_ratio: q.cpu.usage_ratio(),
            memory_used: q.memory.used(),
            memory_limit: q.memory.limit_bytes,
            violation_count: q.violation_count(),
        })
    }
}

/// ドメイン統計情報
#[derive(Debug, Clone)]
pub struct DomainStats {
    pub domain_id: DomainId,
    pub priority: DomainPriority,
    pub cpu_usage_ratio: f64,
    pub memory_used: u64,
    pub memory_limit: u64,
    pub violation_count: u64,
}

/// グローバルクォータマネージャ
static QUOTA_MANAGER: QuotaManager = QuotaManager::new();

/// グローバルクォータマネージャへのアクセス
pub fn quota_manager() -> &'static QuotaManager {
    &QUOTA_MANAGER
}

/// クォータシステムの初期化
pub fn init() {
    // カーネルドメインを登録
    QUOTA_MANAGER.register(DomainQuota::kernel());
    log::info!("[Quota] Resource quota system initialized\n");
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_cpu_quota() {
        let quota = CpuQuota::new(50, 100); // 50%, 100ms period

        // 50%使用は許可
        assert!(!quota.consume(50_000_000, 0));

        // さらに10%追加で超過
        assert!(quota.is_exceeded() == false);
        assert!(quota.consume(10_000_000, 50_000_000));
        assert!(quota.is_exceeded());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_memory_quota() {
        let quota = MemoryQuota::new(1); // 1MB

        // 512KB割り当て成功
        assert!(quota.try_allocate(512 * 1024).is_ok());

        // さらに768KB割り当て失敗
        assert!(quota.try_allocate(768 * 1024).is_err());

        // 解放後は割り当て可能
        quota.deallocate(256 * 1024);
        assert!(quota.try_allocate(512 * 1024).is_ok());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_oom_victim_selection() {
        let mut quotas = BTreeMap::new();

        let mut q1 = DomainQuota::new(DomainId::new(1), DomainPriority::Normal);
        let _ = q1.memory.try_allocate(100 * 1024 * 1024);

        let mut q2 = DomainQuota::new(DomainId::new(2), DomainPriority::Low);
        let _ = q2.memory.try_allocate(50 * 1024 * 1024);

        let q3 = DomainQuota::new(DomainId::new(3), DomainPriority::Critical);

        quotas.insert(DomainId::new(1), q1);
        quotas.insert(DomainId::new(2), q2);
        quotas.insert(DomainId::new(3), q3);

        // Low優先度のドメイン2が選択される
        let victim = select_oom_victim(&quotas).unwrap();
        assert_eq!(victim.domain_id, DomainId::new(2));
    }
}
