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
use crate::domain::DomainId;
use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[path = "quota/memory.rs"]
mod memory;
use memory::MemoryAccount;
pub(crate) use memory::{MemoryBinding, MemoryCredit};

/// ドメイン優先度
///
/// OOMキラーおよびスケジューリング優先度に影響します。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DomainPriority {
    /// 最低優先度 - OOMキラーの最初の対象
    Low = 0,
    /// 通常優先度
    #[default]
    Normal = 1,
    /// 高優先度
    High = 2,
    /// クリティカル - OOMキラー対象外、カーネルコア用
    Critical = 3,
}

impl DomainPriority {
    pub const fn scheduler_weight(self) -> u64 {
        match self {
            Self::Low => 1,
            Self::Normal => 2,
            Self::High => 4,
            Self::Critical => 8,
        }
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
    period: PoisonLock<CpuQuotaPeriod>,
}

#[derive(Debug)]
struct CpuQuotaPeriod {
    used_ns: u64,
    start_ns: u64,
    exceeded: bool,
}

impl CpuQuotaPeriod {
    fn advance(&mut self, now_ns: u64, period_ns: u64) {
        let aligned_start = now_ns - now_ns % period_ns;
        if aligned_start > self.start_ns {
            self.start_ns = aligned_start;
            self.used_ns = 0;
            self.exceeded = false;
        }
    }
}

impl CpuQuota {
    /// Admission and period rollover share the same lock as charging. A
    /// deadline is returned only while this domain must wait for its period.
    pub fn wait_deadline(&self, now_ns: u64) -> Option<u64> {
        if self.limit_per_period_ns == u64::MAX {
            return None;
        }
        let mut period = self
            .period
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        period.advance(now_ns, self.period_ns);
        if period.used_ns >= self.limit_per_period_ns {
            Some(period.start_ns.saturating_add(self.period_ns))
        } else {
            None
        }
    }
    /// 新しいCPUクォータを作成
    ///
    /// # Arguments
    /// * `limit_percent` - CPU使用率の上限（0-100）
    /// * `period_ms` - 計測期間（ミリ秒）
    ///
    /// # Panics
    /// Panics if a configuration has no period, exceeds 100%, or its
    /// millisecond period cannot be represented in nanoseconds.
    pub fn new(limit_percent: u64, period_ms: u64) -> Self {
        assert!(limit_percent <= 100);
        let period_ns = period_ms
            .checked_mul(1_000_000)
            .filter(|period| *period != 0)
            .expect("quota period must be a positive nanosecond duration");
        let limit_per_period_ns =
            ((u128::from(period_ns) * u128::from(limit_percent)) / 100) as u64;

        Self {
            limit_per_period_ns,
            period_ns,
            period: PoisonLock::new(CpuQuotaPeriod {
                used_ns: 0,
                start_ns: 0,
                exceeded: false,
            }),
        }
    }

    /// 無制限のCPUクォータ
    pub fn unlimited() -> Self {
        Self {
            limit_per_period_ns: u64::MAX,
            period_ns: 100_000_000, // 100ms
            period: PoisonLock::new(CpuQuotaPeriod {
                used_ns: 0,
                start_ns: 0,
                exceeded: false,
            }),
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
        let mut period = self
            .period
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        period.advance(current_time_ns, self.period_ns);
        // A fragment spans [end - elapsed, end). Charge only its intersection
        // with the current fixed period. Late SMP charges never roll time back.
        let fragment_start = current_time_ns.saturating_sub(elapsed_ns);
        let charged = current_time_ns.saturating_sub(fragment_start.max(period.start_ns));
        period.used_ns = period.used_ns.saturating_add(charged);
        period.exceeded =
            self.limit_per_period_ns != u64::MAX && period.used_ns >= self.limit_per_period_ns;
        period.exceeded
    }

    /// クォータ超過しているかチェック
    pub fn is_exceeded(&self) -> bool {
        self.period
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .exceeded
    }

    /// 使用率を取得（0.0-1.0）
    pub fn usage_ratio(&self) -> f64 {
        let used = self
            .period
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .used_ns;
        if self.limit_per_period_ns == 0 {
            return 0.0;
        }
        (used as f64) / (self.limit_per_period_ns as f64)
    }

    /// リセット
    pub fn reset(&self) {
        let mut period = self
            .period
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        period.used_ns = 0;
        period.exceeded = false;
    }
}

/// Memory admission policy. Usage belongs to the registered stable account,
/// so replacing policy cannot reset charges held by live allocations.
#[derive(Debug)]
pub struct MemoryQuota {
    pub limit_bytes: u64,
    pub warning_threshold_percent: u64,
}

impl MemoryQuota {
    pub const fn from_bytes(limit_bytes: u64) -> Self {
        Self {
            limit_bytes,
            warning_threshold_percent: 80,
        }
    }

    pub const fn unlimited() -> Self {
        Self {
            limit_bytes: u64::MAX,
            warning_threshold_percent: 100,
        }
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
            cpu: CpuQuota::new(100, 100), // デフォルト: 100ms期間で100%
            memory: MemoryQuota::from_bytes(256 * 1024 * 1024), // デフォルト: 256MB
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

    pub fn with_memory_limit_bytes(mut self, limit_bytes: u64) -> Self {
        self.memory = MemoryQuota::from_bytes(limit_bytes);
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
pub use kernel_api::resource::domain::QuotaError;

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

/// Policy registry owns every account until all execution bindings and memory
/// credits have returned. Registration/observation is cold; allocation and
/// cross-CPU free use a binding/credit directly and never acquire this lock.
pub struct QuotaManager {
    quotas: PoisonLock<Vec<RegisteredQuota>>,
}

struct RegisteredQuota {
    policy: DomainQuota,
    memory: Box<MemoryAccount>,
}

impl QuotaManager {
    pub const fn new() -> Self {
        Self {
            quotas: PoisonLock::new(Vec::new()),
        }
    }

    /// Publish policy without resetting usage. A retired account with outstanding
    /// bindings or credits cannot be reused, even for the same domain identity.
    /// Metadata is prepared outside the lock, because its allocation may enter OOM.
    pub fn register(&self, quota: DomainQuota) -> Result<(), QuotaError> {
        let needed = {
            let mut quotas = self
                .quotas
                .lock()
                .map_err(|_| QuotaError::RegistryUnavailable)?;
            if let Some(entry) = quotas
                .iter_mut()
                .find(|q| q.policy.domain_id == quota.domain_id)
            {
                if entry.memory.is_open() {
                    entry.update(quota);
                    return Ok(());
                }
                if !entry.memory.can_reclaim() {
                    return Err(QuotaError::Retired {
                        domain_id: quota.domain_id,
                    });
                }
            }
            quotas
                .len()
                .checked_add(1)
                .ok_or(QuotaError::AccountingOverflow)?
        };
        let memory = Box::try_new(MemoryAccount::new(
            quota.domain_id,
            quota.memory.limit_bytes,
        ))
        .map_err(|_| QuotaError::MetadataAllocationFailed)?;
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(needed)
            .map_err(|_| QuotaError::MetadataAllocationFailed)?;
        let mut quotas = self
            .quotas
            .lock()
            .map_err(|_| QuotaError::RegistryUnavailable)?;
        // A concurrent registration may have created or updated the same identity.
        if let Some(index) = quotas
            .iter()
            .position(|q| q.policy.domain_id == quota.domain_id)
        {
            let entry = &mut quotas[index];
            if entry.memory.is_open() {
                entry.update(quota);
                return Ok(());
            }
            if !entry.memory.can_reclaim() {
                return Err(QuotaError::Retired {
                    domain_id: quota.domain_id,
                });
            }
            // Replacement is one locked publication. Appending beside a closed
            // account would let another registration select that old account
            // and publish a second live return target for the same identity.
            let retired = core::mem::replace(
                entry,
                RegisteredQuota {
                    policy: quota,
                    memory,
                },
            );
            drop(quotas);
            drop(retired);
            drop(prepared);
            self.collect_retired();
            return Ok(());
        }
        let required = quotas
            .len()
            .checked_add(1)
            .ok_or(QuotaError::AccountingOverflow)?;
        if quotas.capacity() < required && prepared.capacity() < required {
            return Err(QuotaError::AllocationRace);
        }
        if quotas.capacity() < required {
            prepared.extend(quotas.drain(..));
            core::mem::swap(&mut *quotas, &mut prepared);
        }
        quotas.push(RegisteredQuota {
            policy: quota,
            memory,
        });
        drop(quotas);
        drop(prepared);
        self.collect_retired();
        Ok(())
    }

    /// Revocation stops admission without allocating or destroying metadata.
    /// This may run under the domain registry lock. Cold registration, statistics
    /// and victim selection collect quiescent accounts outside that lock.
    pub fn unregister(&self, domain_id: DomainId) {
        let quotas = self
            .quotas
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for entry in quotas.iter().filter(|q| q.policy.domain_id == domain_id) {
            entry.memory.close();
        }
    }

    /// Update an admitted domain without acquiring metadata. Callers that hold a
    /// domain registry lock may use this path; creating an account requires the
    /// separate fallible registration operation outside that lock.
    pub(crate) fn update_policy(&self, policy: DomainQuota) -> Result<(), QuotaError> {
        let mut quotas = self
            .quotas
            .lock()
            .map_err(|_| QuotaError::RegistryUnavailable)?;
        let entry = quotas
            .iter_mut()
            .find(|q| q.policy.domain_id == policy.domain_id)
            .ok_or(QuotaError::Unregistered {
                domain_id: policy.domain_id,
            })?;
        if !entry.memory.is_open() {
            return Err(QuotaError::Retired {
                domain_id: policy.domain_id,
            });
        }
        entry.update(policy);
        Ok(())
    }

    /// Binding is acquired on execution entry, outside the allocator hot path.
    pub(crate) fn bind_memory(&self, domain_id: DomainId) -> Result<MemoryBinding, QuotaError> {
        if domain_id == DomainId::KERNEL {
            return Ok(MemoryBinding::kernel());
        }
        let quotas = self
            .quotas
            .lock()
            .map_err(|_| QuotaError::RegistryUnavailable)?;
        let entry = quotas
            .iter()
            .find(|q| q.policy.domain_id == domain_id && q.memory.is_open())
            .ok_or_else(|| {
                if quotas.iter().any(|q| q.policy.domain_id == domain_id) {
                    QuotaError::Retired { domain_id }
                } else {
                    QuotaError::Unregistered { domain_id }
                }
            })?;
        entry.memory.bind()
    }

    /// Destruction happens outside the registry lock: freeing metadata can invoke
    /// other allocator boundaries. Credits and bindings independently pin accounts.
    fn collect_retired(&self) {
        // LOOP_PROOF: mode=event; reason=Each iteration removes one quiescent account and exits when no reclaimable retired entry remains.;
        loop {
            let retired = {
                let mut quotas = self
                    .quotas
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let Some(index) = quotas
                    .iter()
                    .position(|q| !q.memory.is_open() && q.memory.can_reclaim())
                else {
                    break;
                };
                quotas.swap_remove(index)
            };
            drop(retired);
        }
    }

    pub fn consume_cpu_time(
        &self,
        domain_id: DomainId,
        elapsed_ns: u64,
        current_time_ns: u64,
    ) -> bool {
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(quota) = quotas
            .iter()
            .find(|q| q.policy.domain_id == domain_id && q.memory.is_open())
        {
            let exceeded = quota.policy.cpu.consume(elapsed_ns, current_time_ns);
            if exceeded {
                quota.policy.record_violation();
            }
            exceeded
        } else {
            false
        }
    }

    pub(crate) fn scheduler_weight(&self, domain: DomainId) -> u64 {
        let quotas = self
            .quotas
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        quotas
            .iter()
            .find(|entry| entry.policy.domain_id == domain)
            .map_or(DomainPriority::Normal.scheduler_weight(), |entry| {
                entry.policy.priority.scheduler_weight()
            })
    }

    pub(crate) fn cpu_wait_deadline(&self, domain_id: DomainId, now_ns: u64) -> Option<u64> {
        let quotas = self
            .quotas
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        quotas
            .iter()
            .find(|entry| entry.policy.domain_id == domain_id)
            .and_then(|entry| entry.policy.cpu.wait_deadline(now_ns))
    }

    /// I/O操作を試行
    pub fn try_network_io(
        &self,
        domain_id: DomainId,
        bytes: u64,
        current_time_ns: u64,
    ) -> Result<(), QuotaError> {
        let quotas = self
            .quotas
            .lock()
            .map_err(|_| QuotaError::RegistryUnavailable)?;
        quotas
            .iter()
            .find(|q| q.policy.domain_id == domain_id && q.memory.is_open())
            .ok_or(QuotaError::Unregistered { domain_id })?
            .policy
            .network_io
            .try_io(bytes, current_time_ns)
    }

    pub fn try_storage_io(
        &self,
        domain_id: DomainId,
        bytes: u64,
        current_time_ns: u64,
    ) -> Result<(), QuotaError> {
        let quotas = self
            .quotas
            .lock()
            .map_err(|_| QuotaError::RegistryUnavailable)?;
        quotas
            .iter()
            .find(|q| q.policy.domain_id == domain_id && q.memory.is_open())
            .ok_or(QuotaError::Unregistered { domain_id })?
            .policy
            .storage_io
            .try_io(bytes, current_time_ns)
    }

    pub fn select_oom_victim(&self) -> Option<OomVictim> {
        self.collect_retired();
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        quotas
            .iter()
            .filter(|q| q.memory.is_open() && q.policy.priority != DomainPriority::Critical)
            .min_by_key(|q| (q.policy.priority, core::cmp::Reverse(q.memory.used())))
            .map(|q| OomVictim {
                domain_id: q.policy.domain_id,
                priority: q.policy.priority,
                memory_usage: q.memory.used(),
                reason: "Selected by priority and charged memory",
            })
    }

    /// Retired accounts remain observable until their last retained owner returns.
    pub fn get_stats(&self, domain_id: DomainId) -> Option<DomainStats> {
        self.collect_retired();
        let quotas = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        quotas
            .iter()
            .find(|q| q.policy.domain_id == domain_id)
            .map(|q| DomainStats {
                domain_id,
                priority: q.policy.priority,
                cpu_usage_ratio: q.policy.cpu.usage_ratio(),
                memory_used: q.memory.used(),
                memory_limit: q.memory.limit(),
                violation_count: q.policy.violation_count(),
            })
    }
}

impl RegisteredQuota {
    fn update(&mut self, policy: DomainQuota) {
        // CPU and I/O accounting also survives a policy-only update.
        assert_eq!(self.policy.cpu.period_ns, policy.cpu.period_ns);
        let previous = self
            .policy
            .cpu
            .period
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut replacement = policy
            .cpu
            .period
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        replacement.used_ns = previous.used_ns;
        replacement.start_ns = previous.start_ns;
        replacement.exceeded = policy.cpu.limit_per_period_ns != u64::MAX
            && previous.used_ns >= policy.cpu.limit_per_period_ns;
        drop(replacement);
        drop(previous);
        policy.network_io.tokens.store(
            self.policy
                .network_io
                .available_tokens()
                .min(policy.network_io.bucket_size),
            Ordering::Relaxed,
        );
        policy.network_io.last_refill_ns.store(
            self.policy
                .network_io
                .last_refill_ns
                .load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        policy.storage_io.tokens.store(
            self.policy
                .storage_io
                .available_tokens()
                .min(policy.storage_io.bucket_size),
            Ordering::Relaxed,
        );
        policy.storage_io.last_refill_ns.store(
            self.policy
                .storage_io
                .last_refill_ns
                .load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        policy
            .violation_count
            .store(self.policy.violation_count(), Ordering::Relaxed);
        self.memory.set_limit(policy.memory.limit_bytes);
        self.policy = policy;
    }
}

impl Drop for QuotaManager {
    fn drop(&mut self) {
        let mut quotas = self
            .quotas
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Production registry is image-lived. A shorter-lived owner must retain
        // backing with outstanding return rights; forgetting a credit can leak
        // accounting, but never lets a later cross-CPU return touch freed RAM.
        for entry in quotas.drain(..) {
            entry.memory.close();
            if !entry.memory.can_reclaim() {
                core::mem::forget(entry.memory);
            }
        }
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
    QUOTA_MANAGER
        .register(DomainQuota::kernel())
        .expect("quota metadata required for kernel startup");
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
    fn cpu_quota_counts_fragments_and_reopens_after_the_period() {
        let quota = CpuQuota::new(10, 100);
        assert!(!quota.consume(4_000_000, 4_000_000));
        // Waiting for the next fragment consumes no CPU quota.
        assert_eq!(quota.wait_deadline(80_000_000), None);
        assert!(quota.consume(6_000_000, 86_000_000));
        assert_eq!(quota.wait_deadline(99_999_999), Some(100_000_000));
        assert_eq!(quota.wait_deadline(100_000_000), None);
        assert!(!quota.is_exceeded());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn cpu_quota_serializes_late_smp_charges_without_rewinding_the_period() {
        let quota = CpuQuota::new(10, 100);
        // CPU A returns across the period boundary: only [100ms, 105ms)
        // belongs to the current window.
        assert!(!quota.consume(10_000_000, 105_000_000));
        // CPU B's late previous-window fragment contributes nothing to it.
        assert!(!quota.consume(20_000_000, 99_000_000));
        assert_eq!(quota.wait_deadline(99_000_000), None);
        // Another CPU's overlapping execution is separate CPU time.
        assert!(quota.consume(5_000_000, 105_000_000));
        assert_eq!(quota.wait_deadline(105_000_000), Some(200_000_000));
        assert_eq!(quota.wait_deadline(200_000_000), None);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_cpu_quota() {
        let quota = CpuQuota::new(50, 100); // 50%, 100ms period

        // 50%使用は許可
        assert!(quota.consume(50_000_000, 50_000_000));

        // さらに10%追加で超過
        assert!(quota.is_exceeded());
        assert!(quota.consume(10_000_000, 60_000_000));
        assert!(quota.is_exceeded());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_memory_quota() {
        let manager = QuotaManager::new();
        let id = DomainId::new(1);
        manager
            .register(
                DomainQuota::new(id, DomainPriority::Normal).with_memory_limit_bytes(1024 * 1024),
            )
            .unwrap();
        let binding = manager.bind_memory(id).unwrap();
        let first = binding.reserve(512 * 1024).unwrap();
        assert!(matches!(
            binding.reserve(768 * 1024),
            Err(QuotaError::MemoryExceeded { .. })
        ));
        drop(first);
        let second = binding.reserve(1024 * 1024).unwrap();
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 1024 * 1024);
        drop(second);
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_oom_victim_selection() {
        let manager = QuotaManager::new();
        for (id, priority) in [
            (1, DomainPriority::Normal),
            (2, DomainPriority::Low),
            (3, DomainPriority::Critical),
        ] {
            manager
                .register(DomainQuota::new(DomainId::new(id), priority))
                .unwrap();
        }
        let binding1 = manager.bind_memory(DomainId::new(1)).unwrap();
        let binding2 = manager.bind_memory(DomainId::new(2)).unwrap();
        let _first = binding1.reserve(100 * 1024 * 1024).unwrap();
        let _second = binding2.reserve(50 * 1024 * 1024).unwrap();
        assert_eq!(
            manager.select_oom_victim().unwrap().domain_id,
            DomainId::new(2)
        );
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn policy_changes_preserve_live_charges_and_exact_byte_limits() {
        let manager = QuotaManager::new();
        let id = DomainId::new(11);
        manager
            .register(DomainQuota::new(id, DomainPriority::Normal).with_memory_limit_bytes(513))
            .unwrap();
        let binding = manager.bind_memory(id).unwrap();
        let credit = binding.reserve(512).unwrap();
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 512);
        manager
            .register(DomainQuota::new(id, DomainPriority::High).with_memory_limit_bytes(511))
            .unwrap();
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 512);
        assert!(matches!(
            binding.reserve(1),
            Err(QuotaError::MemoryExceeded {
                available: 0,
                limit: 511,
                ..
            })
        ));
        drop(credit);
        assert!(binding.reserve(511).is_ok());
        assert!(matches!(
            binding.reserve(512),
            Err(QuotaError::MemoryExceeded { .. })
        ));
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 0);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn retirement_preserves_return_target_and_waits_for_bindings() {
        let manager = QuotaManager::new();
        let id = DomainId::new(12);
        manager
            .register(DomainQuota::new(id, DomainPriority::Low))
            .unwrap();
        let binding = manager.bind_memory(id).unwrap();
        let credit = binding.reserve(777).unwrap();
        manager.unregister(id);
        assert!(matches!(
            binding.reserve(1),
            Err(QuotaError::Retired { .. })
        ));
        assert!(matches!(
            manager.bind_memory(id),
            Err(QuotaError::Retired { .. })
        ));
        assert!(matches!(
            manager.register(DomainQuota::new(id, DomainPriority::Normal)),
            Err(QuotaError::Retired { .. })
        ));
        drop(binding);
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 777);
        drop(credit);
        assert!(manager.get_stats(id).is_none());
        manager
            .register(DomainQuota::new(id, DomainPriority::Normal))
            .unwrap();
        let next = manager.bind_memory(id).unwrap();
        assert!(next.reserve(1).is_ok());
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 0);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn missing_account_zero_size_and_unlimited_overflow_are_distinct() {
        let manager = QuotaManager::new();
        let id = DomainId::new(13);
        assert!(matches!(
            manager.bind_memory(id),
            Err(QuotaError::Unregistered { .. })
        ));
        assert!(
            manager
                .bind_memory(DomainId::KERNEL)
                .unwrap()
                .reserve(99)
                .unwrap()
                .is_none()
        );
        manager
            .register(
                DomainQuota::new(id, DomainPriority::Normal).with_memory_limit_bytes(u64::MAX),
            )
            .unwrap();
        let binding = manager.bind_memory(id).unwrap();
        assert!(matches!(binding.reserve(0), Err(QuotaError::InvalidSize)));
        let entire = binding.reserve(u64::MAX).unwrap();
        assert!(matches!(
            binding.reserve(1),
            Err(QuotaError::AccountingOverflow)
        ));
        assert_eq!(manager.get_stats(id).unwrap().memory_used, u64::MAX);
        drop(entire);
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 0);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn quota_matches_independent_live_allocation_model() {
        let manager = QuotaManager::new();
        let id = DomainId::new(14);
        manager
            .register(DomainQuota::new(id, DomainPriority::Normal).with_memory_limit_bytes(1023))
            .unwrap();
        let binding = manager.bind_memory(id).unwrap();
        let mut live = Vec::new();
        let mut expected = 0;
        let mut sequence = 0x91c4_u32;
        for _ in 0..2000 {
            sequence = sequence.wrapping_mul(1664525).wrapping_add(1013904223);
            if sequence & 3 == 0 && !live.is_empty() {
                let index = sequence as usize % live.len();
                let (bytes, owner) = live.swap_remove(index);
                expected -= bytes;
                drop(owner);
            } else {
                let bytes = u64::from((sequence >> 8) % 300 + 1);
                let fits = expected + bytes <= 1023;
                match binding.reserve(bytes) {
                    Ok(owner) => {
                        assert!(fits);
                        expected += bytes;
                        live.push((bytes, owner));
                    }
                    Err(QuotaError::MemoryExceeded { .. }) => assert!(!fits),
                    result => panic!("unexpected quota model result: {result:?}"),
                }
            }
            assert_eq!(manager.get_stats(id).unwrap().memory_used, expected);
        }
        drop(live);
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 0);
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn concurrent_return_and_retirement_keep_exact_usage() {
        let manager = QuotaManager::new();
        let id = DomainId::new(15);
        manager
            .register(DomainQuota::new(id, DomainPriority::Normal).with_memory_limit_bytes(65536))
            .unwrap();
        let binding = manager.bind_memory(id).unwrap();
        let credits: Vec<_> = (0..1024).map(|_| binding.reserve(64).unwrap()).collect();
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 65536);
        manager.unregister(id);
        drop(binding);
        std::thread::scope(|scope| {
            for (index, credit) in credits.into_iter().enumerate() {
                scope.spawn(move || {
                    if index % 3 == 0 {
                        std::thread::yield_now();
                    }
                    drop(credit);
                });
                // Observation may reclaim only after the final credit returned.
                if let Some(stats) = manager.get_stats(id) {
                    assert!(stats.memory_used <= 65536);
                }
            }
        });
        assert!(manager.get_stats(id).is_none());
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn quiescent_retirement_replaces_the_account_in_one_publication() {
        let manager = QuotaManager::new();
        let id = DomainId::new(19);
        manager
            .register(DomainQuota::new(id, DomainPriority::Normal).with_memory_limit_bytes(1024))
            .unwrap();
        // Retirement releases the registry lock before collecting. Establish
        // that real transition boundary without relying on thread scheduling.
        manager
            .quotas
            .lock()
            .unwrap_or_else(|_| panic!("fixture quota lock poisoned"))[0]
            .memory
            .close();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    manager
                        .register(
                            DomainQuota::new(id, DomainPriority::Normal)
                                .with_memory_limit_bytes(1024),
                        )
                        .unwrap();
                });
            }
        });
        assert_eq!(
            manager
                .quotas
                .lock()
                .unwrap_or_else(|_| panic!("fixture quota lock poisoned"))
                .len(),
            1
        );
        let binding = manager.bind_memory(id).unwrap();
        let credit = binding.reserve(1024).unwrap();
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 1024);
        manager
            .register(DomainQuota::new(id, DomainPriority::Low).with_memory_limit_bytes(1024))
            .unwrap();
        assert!(matches!(
            binding.reserve(1),
            Err(QuotaError::MemoryExceeded { .. })
        ));
        drop(credit);
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 0);
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn credit_retains_backing_when_registry_owner_is_dropped() {
        let manager = QuotaManager::new();
        let id = DomainId::new(16);
        manager
            .register(DomainQuota::new(id, DomainPriority::Normal))
            .unwrap();
        let binding = manager.bind_memory(id).unwrap();
        let credit = binding.reserve(23).unwrap();
        drop(manager);
        assert!(matches!(
            binding.reserve(1),
            Err(QuotaError::Retired { .. })
        ));
        std::thread::spawn(move || drop(credit)).join().unwrap();
        drop(binding);
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn competing_reservations_cannot_over_admit_byte_budget() {
        let manager = QuotaManager::new();
        let id = DomainId::new(17);
        manager
            .register(DomainQuota::new(id, DomainPriority::Normal).with_memory_limit_bytes(1000))
            .unwrap();
        let binding = manager.bind_memory(id).unwrap();
        let credits = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..4 {
                let binding = &binding;
                workers.push(scope.spawn(move || {
                    let mut credits = Vec::new();
                    for _ in 0..4000 {
                        match binding.reserve(1) {
                            Ok(credit) => credits.push(credit),
                            Err(QuotaError::AllocationRace) => continue,
                            Err(QuotaError::MemoryExceeded { .. }) => break,
                            result => panic!("unexpected concurrent admission: {result:?}"),
                        }
                    }
                    credits
                }));
            }
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(credits.iter().map(Vec::len).sum::<usize>(), 1000);
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 1000);
        drop(credits);
        assert_eq!(manager.get_stats(id).unwrap().memory_used, 0);
    }
}
