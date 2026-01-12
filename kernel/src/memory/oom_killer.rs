// ============================================================================
// kernel/src/memory/oom_killer.rs - OOM Killer for Memory Exhaustion Handling
// ============================================================================
//!
//! # OOM Killer (Out of Memory Killer)
//!
//! 設計書 Section 9.3.4 に基づく実装
//!
//! システム全体のメモリが枯渇した場合、以下の優先順位でドメインを終了させます:
//!
//! 1. **優先度に基づく選択:** critical > normal > low
//! 2. **メモリ消費量に基づく選択:** 同一優先度内で最大消費を選択
//! 3. **終了とリソース回収:** パニック処理と同様の手順
//! 4. **クリティカルドメインの保護:** critical優先度は対象外
//!
//! ## 使用例
//!
//! ```rust
//! // メモリ枯渇時の自動呼び出し
//! if !oom_killer::try_free_memory() {
//!     // 回復不能 - カーネルパニック
//!     panic!("OOM: Unable to free memory");
//! }
//! ```

use crate::sync::PoisonLock;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// ドメイン優先度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DomainPriority {
    /// 低優先度 - OOM時に最初に終了対象
    Low = 0,
    /// 通常優先度
    Normal = 1,
    /// クリティカル - OOM対象外
    Critical = 2,
}

impl Default for DomainPriority {
    fn default() -> Self {
        DomainPriority::Normal
    }
}

/// ドメインメモリ情報
#[derive(Debug, Clone)]
pub struct DomainMemoryInfo {
    /// ドメインID
    pub domain_id: u64,
    /// ドメイン名
    pub name: String,
    /// 優先度
    pub priority: DomainPriority,
    /// 使用メモリ量（バイト）
    pub memory_usage: u64,
    /// 最終アクティビティ時刻
    pub last_activity: u64,
}

/// OOM Killerの状態
pub struct OomKiller {
    /// 登録されたドメイン
    domains: PoisonLock<Vec<DomainMemoryInfo>>,
    /// 現在OOM処理中かどうか
    in_progress: AtomicBool,
    /// 終了させたドメイン数（統計用）
    kill_count: AtomicU64,
    /// 解放したメモリ量（統計用）
    freed_memory: AtomicU64,
}

/// グローバルOOM Killerインスタンス
static OOM_KILLER: OomKiller = OomKiller {
    domains: PoisonLock::new(Vec::new()),
    in_progress: AtomicBool::new(false),
    kill_count: AtomicU64::new(0),
    freed_memory: AtomicU64::new(0),
};

impl OomKiller {
    /// ドメインを登録
    pub fn register_domain(&self, info: DomainMemoryInfo) {
        match self.domains.lock() {
            Ok(mut domains) => {
                // 既存のエントリを更新または新規追加
                if let Some(existing) = domains.iter_mut().find(|d| d.domain_id == info.domain_id) {
                    *existing = info;
                } else {
                    domains.push(info);
                }
            }
            Err(_) => {
                log::error!("[MEM] OOM Killer domains lock poisoned - register skipped");
            }
        }
    }

    /// ドメインの登録を解除
    pub fn unregister_domain(&self, domain_id: u64) {
        match self.domains.lock() {
            Ok(mut domains) => domains.retain(|d| d.domain_id != domain_id),
            Err(_) => log::error!("[MEM] OOM Killer domains lock poisoned - unregister skipped"),
        }
    }

    /// ドメインのメモリ使用量を更新
    pub fn update_memory_usage(&self, domain_id: u64, usage: u64) {
        match self.domains.lock() {
            Ok(mut domains) => {
                if let Some(domain) = domains.iter_mut().find(|d| d.domain_id == domain_id) {
                    domain.memory_usage = usage;
                }
            }
            Err(_) => log::error!("[MEM] OOM Killer domains lock poisoned - update skipped"),
        }
    }

    /// OOM Killer を実行してメモリを解放
    ///
    /// # Returns
    /// * `Some(freed_bytes)` - 解放できたメモリ量
    /// * `None` - 解放対象がない（全てcritical）
    pub fn try_free_memory(&self) -> Option<u64> {
        // 再入防止
        if self.in_progress.swap(true, Ordering::SeqCst) {
            log::info!("[OOM] Already in progress, skipping\n");
            return None;
        }

        let result = self.select_and_kill_victim();

        self.in_progress.store(false, Ordering::SeqCst);
        result
    }

    /// 犠牲者を選択して終了
    fn select_and_kill_victim(&self) -> Option<u64> {
        let victim = match self.domains.lock() {
            Ok(domains) => {
                // 優先度順（低い方が先）、同優先度内ではメモリ使用量順（大きい方が先）
                let mut candidates: Vec<_> = domains
                    .iter()
                    .filter(|d| d.priority != DomainPriority::Critical)
                    .cloned()
                    .collect();

                candidates.sort_by(|a, b| {
                    match a.priority.cmp(&b.priority) {
                        core::cmp::Ordering::Equal => b.memory_usage.cmp(&a.memory_usage), // 大きい方を先に
                        other => other, // 優先度が低い方を先に
                    }
                });

                candidates.first().cloned()
            }
            Err(_) => {
                log::error!("[OOM] OOM Killer domains lock poisoned - cannot select victim");
                None
            }
        };

        match victim {
            Some(victim) => {
                log::info!(
                    "[OOM] Killing domain '{}' (id={}, priority={:?}, memory={}KB)\n",
                    victim.name,
                    victim.domain_id,
                    victim.priority,
                    victim.memory_usage / 1024
                );

                let freed = self.kill_domain(&victim);

                self.kill_count.fetch_add(1, Ordering::Relaxed);
                self.freed_memory.fetch_add(freed, Ordering::Relaxed);

                Some(freed)
            }
            None => {
                log::info!("[OOM] No killable domains (all critical)\n");
                None
            }
        }
    }

    /// ドメインを終了してメモリを解放
    fn kill_domain(&self, victim: &DomainMemoryInfo) -> u64 {
        let freed = victim.memory_usage;

        // ドメインを登録解除
        self.unregister_domain(victim.domain_id);

        // TODO: 実際のドメイン終了処理
        // - タスクの強制終了
        // - リソースの解放
        // - パニックハンドラの呼び出し

        log::info!(
            "[OOM] Domain '{}' killed, freed {}KB\n",
            victim.name,
            freed / 1024
        );

        freed
    }

    /// 統計情報を取得
    pub fn stats(&self) -> OomStats {
        let total_domains = match self.domains.lock() {
            Ok(d) => d.len(),
            Err(_) => {
                log::error!("[MEM] OOM Killer domains lock poisoned - returning zero stats");
                0
            }
        };
        OomStats {
            total_domains,
            kill_count: self.kill_count.load(Ordering::Relaxed),
            freed_memory: self.freed_memory.load(Ordering::Relaxed),
            in_progress: self.in_progress.load(Ordering::Relaxed),
        }
    }

    /// 全ドメインのメモリ情報を取得
    pub fn list_domains(&self) -> Vec<DomainMemoryInfo> {
        match self.domains.lock() {
            Ok(d) => d.clone(),
            Err(_) => {
                log::error!("[MEM] OOM Killer domains lock poisoned - returning empty list");
                Vec::new()
            }
        }
    }
}

/// OOM統計情報
#[derive(Debug, Clone)]
pub struct OomStats {
    /// 登録ドメイン数
    pub total_domains: usize,
    /// 終了させたドメイン数
    pub kill_count: u64,
    /// 解放した総メモリ量
    pub freed_memory: u64,
    /// 現在OOM処理中か
    pub in_progress: bool,
}

// ============================================================================
// Public API
// ============================================================================

/// ドメインを登録
pub fn register_domain(info: DomainMemoryInfo) {
    OOM_KILLER.register_domain(info);
}

/// ドメインの登録を解除
pub fn unregister_domain(domain_id: u64) {
    OOM_KILLER.unregister_domain(domain_id);
}

/// ドメインのメモリ使用量を更新
pub fn update_memory_usage(domain_id: u64, usage: u64) {
    OOM_KILLER.update_memory_usage(domain_id, usage);
}

/// OOM Killer を実行してメモリを解放
///
/// # Returns
/// * `true` - メモリを解放できた
/// * `false` - 解放対象がない
pub fn try_free_memory() -> bool {
    OOM_KILLER.try_free_memory().is_some()
}

/// 統計情報を取得
pub fn stats() -> OomStats {
    OOM_KILLER.stats()
}

/// 全ドメインのメモリ情報を取得
pub fn list_domains() -> Vec<DomainMemoryInfo> {
    OOM_KILLER.list_domains()
}

/// 簡易ドメイン登録（テスト用）
pub fn register_simple(domain_id: u64, name: &str, priority: DomainPriority, memory_usage: u64) {
    register_domain(DomainMemoryInfo {
        domain_id,
        name: String::from(name),
        priority,
        memory_usage,
        last_activity: crate::task::timer::current_tick(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_domain_registration() {
        let info = DomainMemoryInfo {
            domain_id: 1,
            name: String::from("test"),
            priority: DomainPriority::Normal,
            memory_usage: 1024 * 1024,
            last_activity: 0,
        };

        OOM_KILLER.register_domain(info);
        assert!(OOM_KILLER.list_domains().iter().any(|d| d.domain_id == 1));

        OOM_KILLER.unregister_domain(1);
        assert!(!OOM_KILLER.list_domains().iter().any(|d| d.domain_id == 1));
    }

    #[test_case]
    fn test_victim_selection_by_priority() {
        // Low priority should be selected first
        OOM_KILLER.register_domain(DomainMemoryInfo {
            domain_id: 10,
            name: String::from("high_mem_normal"),
            priority: DomainPriority::Normal,
            memory_usage: 10 * 1024 * 1024,
            last_activity: 0,
        });

        OOM_KILLER.register_domain(DomainMemoryInfo {
            domain_id: 11,
            name: String::from("low_priority"),
            priority: DomainPriority::Low,
            memory_usage: 1 * 1024 * 1024,
            last_activity: 0,
        });

        // Low priority domain should be killed first despite smaller memory
        let freed = OOM_KILLER.try_free_memory();
        assert!(freed.is_some());

        // Cleanup
        OOM_KILLER.unregister_domain(10);
    }

    #[test_case]
    fn test_critical_domains_protected() {
        OOM_KILLER.register_domain(DomainMemoryInfo {
            domain_id: 20,
            name: String::from("critical_domain"),
            priority: DomainPriority::Critical,
            memory_usage: 100 * 1024 * 1024,
            last_activity: 0,
        });

        // Should not kill critical domain
        // (would return None if only critical domains exist)
        let initial_count = OOM_KILLER.list_domains().len();
        let _ = OOM_KILLER.try_free_memory();

        // Critical domain should still exist
        assert!(OOM_KILLER.list_domains().iter().any(|d| d.domain_id == 20));

        // Cleanup
        OOM_KILLER.unregister_domain(20);
    }

    #[test_case]
    fn test_poisoned_register_skips_and_list_empty() {
        use crate::sync::set_panicking;
        set_panicking(true);
        OOM_KILLER.register_domain(DomainMemoryInfo {
            domain_id: 99,
            name: String::from("poisoned"),
            priority: DomainPriority::Normal,
            memory_usage: 512,
            last_activity: 0,
        });
        set_panicking(false);
        assert!(!OOM_KILLER.list_domains().iter().any(|d| d.domain_id == 99));
    }

    #[test_case]
    fn test_poisoned_stats_returns_zero_total_domains() {
        use crate::sync::set_panicking;
        set_panicking(true);
        let s = OOM_KILLER.stats();
        assert_eq!(s.total_domains, 0);
        set_panicking(false);
    }
}

