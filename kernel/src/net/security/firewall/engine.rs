// ============================================================================
// kernel/src/net/security/firewall/engine.rs - ファイアウォールエンジン
// ============================================================================
//! ルール評価エンジン。
//!
//! 優先度順にソートされたルールリストを線形走査し、最初にマッチしたルールの
//! アクションを返す。マッチしなかった場合はデフォルトポリシーを適用する。

use super::rules::{FirewallAction, FirewallDirection, FirewallRule, IpAddress, RuleId};
use super::stats::FirewallStats;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

/// ファイアウォール評価結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallVerdict {
    /// パケットを許可
    Allow,
    /// パケットを拒否（ドロップ）
    Deny,
}

/// ファイアウォールエンジン
///
/// グローバルPoisonLockで保護されるため、内部ロックは不要。
pub struct FirewallEngine {
    /// 有効フラグ
    enabled: bool,
    /// ルールリスト（優先度順にソート済み）
    rules: Vec<FirewallRule>,
    /// 次のルール ID
    next_id: u64,
    /// Ingress デフォルトポリシー
    default_ingress: FirewallAction,
    /// Egress デフォルトポリシー
    default_egress: FirewallAction,
    /// 統計情報
    stats_inner: FirewallStatsInner,
}

/// 内部統計（非アトミック — PoisonLock 保護下でのみアクセス）
struct FirewallStatsInner {
    /// 許可されたパケット数
    allowed: u64,
    /// 拒否されたパケット数
    denied: u64,
    /// ルール評価回数
    evaluated: u64,
    /// ルールにマッチした回数
    matched: u64,
    /// デフォルトポリシーが適用された回数
    default_applied: u64,
}

impl FirewallStatsInner {
    const fn new() -> Self {
        Self {
            allowed: 0,
            denied: 0,
            evaluated: 0,
            matched: 0,
            default_applied: 0,
        }
    }

    fn to_stats(&self) -> FirewallStats {
        FirewallStats {
            allowed: self.allowed,
            denied: self.denied,
            evaluated: self.evaluated,
            matched: self.matched,
            default_applied: self.default_applied,
        }
    }
}

impl FirewallEngine {
    /// const 初期化（static 変数用）
    pub const fn new_const() -> Self {
        Self {
            enabled: true,
            rules: Vec::new(),
            next_id: 1,
            default_ingress: FirewallAction::Deny,
            default_egress: FirewallAction::Allow,
            stats_inner: FirewallStatsInner::new(),
        }
    }

    /// ファイアウォールが有効かどうか
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// 有効/無効を切り替える
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if enabled {
            log::info!(
                "[FIREWALL] enabled (ingress={}, egress={})",
                self.default_ingress,
                self.default_egress
            );
        } else {
            log::info!("[FIREWALL] disabled");
        }
    }

    /// デフォルトポリシーを設定する
    pub fn set_default_policy(&mut self, direction: FirewallDirection, action: FirewallAction) {
        match direction {
            FirewallDirection::Ingress => {
                self.default_ingress = action;
                log::info!("[FIREWALL] default ingress policy: {}", action);
            }
            FirewallDirection::Egress => {
                self.default_egress = action;
                log::info!("[FIREWALL] default egress policy: {}", action);
            }
            FirewallDirection::Both => {
                self.default_ingress = action;
                self.default_egress = action;
                log::info!("[FIREWALL] default policy (both): {}", action);
            }
        }
    }

    /// ルールを追加する
    ///
    /// 優先度順にソートされたリストに挿入する。
    /// 戻り値は割り当てられたルール ID。
    pub fn add_rule(&mut self, mut rule: FirewallRule) -> RuleId {
        let id = self.next_id;
        self.next_id += 1;
        rule.id = id;

        // 挿入位置を探す（安定ソート: 同一優先度なら追加順維持）
        let pos = self
            .rules
            .iter()
            .position(|r| r.priority > rule.priority)
            .unwrap_or(self.rules.len());

        log::info!("[FIREWALL] rule added: {}", rule);
        self.rules.insert(pos, rule);
        id
    }

    /// ルールを削除する
    pub fn remove_rule(&mut self, id: RuleId) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            let rule = self.rules.remove(pos);
            log::info!("[FIREWALL] rule removed: {}", rule);
            true
        } else {
            false
        }
    }

    /// 全ルールをクリアする
    pub fn clear_rules(&mut self) {
        self.rules.clear();
        log::info!("[FIREWALL] all rules cleared");
    }

    /// 現在のルール一覧を取得する
    pub fn list_rules(&self) -> Vec<FirewallRule> {
        self.rules.clone()
    }

    /// ルール数を取得する
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 統計を取得する
    pub fn stats(&self) -> FirewallStats {
        self.stats_inner.to_stats()
    }

    /// パケットを評価する
    ///
    /// ルールを優先度順に走査し、最初にマッチしたルールのアクションを返す。
    /// マッチしなかった場合はデフォルトポリシーが適用される。
    pub fn evaluate(
        &self,
        direction: FirewallDirection,
        src_ip: IpAddress,
        dst_ip: IpAddress,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
    ) -> FirewallVerdict {
        // 無効時は全て許可
        if !self.enabled {
            return FirewallVerdict::Allow;
        }

        // 統計を更新（&self なのでここでは更新しない — evaluate_mut を使用）
        // Note: evaluate は &self で呼ばれるため統計更新はできない
        // グローバルAPI側で統計を別途記録するか、evaluate_mut を使用する

        // ルールを優先度順に走査
        for rule in &self.rules {
            if rule.matches(
                direction, src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags,
            ) {
                if rule.action.is_log() {
                    log::info!(
                        "[FIREWALL] {} {} {} :{} -> {} :{} proto={} rule=#{}",
                        if rule.action.is_allow() {
                            "ALLOW"
                        } else {
                            "DENY"
                        },
                        direction,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        protocol,
                        rule.id,
                    );
                }

                return if rule.action.is_allow() {
                    FirewallVerdict::Allow
                } else {
                    FirewallVerdict::Deny
                };
            }
        }

        // デフォルトポリシー
        let default = match direction {
            FirewallDirection::Ingress => &self.default_ingress,
            FirewallDirection::Egress => &self.default_egress,
            FirewallDirection::Both => {
                // 両方向の場合は Ingress / Egress 双方が Allow なら Allow
                if self.default_ingress.is_allow() && self.default_egress.is_allow() {
                    &self.default_ingress
                } else {
                    &FirewallAction::Deny
                }
            }
        };

        if default.is_allow() {
            FirewallVerdict::Allow
        } else {
            FirewallVerdict::Deny
        }
    }

    /// パケットを評価し、統計を更新する（可変参照版）
    pub fn evaluate_mut(
        &mut self,
        direction: FirewallDirection,
        src_ip: IpAddress,
        dst_ip: IpAddress,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
    ) -> FirewallVerdict {
        if !self.enabled {
            return FirewallVerdict::Allow;
        }

        self.stats_inner.evaluated += 1;

        for rule in &self.rules {
            if rule.matches(
                direction, src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags,
            ) {
                self.stats_inner.matched += 1;

                if rule.action.is_log() {
                    log::info!(
                        "[FIREWALL] {} {} {} :{} -> {} :{} proto={} rule=#{}",
                        if rule.action.is_allow() {
                            "ALLOW"
                        } else {
                            "DENY"
                        },
                        direction,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        protocol,
                        rule.id,
                    );
                }

                let verdict = if rule.action.is_allow() {
                    self.stats_inner.allowed += 1;
                    FirewallVerdict::Allow
                } else {
                    self.stats_inner.denied += 1;
                    FirewallVerdict::Deny
                };
                return verdict;
            }
        }

        // デフォルトポリシー
        self.stats_inner.default_applied += 1;
        let default = match direction {
            FirewallDirection::Ingress => &self.default_ingress,
            FirewallDirection::Egress => &self.default_egress,
            FirewallDirection::Both => {
                // 両方向の場合は Ingress / Egress 双方が Allow なら Allow
                if self.default_ingress.is_allow() && self.default_egress.is_allow() {
                    &self.default_ingress
                } else {
                    &FirewallAction::Deny
                }
            }
        };

        if default.is_allow() {
            self.stats_inner.allowed += 1;
            FirewallVerdict::Allow
        } else {
            self.stats_inner.denied += 1;
            FirewallVerdict::Deny
        }
    }
}
