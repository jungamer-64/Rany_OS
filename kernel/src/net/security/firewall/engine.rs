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
    default_ingress: IngressDefault,
    /// Egress デフォルトポリシー
    default_egress: FirewallAction,
    /// 統計情報
    stats_inner: FirewallStatsInner,
}

enum IngressDefault {
    Fixed(FirewallAction),
    KnownTcpFlows,
}

impl core::fmt::Display for IngressDefault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fixed(action) => action.fmt(f),
            Self::KnownTcpFlows => f.write_str("allow known TCP flows"),
        }
    }
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
            default_ingress: IngressDefault::Fixed(FirewallAction::Deny),
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
                self.default_ingress = IngressDefault::Fixed(action);
                log::info!("[FIREWALL] default ingress policy: {}", action);
            }
            FirewallDirection::Egress => {
                self.default_egress = action;
                log::info!("[FIREWALL] default egress policy: {}", action);
            }
            FirewallDirection::Both => {
                self.default_ingress = IngressDefault::Fixed(action);
                self.default_egress = action;
                log::info!("[FIREWALL] default policy (both): {}", action);
            }
        }
    }

    pub(super) fn allow_known_tcp_flows_by_default(&mut self) {
        self.default_ingress = IngressDefault::KnownTcpFlows;
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

        log::info!("[FIREWALL] rule added: id={}", id);
        self.rules.insert(pos, rule);
        id
    }

    /// ルールを削除する
    pub fn remove_rule(&mut self, id: RuleId) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            self.rules.remove(pos);
            log::info!("[FIREWALL] rule removed: id={}", id);
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

    /// 現在のルール一覧を借用する
    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    /// 統計を取得する
    pub fn stats(&self) -> FirewallStats {
        self.stats_inner.to_stats()
    }

    /// Admission to bounded reassembly uses only facts visible in every
    /// fragment. Any potentially matching allow rule defers the decision to
    /// the complete datagram, preserving the ordered policy.
    pub(super) fn admits_fragment(
        &self,
        src: IpAddress,
        dst: IpAddress,
        protocol: Option<u8>,
    ) -> bool {
        if !self.enabled {
            return true;
        }
        for rule in &self.rules {
            if !rule.matches_network(FirewallDirection::Ingress, src, dst, protocol) {
                continue;
            }
            if rule.action.is_allow() {
                return true;
            }
            if rule.matches_all_transports(protocol) {
                return false;
            }
        }
        match self.default_ingress {
            IngressDefault::Fixed(action) => action.is_allow(),
            IngressDefault::KnownTcpFlows => protocol.is_none_or(|number| number == 6),
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
        known_tcp_flow: impl FnOnce() -> bool,
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

        self.stats_inner.default_applied += 1;
        let allow_ingress = || match self.default_ingress {
            IngressDefault::Fixed(action) => action.is_allow(),
            IngressDefault::KnownTcpFlows => protocol == 6 && known_tcp_flow(),
        };
        let allowed = match direction {
            FirewallDirection::Ingress => allow_ingress(),
            FirewallDirection::Egress => self.default_egress.is_allow(),
            FirewallDirection::Both => self.default_egress.is_allow() && allow_ingress(),
        };

        if allowed {
            self.stats_inner.allowed += 1;
            FirewallVerdict::Allow
        } else {
            self.stats_inner.denied += 1;
            FirewallVerdict::Deny
        }
    }
}
