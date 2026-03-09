// ============================================================================
// kernel/src/net/security/firewall/mod.rs - ファイアウォールモジュール
// ============================================================================
//! # ファイアウォール
//!
//! ステートレスなパケットフィルタリングエンジン。
//! Ingress（受信）/ Egress（送信）の両方向でルールベースのフィルタリングを提供する。
//!
//! ## 設計方針
//!
//! - **Safe Rust のみ**: unsafe コードなし
//! - **PoisonLock**: パニック安全な共有リソース管理
//! - **ゼロコピー互換**: パケットデータを参照のみで検査し、コピーは行わない
//! - **O(n) ルール評価**: 優先度順にソート済みのルールリストを線形走査
//!   （ルール数が少ない環境向け。大規模ルールにはハッシュマップ最適化を追加可能）
//!
//! ## 統合ポイント
//!
//! - Ingress: `NetworkEventHandler::handle_event_with_stack()` の
//!   `IngressPacket` 処理前に `check_ingress()` を呼び出す
//! - Egress: `NetworkStack` の送信関数（`send_tcp`, `send_udp_raw` 等）で
//!   `check_egress()` を呼び出す

mod engine;
mod rules;
mod stats;
#[cfg(test)]
mod tests;

pub use engine::{FirewallEngine, FirewallVerdict};
pub use rules::{
    FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule, IpMatch, PortMatch, RuleId,
};
pub use stats::FirewallStats;

use crate::sync::PoisonLock;

extern crate alloc;

// ============================================================================
// グローバルインスタンス
// ============================================================================

/// グローバルファイアウォールエンジン
///
/// PoisonLock による排他制御で、パニック時もデッドロックしない。
static FIREWALL: PoisonLock<FirewallEngine> = PoisonLock::new(FirewallEngine::new_const());

/// Ingress パケットをファイアウォールルールに照合する
///
/// ## 引数
/// - `src_ip`: 送信元 IPv4 アドレス（4バイト）
/// - `dst_ip`: 宛先 IPv4 アドレス（4バイト）
/// - `protocol`: IP プロトコル番号（6=TCP, 17=UDP, 1=ICMP）
/// - `src_port`: 送信元ポート（ICMP の場合は 0）
/// - `dst_port`: 宛先ポート（ICMP の場合は 0）
///
/// ## 戻り値
/// - `true`: パケットを許可
/// - `false`: パケットを拒否（ドロップ）
pub fn check_ingress(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> bool {
    match FIREWALL.lock() {
        Ok(mut fw) => {
            fw.evaluate_mut(
                FirewallDirection::Ingress,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            ) == FirewallVerdict::Allow
        }
        Err(_) => {
            // PoisonLock がポイズンされた場合はフェイルオープン（許可）
            // セキュリティポリシー上はフェイルクローズが望ましいが、
            // カーネルの可用性を優先する
            log::warn!("[FIREWALL] lock poisoned — fail-open");
            true
        }
    }
}

/// Egress パケットをファイアウォールルールに照合する
pub fn check_egress(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> bool {
    match FIREWALL.lock() {
        Ok(mut fw) => {
            fw.evaluate_mut(
                FirewallDirection::Egress,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            ) == FirewallVerdict::Allow
        }
        Err(_) => {
            log::warn!("[FIREWALL] lock poisoned — fail-open");
            true
        }
    }
}

/// ファイアウォールルールを追加する
///
/// ルールは優先度（`priority`）の昇順に自動ソートされる。
/// 同じ優先度の場合は追加順が維持される。
pub fn add_rule(rule: FirewallRule) -> Result<RuleId, &'static str> {
    match FIREWALL.lock() {
        Ok(mut fw) => Ok(fw.add_rule(rule)),
        Err(_) => Err("firewall lock poisoned"),
    }
}

/// ファイアウォールルールを削除する
pub fn remove_rule(id: RuleId) -> Result<bool, &'static str> {
    match FIREWALL.lock() {
        Ok(mut fw) => Ok(fw.remove_rule(id)),
        Err(_) => Err("firewall lock poisoned"),
    }
}

/// 全ルールをクリアする
pub fn clear_rules() -> Result<(), &'static str> {
    match FIREWALL.lock() {
        Ok(mut fw) => {
            fw.clear_rules();
            Ok(())
        }
        Err(_) => Err("firewall lock poisoned"),
    }
}

/// デフォルトポリシーを設定する
pub fn set_default_policy(
    direction: FirewallDirection,
    action: FirewallAction,
) -> Result<(), &'static str> {
    match FIREWALL.lock() {
        Ok(mut fw) => {
            fw.set_default_policy(direction, action);
            Ok(())
        }
        Err(_) => Err("firewall lock poisoned"),
    }
}

/// ファイアウォールを有効化する
pub fn enable() -> Result<(), &'static str> {
    match FIREWALL.lock() {
        Ok(mut fw) => {
            fw.set_enabled(true);
            Ok(())
        }
        Err(_) => Err("firewall lock poisoned"),
    }
}

/// ファイアウォールを無効化する
pub fn disable() -> Result<(), &'static str> {
    match FIREWALL.lock() {
        Ok(mut fw) => {
            fw.set_enabled(false);
            Ok(())
        }
        Err(_) => Err("firewall lock poisoned"),
    }
}

/// 現在のルール一覧を取得する
pub fn list_rules() -> Result<alloc::vec::Vec<FirewallRule>, &'static str> {
    match FIREWALL.lock() {
        Ok(fw) => Ok(fw.list_rules()),
        Err(_) => Err("firewall lock poisoned"),
    }
}

/// ファイアウォール統計を取得する
pub fn get_stats() -> FirewallStats {
    match FIREWALL.lock() {
        Ok(fw) => fw.stats(),
        Err(_) => FirewallStats::default(),
    }
}

/// ファイアウォールが有効かどうかを返す
pub fn is_enabled() -> bool {
    match FIREWALL.lock() {
        Ok(fw) => fw.enabled(),
        Err(_) => false,
    }
}
