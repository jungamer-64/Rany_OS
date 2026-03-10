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
    FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule, IpAddress, IpMatch,
    PortMatch, RuleId,
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
/// - `src_ip`: 送信元 IP アドレス
/// - `dst_ip`: 宛先 IP アドレス
/// - `protocol`: IP プロトコル番号（6=TCP, 17=UDP, 1=ICMP）
/// - `src_port`: 送信元ポート（ICMP の場合は 0）
/// - `dst_port`: 宛先ポート（ICMP の場合は 0）
/// - `tcp_flags`: TCP フラグ（TCP 以外の場合は 0）
///
/// ## 戻り値
/// - `true`: パケットを許可
/// - `false`: パケットを拒否（ドロップ）
pub fn check_ingress(
    src_ip: impl Into<IpAddress>,
    dst_ip: impl Into<IpAddress>,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> bool {
    let src_ip = src_ip.into();
    let dst_ip = dst_ip.into();
    match FIREWALL.lock() {
        Ok(mut fw) => {
            fw.evaluate_mut(
                FirewallDirection::Ingress,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                tcp_flags,
            ) == FirewallVerdict::Allow
        }
        Err(_) => {
            // Security Fix: PoisonLock がポイズンされた場合はフェイルクローズ（拒否）
            // ポイズン状態 = 以前の評価中にパニックが発生したことを意味し、
            // エンジンの状態が不整合である可能性があるため、安全側に倒す。
            log::error!("[FIREWALL] lock poisoned — fail-closed (SECURITY)");
            false
        }
    }
}

/// Egress パケットをファイアウォールルールに照合する
pub fn check_egress(
    src_ip: impl Into<IpAddress>,
    dst_ip: impl Into<IpAddress>,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> bool {
    let src_ip = src_ip.into();
    let dst_ip = dst_ip.into();
    match FIREWALL.lock() {
        Ok(mut fw) => {
            fw.evaluate_mut(
                FirewallDirection::Egress,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                tcp_flags,
            ) == FirewallVerdict::Allow
        }
        Err(_) => {
            log::error!("[FIREWALL] lock poisoned — fail-closed (SECURITY)");
            false
        }
    }
}

/// IPv4 用の下位互換 API
pub fn check_ingress_v4(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> bool {
    check_ingress(
        IpAddress::V4(src_ip),
        IpAddress::V4(dst_ip),
        protocol,
        src_port,
        dst_port,
        tcp_flags,
    )
}

/// IPv4 用の下位互換 API (Egress)
pub fn check_egress_v4(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> bool {
    check_egress(
        IpAddress::V4(src_ip),
        IpAddress::V4(dst_ip),
        protocol,
        src_port,
        dst_port,
        tcp_flags,
    )
}

/// IPv6 Ingress パケット照合 (下位互換 API)
pub fn check_ingress_v6(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> bool {
    check_ingress(
        IpAddress::V6(src_ip),
        IpAddress::V6(dst_ip),
        protocol,
        src_port,
        dst_port,
        tcp_flags,
    )
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

/// セキュリティ向上のためのデフォルトルールセットを構築する
pub fn setup_default_firewall() {
    match FIREWALL.lock() {
        Ok(mut fw) => {
            // 全てのルールをクリア（初期化用）
            fw.clear_rules();

            // 1. ループバックパケットを許可 (127.0.0.1)
            let _ = fw.add_rule(
                FirewallRule::builder()
                    .name("Allow Loopback Ingress")
                    .ingress()
                    .src_ip(IpMatch::Cidr([127, 0, 0, 0], 8))
                    .allow()
                    .priority(10)
                    .build(),
            );
            let _ = fw.add_rule(
                FirewallRule::builder()
                    .name("Allow Loopback Egress")
                    .egress()
                    .dst_ip(IpMatch::Cidr([127, 0, 0, 0], 8))
                    .allow()
                    .priority(11)
                    .build(),
            );

            // 2. [REMOVED] 確立済みの TCP 接続を許可 (ACK フラグがセットされているもの)
            // SECURITY: ステートレスファイアウォールで全ての ACK パケットを許可するのは危険なため削除。
            // 必要であれば特定の宛先ポートに対して個別に許可ルールを追加すべき。

            // 3. DHCP を許可 (UDP 67, 68)
            let _ = fw.add_rule(
                FirewallRule::builder()
                    .name("Allow DHCP Ingress")
                    .ingress()
                    .udp()
                    .dst_port(PortMatch::Exact(68))
                    .allow()
                    .priority(30)
                    .build(),
            );

            // 4. DNS 応答を許可 (UDP 53)
            let _ = fw.add_rule(
                FirewallRule::builder()
                    .name("Allow DNS Responses")
                    .ingress()
                    .udp()
                    .src_port(PortMatch::Exact(53))
                    .allow()
                    .priority(40)
                    .build(),
            );

            // 5. ICMP エコー応答（Ping Reply）を許可
            let _ = fw.add_rule(
                FirewallRule::builder()
                    .name("Allow ICMP Echo Reply")
                    .ingress()
                    .icmp_type(0) // Type 0: Echo Reply
                    .allow()
                    .priority(50)
                    .build(),
            );

            // 5.1 ICMP 宛先到達不能（MTU探索等に必要）を許可
            let _ = fw.add_rule(
                FirewallRule::builder()
                    .name("Allow ICMP Dest Unreachable")
                    .ingress()
                    .icmp_type(3) // Type 3: Destination Unreachable
                    .allow()
                    .priority(51)
                    .build(),
            );

            // 6. 全ての外向き通信を許可
            fw.set_default_policy(FirewallDirection::Egress, FirewallAction::Allow);
            // 入向きはデフォルト拒否
            fw.set_default_policy(FirewallDirection::Ingress, FirewallAction::Deny);

            fw.set_enabled(true);
            log::info!("[FIREWALL] Secure default rules applied.");
        }
        Err(_) => {
            log::error!("[FIREWALL] Failed to setup default rules: lock poisoned.");
        }
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
