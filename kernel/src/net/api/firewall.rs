// ============================================================================
// kernel/src/net/api/firewall.rs - シェル向けファイアウォールAPI
// ============================================================================
//! シェルコマンドから呼び出せるファイアウォール操作関数群。
//!
//! ## 使用例（ExoShell）
//! ```text
//! > firewall enable
//! > firewall add deny ingress src=10.0.0.0/8 proto=tcp dport=22
//! > firewall add allow ingress src=192.168.1.0/24 proto=tcp dport=22 priority=100
//! > firewall list
//! > firewall stats
//! > firewall disable
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::net::runtime::NetRuntimeHandle;
use crate::net::security::firewall::{
    self, FirewallAction, FirewallDirection, FirewallProtocol, FirewallRule, IpMatch, PortMatch,
};

extern crate alloc;

/// ファイアウォールの状態を文字列化する（イベントハンドラ内部用）
pub(crate) fn firewall_status_text() -> String {
    let enabled = firewall::is_enabled();
    let stats = firewall::get_stats();
    let rules = firewall::list_rules().unwrap_or_default();
    format!(
        "Firewall: {}\nRules: {}\nStats: {}",
        if enabled { "ENABLED" } else { "DISABLED" },
        rules.len(),
        stats,
    )
}

/// ルール一覧を文字列化する（イベントハンドラ内部用）
pub(crate) fn firewall_list_rules_text() -> String {
    match firewall::list_rules() {
        Ok(rules) if rules.is_empty() => String::from("(no rules)"),
        Ok(rules) => {
            let mut out = String::new();
            for rule in &rules {
                out.push_str(&format!("{}\n", rule));
            }
            out
        }
        Err(e) => format!("Error: {}", e),
    }
}

/// 統計情報を文字列化する（イベントハンドラ内部用）
pub(crate) fn firewall_stats_text() -> String {
    format!("{}", firewall::get_stats())
}

pub async fn firewall_enable_in(runtime: NetRuntimeHandle) -> Result<(), &'static str> {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<Result<(), &'static str>>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::FirewallEnable { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_disable_in(runtime: NetRuntimeHandle) -> Result<(), &'static str> {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<Result<(), &'static str>>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::FirewallDisable { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_status_in(runtime: NetRuntimeHandle) -> String {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<String>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::FirewallStatus { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_list_rules_in(runtime: NetRuntimeHandle) -> String {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<String>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::FirewallListRules { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_stats_in(runtime: NetRuntimeHandle) -> String {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<String>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::FirewallStats { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_add_rule_in(
    runtime: NetRuntimeHandle,
    action: &str,
    direction: &str,
    src_ip: &str,
    dst_ip: &str,
    protocol: &str,
    src_port: &str,
    dst_port: &str,
    priority: u16,
    name: &str,
) -> Result<u64, String> {
    let action = parse_action(action)?;
    let direction = parse_direction(direction)?;
    let src_ip = parse_ip_match(src_ip)?;
    let dst_ip = parse_ip_match(dst_ip)?;
    let protocol = parse_protocol(protocol)?;
    let src_port = parse_port_match(src_port)?;
    let dst_port = parse_port_match(dst_port)?;
    let rule = FirewallRule::builder()
        .name(name)
        .action(action)
        .direction(direction)
        .src_ip(src_ip)
        .dst_ip(dst_ip)
        .protocol(protocol)
        .src_port(src_port)
        .dst_port(dst_port)
        .priority(priority)
        .build();

    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<Result<u64, String>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::FirewallAddRule {
        rule: rule.clone(),
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_remove_rule_in(runtime: NetRuntimeHandle, id: u64) -> Result<bool, String> {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<Result<bool, String>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::FirewallRemoveRule {
        id,
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_clear_rules_in(runtime: NetRuntimeHandle) -> Result<(), String> {
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<Result<(), String>>();
    let event =
        crate::net::l4::endpoint::event::NetworkEvent::FirewallClearRules { result_slot, waker };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_set_default_policy_in(
    runtime: NetRuntimeHandle,
    direction: &str,
    action: &str,
) -> Result<(), String> {
    let direction = parse_direction(direction)?;
    let action = parse_action(action)?;
    let (result_slot, waker, command_future) =
        crate::net::runtime::stack::new_command_channel::<Result<(), String>>();
    let event = crate::net::l4::endpoint::event::NetworkEvent::FirewallSetDefaultPolicy {
        direction,
        action,
        result_slot,
        waker,
    };
    let _ = crate::net::l4::endpoint::event::send_event_in(runtime, event).await;
    command_future.await
}

// ============================================================================
// パーサーヘルパー
// ============================================================================

fn parse_action(s: &str) -> Result<FirewallAction, String> {
    match s.to_ascii_lowercase().as_str() {
        "allow" | "accept" => Ok(FirewallAction::Allow),
        "deny" | "drop" | "reject" => Ok(FirewallAction::Deny),
        "log-allow" | "log_allow" => Ok(FirewallAction::LogAllow),
        "log-deny" | "log_deny" => Ok(FirewallAction::LogDeny),
        _ => Err(format!(
            "unknown action: '{}' (allow/deny/log-allow/log-deny)",
            s
        )),
    }
}

fn parse_direction(s: &str) -> Result<FirewallDirection, String> {
    match s.to_ascii_lowercase().as_str() {
        "in" | "ingress" | "input" => Ok(FirewallDirection::Ingress),
        "out" | "egress" | "output" => Ok(FirewallDirection::Egress),
        "both" | "any" | "*" => Ok(FirewallDirection::Both),
        _ => Err(format!("unknown direction: '{}' (in/out/both)", s)),
    }
}

fn parse_protocol(s: &str) -> Result<FirewallProtocol, String> {
    match s.to_ascii_lowercase().as_str() {
        "*" | "any" | "all" => Ok(FirewallProtocol::Any),
        "tcp" => Ok(FirewallProtocol::Tcp),
        "udp" => Ok(FirewallProtocol::Udp),
        "icmp" => Ok(FirewallProtocol::Icmp),
        _ => {
            if let Ok(n) = s.parse::<u8>() {
                Ok(FirewallProtocol::Number(n))
            } else {
                Err(format!("unknown protocol: '{}' (tcp/udp/icmp/*/0-255)", s))
            }
        }
    }
}

/// IPv4 アドレスまたは CIDR 表記をパースする
///
/// 例:
/// - `"*"` → `IpMatch::Any`
/// - `"10.0.2.15"` → `IpMatch::Exact([10, 0, 2, 15])`
/// - `"192.168.1.0/24"` → `IpMatch::Cidr([192, 168, 1, 0], 24)`
fn parse_ip_match(s: &str) -> Result<IpMatch, String> {
    let s = s.trim();
    if s == "*" || s == "any" || s == "0.0.0.0/0" {
        return Ok(IpMatch::Any);
    }

    // CIDR 判定
    if let Some(slash_pos) = s.find('/') {
        let ip_str = &s[..slash_pos];
        let prefix_str = &s[slash_pos + 1..];
        let ip = parse_ipv4(ip_str)?;
        let prefix: u8 = prefix_str
            .parse::<u8>()
            .map_err(|_| format!("invalid prefix length: '{}'", prefix_str))?;
        if prefix > 32 {
            return Err(format!("prefix length {} > 32", prefix));
        }
        return Ok(IpMatch::Cidr(ip, prefix));
    }

    // 単一 IP
    let ip = parse_ipv4(s)?;
    Ok(IpMatch::Exact(ip))
}

/// ドット区切り IPv4 をパースする
fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("invalid IPv4: '{}'", s));
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part
            .parse::<u8>()
            .map_err(|_| format!("invalid octet '{}' in '{}'", part, s))?;
    }
    Ok(octets)
}

/// ポートマッチ条件をパースする
///
/// 例:
/// - `"*"` → `PortMatch::Any`
/// - `"80"` → `PortMatch::Exact(80)`
/// - `"1024-65535"` → `PortMatch::Range(1024, 65535)`
fn parse_port_match(s: &str) -> Result<PortMatch, String> {
    let s = s.trim();
    if s == "*" || s == "any" || s.is_empty() {
        return Ok(PortMatch::Any);
    }

    if let Some(dash_pos) = s.find('-') {
        let start_str = &s[..dash_pos];
        let end_str = &s[dash_pos + 1..];
        let start = start_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port start: '{}'", start_str))?;
        let end = end_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port end: '{}'", end_str))?;
        if start > end {
            return Err(format!("port range start {} > end {}", start, end));
        }
        return Ok(PortMatch::Range(start, end));
    }

    let port = s
        .parse::<u16>()
        .map_err(|_| format!("invalid port: '{}'", s))?;
    Ok(PortMatch::Exact(port))
}

/// 文字列をASCII小文字に変換（no_std互換）
trait ToAsciiLowerStr {
    fn to_ascii_lowercase(&self) -> String;
}

impl ToAsciiLowerStr for str {
    fn to_ascii_lowercase(&self) -> String {
        self.chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    (c as u8 + 32) as char
                } else {
                    c
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn firewall_status_completes_with_event_task() {
        let status = {
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
            let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
            let mut executor = crate::task::TestExecutor::new();
            let result_slot_clone = result_slot.clone();
            let completed_clone = completed.clone();
            executor.spawn(crate::task::Task::new(async move {
                let output =
                    super::firewall_status_in(crate::net::runtime::default_runtime()).await;
                let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(output);
                completed_clone.store(true, core::sync::atomic::Ordering::Release);
            }));
            executor.spawn(crate::task::Task::new(async {
                crate::net::l4::endpoint::event_loop::network_event_task().await;
            }));

            let mut output = None;
            for _ in 0..100_000 {
                executor.drive_once_for_test();
                if completed.load(core::sync::atomic::Ordering::Acquire) {
                    output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    break;
                }
            }
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            output.expect("firewall_status test timed out")
        };
        assert!(status.contains("Firewall:"));
    }
}
