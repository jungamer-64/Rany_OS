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
pub(crate) fn firewall_status_text_in(runtime: NetRuntimeHandle) -> String {
    let enabled = firewall::is_enabled_in(runtime);
    let stats = firewall::get_stats_in(runtime);
    let rule_count = firewall::with_rules_in(runtime, |rules| rules.len()).unwrap_or_default();
    format!(
        "Firewall: {}\nRules: {}\nStats: {}",
        if enabled { "ENABLED" } else { "DISABLED" },
        rule_count,
        stats,
    )
}

/// ルール一覧を文字列化する（イベントハンドラ内部用）
pub(crate) fn firewall_list_rules_text_in(runtime: NetRuntimeHandle) -> String {
    match firewall::with_rules_in(runtime, |rules| {
        if rules.is_empty() {
            return String::from("(no rules)");
        }
        let mut out = String::new();
        for rule in rules {
            out.push_str(&format!("{}\n", rule));
        }
        out
    }) {
        Ok(text) => text,
        Err(e) => format!("Error: {}", e),
    }
}

/// 統計情報を文字列化する（イベントハンドラ内部用）
pub(crate) fn firewall_stats_text_in(runtime: NetRuntimeHandle) -> String {
    format!("{}", firewall::get_stats_in(runtime))
}

pub async fn firewall_enable_in(runtime: NetRuntimeHandle) -> Result<(), &'static str> {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<Result<(), &'static str>>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallEnable { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_disable_in(runtime: NetRuntimeHandle) -> Result<(), &'static str> {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<Result<(), &'static str>>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallDisable { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_status_in(runtime: NetRuntimeHandle) -> String {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<String>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallStatus { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_list_rules_in(runtime: NetRuntimeHandle) -> String {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<String>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallListRules { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_stats_in(runtime: NetRuntimeHandle) -> String {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<String>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallStats { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
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
    tcp_flags: &str,
) -> Result<u64, String> {
    let action = parse_action(action)?;
    let direction = parse_direction(direction)?;
    let src_ip = parse_ip_match(src_ip)?;
    let dst_ip = parse_ip_match(dst_ip)?;
    let protocol = parse_protocol(protocol)?;
    let builder = FirewallRule::builder()
        .name(name)
        .action(action)
        .direction(direction)
        .src_ip(src_ip)
        .dst_ip(dst_ip)
        .priority(priority);
    // ICMP rules carry the message type and code in the port positions.
    let builder = if matches!(protocol, FirewallProtocol::Icmp | FirewallProtocol::Icmpv6) {
        let builder = builder.protocol(protocol);
        match (parse_icmp_field(src_port)?, parse_icmp_field(dst_port)?) {
            (None, None) => builder,
            (Some(icmp_type), None) => builder.icmp_type(icmp_type),
            (Some(icmp_type), Some(code)) => builder.icmp_type_code(icmp_type, code),
            (None, Some(_)) => return Err(String::from("ICMP code requires an ICMP type")),
        }
    } else {
        builder
            .protocol(protocol)
            .src_port(parse_port_match(src_port)?)
            .dst_port(parse_port_match(dst_port)?)
    };
    let builder = if tcp_flags.trim().is_empty() {
        builder
    } else {
        if protocol != FirewallProtocol::Tcp {
            return Err(String::from("tcp_flags requires protocol tcp"));
        }
        let (mask, value) = parse_tcp_flags(tcp_flags)?;
        builder.tcp_flags(mask, value)
    };
    let rule = builder.build();

    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<Result<u64, String>>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallAddRule { rule, reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_remove_rule_in(runtime: NetRuntimeHandle, id: u64) -> Result<bool, String> {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<Result<bool, String>>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallRemoveRule { id, reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_clear_rules_in(runtime: NetRuntimeHandle) -> Result<(), String> {
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<Result<(), String>>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallClearRules { reply },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
    command_future.await
}

pub async fn firewall_set_default_policy_in(
    runtime: NetRuntimeHandle,
    direction: &str,
    action: &str,
) -> Result<(), String> {
    let direction = parse_direction(direction)?;
    let action = parse_action(action)?;
    let (reply, command_future) =
        crate::net::runtime::command::new_command_channel_in::<Result<(), String>>(runtime);
    let event = crate::net::runtime::command::RuntimeCommand::Control(
        crate::net::runtime::command::ControlCommand::FirewallSetDefaultPolicy {
            direction,
            action,
            reply,
        },
    );
    let _ = crate::net::runtime::command::send_command_in(runtime, event).await;
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
        "icmp" | "1" => Ok(FirewallProtocol::Icmp),
        "icmpv6" | "58" => Ok(FirewallProtocol::Icmpv6),
        _ => {
            if let Ok(n) = s.parse::<u8>() {
                Ok(FirewallProtocol::Number(n))
            } else {
                Err(format!(
                    "unknown protocol: '{}' (tcp/udp/icmp/icmpv6/*/0-255)",
                    s
                ))
            }
        }
    }
}

/// IPv4 / IPv6 アドレスまたは CIDR 表記をパースする
///
/// 例:
/// - `"*"` → `IpMatch::Any`
/// - `"10.0.2.15"` → `IpMatch::Exact([10, 0, 2, 15])`
/// - `"192.168.1.0/24"` → `IpMatch::Cidr([192, 168, 1, 0], 24)`
/// - `"2001:db8::/32"` → `IpMatch::CidrV6(..., 32)`
fn parse_ip_match(s: &str) -> Result<IpMatch, String> {
    let s = s.trim();
    if s == "*" || s == "any" || s == "0.0.0.0/0" || s == "::/0" {
        return Ok(IpMatch::Any);
    }

    let (ip_str, prefix_str) = match s.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (s, None),
    };
    let prefix = |max: u8| -> Result<Option<u8>, String> {
        prefix_str
            .map(|text| {
                let prefix = text
                    .parse::<u8>()
                    .map_err(|_| format!("invalid prefix length: '{}'", text))?;
                if prefix > max {
                    return Err(format!("prefix length {} > {}", prefix, max));
                }
                Ok(prefix)
            })
            .transpose()
    };

    if ip_str.contains(':') {
        let ip = crate::net::l3::ipv6::Ipv6Address::parse_text(ip_str)
            .ok_or_else(|| format!("invalid IPv6: '{}'", ip_str))?
            .octets();
        return Ok(match prefix(128)? {
            Some(prefix) => IpMatch::CidrV6(ip, prefix),
            None => IpMatch::ExactV6(ip),
        });
    }
    let ip = parse_ipv4(ip_str)?;
    Ok(match prefix(32)? {
        Some(prefix) => IpMatch::Cidr(ip, prefix),
        None => IpMatch::Exact(ip),
    })
}

/// ICMP type または code。`*` は未指定。
fn parse_icmp_field(s: &str) -> Result<Option<u8>, String> {
    let s = s.trim();
    if s == "*" || s == "any" || s.is_empty() {
        return Ok(None);
    }
    s.parse::<u8>()
        .map(Some)
        .map_err(|_| format!("invalid ICMP type/code: '{}'", s))
}

/// `"mask:value"` 形式の TCP フラグ条件（10進または `0x` 付き16進）
fn parse_tcp_flags(s: &str) -> Result<(u8, u8), String> {
    fn byte(text: &str) -> Result<u8, String> {
        let text = text.trim();
        match text.strip_prefix("0x") {
            Some(hex) => u8::from_str_radix(hex, 16),
            None => text.parse::<u8>(),
        }
        .map_err(|_| format!("invalid TCP flag byte: '{}'", text))
    }
    let (mask, value) = s
        .split_once(':')
        .ok_or_else(|| format!("tcp_flags must be \"mask:value\": '{}'", s))?;
    let (mask, value) = (byte(mask)?, byte(value)?);
    if value & !mask != 0 {
        return Err(String::from("tcp_flags value sets bits outside the mask"));
    }
    Ok((mask, value))
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
