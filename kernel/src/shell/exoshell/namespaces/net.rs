// ============================================================================
// src/shell/exoshell/namespaces/net.rs - Network Namespace
// ============================================================================

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::{CAP_NET_ADMIN, CAP_NET_BIND, CAP_NET_RAW, manager};
use crate::shell::exoshell::types::ExoValue;
use alloc::boxed::Box;

/// ネットワーク名前空間
pub struct NetNamespace;

impl NetNamespace {
    fn current_domain_id() -> u64 {
        crate::shell::runtime::current_domain_id()
    }

    fn require_net_admin(op_name: &str) -> Result<(), ExoValue<'static>> {
        let domain_id = Self::current_domain_id();
        if manager().has_capability(domain_id, CAP_NET_ADMIN) {
            Ok(())
        } else {
            Err(ExoValue::Error(format!(
                "Permission denied: {} requires CAP_NET_ADMIN",
                op_name
            )))
        }
    }

    fn parse_if_id_arg(
        args: &[ExoValue<'static>],
        method: &str,
    ) -> Result<crate::net::runtime::manager::NetIfId, ExoValue<'static>> {
        match args.first().and_then(Self::parse_if_id_value) {
            Some(if_id) => Ok(if_id),
            _ => Err(ExoValue::Error(format!("usage: net.{method}(if_id)"))),
        }
    }

    fn parse_if_id_value(
        value: &ExoValue<'static>,
    ) -> Option<crate::net::runtime::manager::NetIfId> {
        match value {
            ExoValue::Int(n) => u16::try_from(*n)
                .ok()
                .map(crate::net::runtime::manager::NetIfId),
            _ => None,
        }
    }

    /// ネットワーク設定を取得（非同期版）
    pub async fn config(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.config") {
            return e;
        }
        let if_id = match Self::parse_if_id_arg(args, "config") {
            Ok(if_id) => if_id,
            Err(err) => return err,
        };
        match crate::net::api::config::get_interface_config_in(
            crate::net::runtime::default_runtime(),
            if_id,
        )
        .await
        {
            Some(cfg) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("if_id"), ExoValue::Int(cfg.if_id as i64));
                map.insert(String::from("name"), ExoValue::String(Cow::Owned(cfg.name)));
                map.insert(String::from("admin_up"), ExoValue::Bool(cfg.admin_up));
                map.insert(
                    String::from("ip"),
                    ExoValue::String(Cow::Owned(format!(
                        "{}.{}.{}.{}",
                        cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3]
                    ))),
                );
                map.insert(
                    String::from("netmask"),
                    ExoValue::String(Cow::Owned(format!(
                        "{}.{}.{}.{}",
                        cfg.netmask[0], cfg.netmask[1], cfg.netmask[2], cfg.netmask[3]
                    ))),
                );
                map.insert(
                    String::from("mac"),
                    ExoValue::String(Cow::Owned(format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        cfg.mac[0], cfg.mac[1], cfg.mac[2], cfg.mac[3], cfg.mac[4], cfg.mac[5]
                    ))),
                );
                ExoValue::Map(map)
            }
            None => ExoValue::Error(String::from("Network not configured")),
        }
    }

    /// ネットワーク統計（非同期版）
    pub async fn stats(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.stats") {
            return e;
        }
        let if_id = match Self::parse_if_id_arg(args, "stats") {
            Ok(if_id) => if_id,
            Err(err) => return err,
        };
        match crate::net::api::config::get_interface_stats_in(
            crate::net::runtime::default_runtime(),
            if_id,
        )
        .await
        {
            Some(stats) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("if_id"), ExoValue::Int(stats.if_id as i64));
                map.insert(
                    String::from("rx_packets"),
                    ExoValue::Int(stats.rx_packets as i64),
                );
                map.insert(
                    String::from("tx_packets"),
                    ExoValue::Int(stats.tx_packets as i64),
                );
                map.insert(
                    String::from("rx_bytes"),
                    ExoValue::Int(stats.rx_bytes as i64),
                );
                map.insert(
                    String::from("tx_bytes"),
                    ExoValue::Int(stats.tx_bytes as i64),
                );
                map.insert(
                    String::from("rx_errors"),
                    ExoValue::Int(stats.rx_errors as i64),
                );
                map.insert(
                    String::from("tx_errors"),
                    ExoValue::Int(stats.tx_errors as i64),
                );
                map.insert(
                    String::from("rx_dropped"),
                    ExoValue::Int(stats.rx_dropped as i64),
                );
                ExoValue::Map(map)
            }
            None => ExoValue::Error(String::from("No network statistics")),
        }
    }

    /// ARPキャッシュ（非同期版）
    pub async fn arp_cache() -> ExoValue<'static> {
        let entries =
            crate::net::api::connections::get_arp_cache_in(crate::net::runtime::default_runtime())
                .await;
        let values: Vec<ExoValue> = entries
            .into_iter()
            .map(|e| {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("ip"),
                    ExoValue::String(Cow::Owned(format!(
                        "{}.{}.{}.{}",
                        e.ip[0], e.ip[1], e.ip[2], e.ip[3]
                    ))),
                );
                map.insert(
                    String::from("mac"),
                    ExoValue::String(Cow::Owned(format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        e.mac[0], e.mac[1], e.mac[2], e.mac[3], e.mac[4], e.mac[5]
                    ))),
                );
                map.insert(String::from("complete"), ExoValue::Bool(e.complete));
                ExoValue::Map(map)
            })
            .collect();
        ExoValue::Array(values)
    }

    /// ARPキャッシュ挿入（非同期版）
    ///
    /// イベントキュー経由でARP挿入を行い、NETWORK_STACKロックを回避する。
    pub async fn arp_insert(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        if args.len() != 2 {
            return ExoValue::Error(String::from("usage: net.arp_insert(ip, mac)"));
        }
        let ip = match &args[0] {
            ExoValue::String(s) => {
                let nums: Vec<_> = s.split('.').collect();
                if nums.len() != 4 {
                    return ExoValue::Error(String::from("invalid IP"));
                }
                let mut octets = [0u8; 4];
                for (i, part) in nums.iter().enumerate() {
                    if let Ok(v) = part.parse::<u8>() {
                        octets[i] = v;
                    } else {
                        return ExoValue::Error(String::from("invalid IP"));
                    }
                }
                crate::net::l3::ipv4::Ipv4Address::new(octets)
            }
            _ => return ExoValue::Error(String::from("ip must be string")),
        };
        let mac = match &args[1] {
            ExoValue::String(s) => {
                let parts: Vec<_> = s.split(':').collect();
                if parts.len() != 6 {
                    return ExoValue::Error(String::from("invalid MAC"));
                }
                let mut octets = [0u8; 6];
                for (i, part) in parts.iter().enumerate() {
                    if let Ok(v) = u8::from_str_radix(part, 16) {
                        octets[i] = v;
                    } else {
                        return ExoValue::Error(String::from("invalid MAC"));
                    }
                }
                crate::net::l2::ethernet::MacAddress::from_octets(
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                )
            }
            _ => return ExoValue::Error(String::from("mac must be string")),
        };
        crate::net::api::connections::enqueue_arp_cache_insert_in(
            crate::net::runtime::default_runtime(),
            ip,
            mac,
        );
        ExoValue::Bool(true)
    }

    fn format_ipv6(addr: [u8; 16]) -> String {
        format!("{}", crate::net::l3::ipv6::Ipv6Address::new(addr))
    }

    /// DHCP state snapshot — 非同期版（推奨）
    pub async fn dhcp_state(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let if_id = match Self::parse_if_id_arg(args, "dhcp_state") {
            Ok(if_id) => if_id,
            Err(err) => return err,
        };
        let state =
            crate::net::api::dhcp::get_dhcp_state_in(crate::net::runtime::default_runtime(), if_id)
                .await;
        Self::format_dhcp_state(state)
    }

    /// DhcpRuntimeState を ExoValue に変換（共通ヘルパー）
    fn format_dhcp_state(state: crate::net::api::dhcp::DhcpRuntimeState) -> ExoValue<'static> {
        let v4_ip = match state.v4_assigned_ip {
            Some(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            None => String::from("nil"),
        };
        let v4_lease = match state.v4_lease_remaining {
            Some(v) => format!("{}s", v),
            None => String::from("nil"),
        };
        let v4_last_declined = match state.v4_last_declined {
            Some(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            None => String::from("nil"),
        };
        let v4_last_released = match state.v4_last_released {
            Some(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            None => String::from("nil"),
        };
        let v6_ip = match state.v6_assigned_ip {
            Some(ip) => Self::format_ipv6(ip),
            None => String::from("nil"),
        };
        let v6_pref = match state.v6_preferred_remaining {
            Some(v) => format!("{}s", v),
            None => String::from("nil"),
        };
        let v6_valid = match state.v6_valid_remaining {
            Some(v) => format!("{}s", v),
            None => String::from("nil"),
        };

        ExoValue::String(Cow::Owned(format!(
            "v4_state={} v4_ip={} v4_lease={} v4_last_declined={} v4_last_released={} v6_state={} v6_ip={} v6_preferred={} v6_valid={}",
            state.v4_state,
            v4_ip,
            v4_lease,
            v4_last_declined,
            v4_last_released,
            state.v6_state,
            v6_ip,
            v6_pref,
            v6_valid
        )))
    }

    /// DHCP renew — 非同期版（推奨）
    pub async fn dhcp_renew() -> ExoValue<'static> {
        match crate::net::api::dhcp::dhcp_renew_in(crate::net::runtime::default_runtime()).await {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(e),
        }
    }

    /// DHCP discover — 非同期版（推奨）
    pub async fn dhcp_discover() -> ExoValue<'static> {
        if let Some(info) =
            crate::net::api::dhcp::dhcp_discover_in(crate::net::runtime::default_runtime()).await
        {
            let mut map = BTreeMap::new();
            map.insert(
                String::from("server_ip"),
                ExoValue::String(Cow::Owned(format!(
                    "{}.{}.{}.{}",
                    info.server_ip[0], info.server_ip[1], info.server_ip[2], info.server_ip[3]
                ))),
            );
            map.insert(
                String::from("offered_ip"),
                ExoValue::String(Cow::Owned(format!(
                    "{}.{}.{}.{}",
                    info.offered_ip[0], info.offered_ip[1], info.offered_ip[2], info.offered_ip[3]
                ))),
            );
            ExoValue::Map(map)
        } else {
            ExoValue::Nil
        }
    }

    /// DHCP release — 非同期版（推奨）
    pub async fn dhcp_release() -> ExoValue<'static> {
        let released =
            crate::net::api::dhcp::dhcp_release_in(crate::net::runtime::default_runtime()).await;
        ExoValue::Bool(released)
    }

    /// DHCP inform — 非同期版（推奨）
    pub async fn dhcp_inform() -> ExoValue<'static> {
        match crate::net::api::dhcp::dhcp_inform_in(crate::net::runtime::default_runtime()).await {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(e),
        }
    }

    /// DHCP last declined — 非同期版（推奨）
    pub async fn dhcp_last_declined() -> ExoValue<'static> {
        match crate::net::api::dhcp::dhcp_last_declined_in(crate::net::runtime::default_runtime())
            .await
        {
            Some(o) => ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))),
            None => ExoValue::Nil,
        }
    }

    /// DHCP last released — 非同期版（推奨）
    pub async fn dhcp_last_released() -> ExoValue<'static> {
        match crate::net::api::dhcp::dhcp_last_released_in(crate::net::runtime::default_runtime())
            .await
        {
            Some(o) => ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))),
            None => ExoValue::Nil,
        }
    }

    /// ICMP エコー送信（完全非同期版）
    ///
    /// `IcmpEchoFuture` を使用し、イベントキュー経由で送信・応答待機を行う。
    /// 同期ロックやIRQ無効化を一切使用しない。
    /// Requires CAP_NET_RAW
    pub async fn ping(ip: [u8; 4], count: u16) -> ExoValue<'static> {
        // セキュリティチェック
        let domain_id = Self::current_domain_id();
        // Kernel domain(0) is trusted control plane; allow diagnostic ping
        // even when capability tables are not explicitly seeded yet.
        if domain_id != 0 && !manager().has_capability(domain_id, CAP_NET_RAW) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_RAW required"));
        }

        let mut results = Vec::new();
        for seq in 1..=count {
            // 各パケット送信前にyield（他タスクに機会を与える）
            crate::task::yield_now().await;

            // 完全非同期: IcmpEchoFuture 経由で送信 + 応答待機
            match crate::net::api::icmp::ping_in(crate::net::runtime::default_runtime(), ip, seq)
                .await
            {
                Ok(echo) => {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("seq"), ExoValue::Int(seq as i64));
                    // rtt_us（マイクロ秒）をミリ秒に変換
                    map.insert(
                        String::from("rtt_ms"),
                        ExoValue::Float(echo.rtt_us as f64 / 1000.0),
                    );
                    map.insert(String::from("success"), ExoValue::Bool(true));
                    results.push(ExoValue::Map(map));
                }
                Err(e) => {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("seq"), ExoValue::Int(seq as i64));
                    map.insert(
                        String::from("error"),
                        ExoValue::String(Cow::Owned(alloc::format!("{:?}", e))),
                    );
                    map.insert(String::from("success"), ExoValue::Bool(false));
                    results.push(ExoValue::Map(map));
                }
            }

            // パケット間に少し待機（async sleep）
            if seq < count {
                crate::task::sleep_ms(100).await;
            }
        }
        ExoValue::Array(results)
    }

    // ================================================================
    // TCP/UDP接続一覧 (netstat相当)
    // ================================================================

    /// TCP接続一覧 (非同期版)
    pub async fn tcp_connections() -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.tcp") {
            return e;
        }
        let connections = crate::net::api::connections::get_tcp_connections_in(
            crate::net::runtime::default_runtime(),
        )
        .await;
        let values: Vec<ExoValue> = connections
            .into_iter()
            .map(|c| {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("local"),
                    ExoValue::String(Cow::Owned(c.local_addr)),
                );
                map.insert(
                    String::from("remote"),
                    ExoValue::String(Cow::Owned(c.remote_addr)),
                );
                map.insert(String::from("state"), ExoValue::String(Cow::Owned(c.state)));
                ExoValue::Map(map)
            })
            .collect();
        ExoValue::Array(values)
    }

    /// UDP エンドポイント一覧 (非同期版)
    pub async fn udp_endpoints() -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.udp") {
            return e;
        }
        let endpoints = crate::net::api::connections::get_udp_endpoints_in(
            crate::net::runtime::default_runtime(),
        )
        .await;
        let values: Vec<ExoValue> = endpoints
            .into_iter()
            .map(|e| {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("local"),
                    ExoValue::String(Cow::Owned(e.local_addr)),
                );
                map.insert(
                    String::from("remote"),
                    ExoValue::String(Cow::Owned(e.remote_addr)),
                );
                ExoValue::Map(map)
            })
            .collect();
        ExoValue::Array(values)
    }

    /// netstat相当 — TCP接続 + UDPエンドポイント統合表示
    pub async fn netstat() -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.netstat") {
            return e;
        }
        let tcp_connections = crate::net::api::connections::get_tcp_connections_in(
            crate::net::runtime::default_runtime(),
        )
        .await;
        let udp_endpoints = crate::net::api::connections::get_udp_endpoints_in(
            crate::net::runtime::default_runtime(),
        )
        .await;

        let tcp_values: Vec<ExoValue> = tcp_connections
            .into_iter()
            .map(|c| {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("proto"),
                    ExoValue::String(Cow::Borrowed("TCP")),
                );
                map.insert(
                    String::from("local"),
                    ExoValue::String(Cow::Owned(c.local_addr)),
                );
                map.insert(
                    String::from("remote"),
                    ExoValue::String(Cow::Owned(c.remote_addr)),
                );
                map.insert(String::from("state"), ExoValue::String(Cow::Owned(c.state)));
                ExoValue::Map(map)
            })
            .collect();

        let udp_values: Vec<ExoValue> = udp_endpoints
            .into_iter()
            .map(|e| {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("proto"),
                    ExoValue::String(Cow::Borrowed("UDP")),
                );
                map.insert(
                    String::from("local"),
                    ExoValue::String(Cow::Owned(e.local_addr)),
                );
                map.insert(
                    String::from("remote"),
                    ExoValue::String(Cow::Owned(e.remote_addr)),
                );
                map.insert(String::from("state"), ExoValue::String(Cow::Borrowed("-")));
                ExoValue::Map(map)
            })
            .collect();

        let mut all = tcp_values;
        all.extend(udp_values);
        ExoValue::Array(all)
    }

    // ================================================================
    // インターフェース管理
    // ================================================================

    /// ネットワークインターフェース一覧
    pub async fn interfaces() -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.interfaces") {
            return e;
        }
        let values: Vec<ExoValue> =
            crate::net::api::config::list_interfaces_in(crate::net::runtime::default_runtime())
                .await
                .into_iter()
                .map(|iface| {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("if_id"), ExoValue::Int(iface.if_id as i64));
                    map.insert(
                        String::from("name"),
                        ExoValue::String(Cow::Owned(iface.name)),
                    );
                    map.insert(String::from("admin_up"), ExoValue::Bool(iface.admin_up));
                    if let Some(ip) = iface.ip {
                        map.insert(
                            String::from("ip"),
                            ExoValue::String(Cow::Owned(format!(
                                "{}.{}.{}.{}",
                                ip[0], ip[1], ip[2], ip[3]
                            ))),
                        );
                    } else {
                        map.insert(String::from("ip"), ExoValue::Nil);
                    }
                    if let Some(mac) = iface.mac {
                        map.insert(
                            String::from("mac"),
                            ExoValue::String(Cow::Owned(format!(
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                            ))),
                        );
                    }
                    ExoValue::Map(map)
                })
                .collect();
        ExoValue::Array(values)
    }

    /// インターフェースを有効化（管理権限必要）
    pub async fn if_up(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        let if_id = match args.first().and_then(Self::parse_if_id_value) {
            Some(if_id) => if_id,
            _ => return ExoValue::Error(String::from("usage: net.if_up(interface_id)")),
        };
        match crate::net::runtime::manager::set_interface_up_in(
            crate::net::runtime::default_runtime(),
            if_id,
        ) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("Failed: {:?}", e)),
        }
    }

    /// インターフェースを無効化（管理権限必要）
    pub async fn if_down(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        let if_id = match args.first().and_then(Self::parse_if_id_value) {
            Some(if_id) => if_id,
            _ => return ExoValue::Error(String::from("usage: net.if_down(interface_id)")),
        };
        match crate::net::runtime::manager::set_interface_down_in(
            crate::net::runtime::default_runtime(),
            if_id,
        ) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("Failed: {:?}", e)),
        }
    }

    // ================================================================
    // ルーティングテーブル管理
    // ================================================================

    /// IPv4/IPv6 ルーティングテーブル表示
    pub async fn routes() -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.routes") {
            return e;
        }
        let mut entries = Vec::new();

        // IPv4 routes
        if let Ok(routes) = crate::net::runtime::manager::list_ipv4_routes_in(
            crate::net::runtime::default_runtime(),
        ) {
            for r in routes {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("family"),
                    ExoValue::String(Cow::Borrowed("IPv4")),
                );
                map.insert(
                    String::from("destination"),
                    ExoValue::String(Cow::Owned(format!("{}/{}", r.destination, r.prefix_len))),
                );
                map.insert(
                    String::from("gateway"),
                    match r.gateway {
                        Some(gw) => ExoValue::String(Cow::Owned(format!("{}", gw))),
                        None => ExoValue::String(Cow::Borrowed("*")),
                    },
                );
                map.insert(String::from("if_id"), ExoValue::Int(r.if_id.0 as i64));
                map.insert(String::from("metric"), ExoValue::Int(r.metric as i64));
                let mut flags_str = String::new();
                if r.flags.connected {
                    flags_str.push('C');
                }
                if r.flags.static_route {
                    flags_str.push('S');
                }
                if r.flags.default_route {
                    flags_str.push('D');
                }
                if !r.admin_enabled {
                    flags_str.push_str("(down)");
                }
                map.insert(
                    String::from("flags"),
                    ExoValue::String(Cow::Owned(flags_str)),
                );
                entries.push(ExoValue::Map(map));
            }
        }

        // IPv6 routes
        if let Ok(routes) = crate::net::runtime::manager::list_ipv6_routes_in(
            crate::net::runtime::default_runtime(),
        ) {
            for r in routes {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("family"),
                    ExoValue::String(Cow::Borrowed("IPv6")),
                );
                map.insert(
                    String::from("destination"),
                    ExoValue::String(Cow::Owned(format!("{}/{}", r.destination, r.prefix_len))),
                );
                map.insert(
                    String::from("gateway"),
                    match r.gateway {
                        Some(gw) => ExoValue::String(Cow::Owned(format!("{}", gw))),
                        None => ExoValue::String(Cow::Borrowed("*")),
                    },
                );
                map.insert(String::from("if_id"), ExoValue::Int(r.if_id.0 as i64));
                map.insert(String::from("metric"), ExoValue::Int(r.metric as i64));
                let mut flags_str = String::new();
                if r.flags.connected {
                    flags_str.push('C');
                }
                if r.flags.static_route {
                    flags_str.push('S');
                }
                if r.flags.default_route {
                    flags_str.push('D');
                }
                if !r.admin_enabled {
                    flags_str.push_str("(down)");
                }
                map.insert(
                    String::from("flags"),
                    ExoValue::String(Cow::Owned(flags_str)),
                );
                entries.push(ExoValue::Map(map));
            }
        }

        ExoValue::Array(entries)
    }

    /// IPv4ルート追加（管理権限必要）
    ///
    /// usage: net.route_add("192.168.1.0", 24, "10.0.2.1", 0, 100)
    ///        net.route_add(dest, prefix_len, gateway, if_id, metric)
    pub async fn route_add(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        if args.len() < 4 {
            return ExoValue::Error(String::from(
                "usage: net.route_add(dest, prefix_len, gateway, if_id [, metric])\n\
                 例: net.route_add(\"192.168.1.0\", 24, \"10.0.2.1\", 0)",
            ));
        }
        let dest = match Self::parse_ipv4_arg(&args[0]) {
            Ok(ip) => crate::net::l3::ipv4::Ipv4Address::new(ip),
            Err(e) => return ExoValue::Error(format!("dest: {}", e)),
        };
        let prefix_len = match &args[1] {
            ExoValue::Int(n) => *n as u8,
            _ => return ExoValue::Error(String::from("prefix_len must be integer")),
        };
        let gateway = match &args[2] {
            ExoValue::String(s) if s.as_ref() == "*" || s.as_ref() == "none" => None,
            other => match Self::parse_ipv4_arg(other) {
                Ok(ip) => Some(crate::net::l3::ipv4::Ipv4Address::new(ip)),
                Err(e) => return ExoValue::Error(format!("gateway: {}", e)),
            },
        };
        let if_id = match Self::parse_if_id_value(&args[3]) {
            Some(if_id) => if_id,
            _ => return ExoValue::Error(String::from("if_id must be integer")),
        };
        let metric = args
            .get(4)
            .and_then(|v| match v {
                ExoValue::Int(n) => Some(*n as u32),
                _ => None,
            })
            .unwrap_or(100);

        let route = crate::net::runtime::manager::Ipv4Route {
            destination: dest,
            prefix_len,
            gateway,
            if_id,
            metric,
            flags: crate::net::runtime::manager::RouteFlags::static_route(),
            admin_enabled: true,
            managed_by_interface: false,
        };
        match crate::net::runtime::manager::add_ipv4_route_in(
            crate::net::runtime::default_runtime(),
            route,
        ) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("Failed to add route: {:?}", e)),
        }
    }

    /// IPv4 ルート削除（管理権限必要）
    ///
    /// usage: net.route_del("192.168.1.0", 24, 0)
    ///        net.route_del(dest, prefix_len, if_id)
    pub async fn route_del(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        if args.len() < 3 {
            return ExoValue::Error(String::from(
                "usage: net.route_del(dest, prefix_len, if_id)\n\
                 例: net.route_del(\"192.168.1.0\", 24, 0)",
            ));
        }
        let dest = match Self::parse_ipv4_arg(&args[0]) {
            Ok(ip) => crate::net::l3::ipv4::Ipv4Address::new(ip),
            Err(e) => return ExoValue::Error(format!("dest: {}", e)),
        };
        let prefix_len = match &args[1] {
            ExoValue::Int(n) => *n as u8,
            _ => return ExoValue::Error(String::from("prefix_len must be integer")),
        };
        let if_id = match Self::parse_if_id_value(&args[2]) {
            Some(if_id) => if_id,
            _ => return ExoValue::Error(String::from("if_id must be integer")),
        };
        // Build a route to match for deletion (gateway/metric/flags don't matter for retain comparison)
        let route = crate::net::runtime::manager::Ipv4Route {
            destination: dest,
            prefix_len,
            gateway: None,
            if_id,
            metric: 0,
            flags: crate::net::runtime::manager::RouteFlags::static_route(),
            admin_enabled: true,
            managed_by_interface: false,
        };
        match crate::net::runtime::manager::del_ipv4_route_in(
            crate::net::runtime::default_runtime(),
            route,
        ) {
            Ok(deleted) => ExoValue::Bool(deleted),
            Err(e) => ExoValue::Error(format!("Failed to delete route: {:?}", e)),
        }
    }

    // ================================================================
    // ファイアウォール管理
    // ================================================================

    /// ファイアウォール状態表示
    pub async fn firewall_status() -> ExoValue<'static> {
        let status =
            crate::net::api::firewall::firewall_status_in(crate::net::runtime::default_runtime())
                .await;
        ExoValue::String(Cow::Owned(status))
    }

    /// ファイアウォール有効化 (管理権限必要)
    pub async fn firewall_enable() -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        match crate::net::api::firewall::firewall_enable_in(crate::net::runtime::default_runtime())
            .await
        {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// ファイアウォール無効化 (管理権限必要)
    pub async fn firewall_disable() -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        match crate::net::api::firewall::firewall_disable_in(crate::net::runtime::default_runtime())
            .await
        {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// ファイアウォールルール一覧表示
    pub async fn firewall_rules() -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.firewall_rules") {
            return e;
        }
        let rules = crate::net::api::firewall::firewall_list_rules_in(
            crate::net::runtime::default_runtime(),
        )
        .await;
        ExoValue::String(Cow::Owned(rules))
    }

    /// ファイアウォール統計情報
    pub async fn firewall_stats() -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.firewall_stats") {
            return e;
        }
        let stats =
            crate::net::api::firewall::firewall_stats_in(crate::net::runtime::default_runtime())
                .await;
        ExoValue::String(Cow::Owned(stats))
    }

    /// ファイアウォールルール追加 (管理権限必要)
    ///
    /// usage: net.firewall_add("deny", "in", "10.0.0.0/8", "*", "tcp", "*", "22", 50, "block-ssh")
    pub async fn firewall_add(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        if args.len() < 8 {
            return ExoValue::Error(String::from(
                "usage: net.firewall_add(action, direction, src_ip, dst_ip, protocol, src_port, dst_port, priority [, name])\n\
                 例: net.firewall_add(\"deny\", \"in\", \"*\", \"*\", \"tcp\", \"*\", \"22\", 50, \"block-ssh\")",
            ));
        }
        let str_arg = |i: usize| -> Result<&str, ExoValue<'static>> {
            match &args[i] {
                ExoValue::String(s) => Ok(s.as_ref()),
                _ => Err(ExoValue::Error(format!("arg {} must be a string", i + 1))),
            }
        };
        let action = match str_arg(0) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let direction = match str_arg(1) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let src_ip = match str_arg(2) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let dst_ip = match str_arg(3) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let protocol = match str_arg(4) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let src_port = match str_arg(5) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let dst_port = match str_arg(6) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let priority = match &args[7] {
            ExoValue::Int(n) => *n as u16,
            ExoValue::String(s) => s.parse::<u16>().unwrap_or(100),
            _ => 100,
        };
        let name = args
            .get(8)
            .and_then(|v| match v {
                ExoValue::String(s) => Some(s.as_ref()),
                _ => None,
            })
            .unwrap_or("");

        match crate::net::api::firewall::firewall_add_rule_in(
            crate::net::runtime::default_runtime(),
            action,
            direction,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            priority,
            name,
        )
        .await
        {
            Ok(id) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("rule_id"), ExoValue::Int(id as i64));
                map.insert(String::from("success"), ExoValue::Bool(true));
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(e),
        }
    }

    /// ファイアウォールルール削除 (管理権限必要)
    pub async fn firewall_remove(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        let rule_id = match args.first() {
            Some(ExoValue::Int(n)) => *n as u64,
            _ => return ExoValue::Error(String::from("usage: net.firewall_remove(rule_id)")),
        };
        match crate::net::api::firewall::firewall_remove_rule_in(
            crate::net::runtime::default_runtime(),
            rule_id,
        )
        .await
        {
            Ok(deleted) => ExoValue::Bool(deleted),
            Err(e) => ExoValue::Error(e),
        }
    }

    /// ファイアウォールルール全削除 (管理権限必要)
    pub async fn firewall_clear() -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        match crate::net::api::firewall::firewall_clear_rules_in(
            crate::net::runtime::default_runtime(),
        )
        .await
        {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(e),
        }
    }

    /// ファイアウォールデフォルトポリシー設定 (管理権限必要)
    ///
    /// usage: net.firewall_policy("in", "deny")
    pub async fn firewall_policy(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let domain_id = Self::current_domain_id();
        if !manager().has_capability(domain_id, CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }
        if args.len() < 2 {
            return ExoValue::Error(String::from(
                "usage: net.firewall_policy(direction, action)\n\
                 例: net.firewall_policy(\"in\", \"deny\")",
            ));
        }
        let direction = match &args[0] {
            ExoValue::String(s) => s.as_ref(),
            _ => return ExoValue::Error(String::from("direction must be string")),
        };
        let action = match &args[1] {
            ExoValue::String(s) => s.as_ref(),
            _ => return ExoValue::Error(String::from("action must be string")),
        };
        match crate::net::api::firewall::firewall_set_default_policy_in(
            crate::net::runtime::default_runtime(),
            direction,
            action,
        )
        .await
        {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(e),
        }
    }

    // ================================================================
    // ネットワーク診断・スナップショット
    // ================================================================

    /// ネットワーク全体のスナップショット (カウンタ + インターフェース + イベント)
    pub async fn snapshot() -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.snapshot") {
            return e;
        }
        let snap = crate::net::api::diagnostics::network_snapshot_in(
            crate::net::runtime::default_runtime(),
        )
        .await;
        let mut map = BTreeMap::new();
        map.insert(
            String::from("rx_packets"),
            ExoValue::Int(snap.rx_packets as i64),
        );
        map.insert(
            String::from("tx_packets"),
            ExoValue::Int(snap.tx_packets as i64),
        );
        map.insert(
            String::from("rx_bytes"),
            ExoValue::Int(snap.rx_bytes as i64),
        );
        map.insert(
            String::from("tx_bytes"),
            ExoValue::Int(snap.tx_bytes as i64),
        );
        map.insert(String::from("drops"), ExoValue::Int(snap.drops as i64));
        map.insert(String::from("errors"), ExoValue::Int(snap.errors as i64));

        let ifaces: Vec<ExoValue> = snap
            .interfaces
            .into_iter()
            .map(|iface| {
                let mut m = BTreeMap::new();
                m.insert(
                    String::from("name"),
                    ExoValue::String(Cow::Owned(iface.name)),
                );
                m.insert(
                    String::from("rx_packets"),
                    ExoValue::Int(iface.rx_packets as i64),
                );
                m.insert(
                    String::from("tx_packets"),
                    ExoValue::Int(iface.tx_packets as i64),
                );
                ExoValue::Map(m)
            })
            .collect();
        map.insert(String::from("interfaces"), ExoValue::Array(ifaces));
        map.insert(
            String::from("recent_events_count"),
            ExoValue::Int(snap.recent_events.len() as i64),
        );

        ExoValue::Map(map)
    }

    /// 最近のネットワークイベント一覧
    ///
    /// usage: net.events(limit)  — デフォルト20件
    pub async fn events(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        if let Err(e) = Self::require_net_admin("net.events") {
            return e;
        }
        let limit = args
            .first()
            .and_then(|v| match v {
                ExoValue::Int(n) => Some(*n as usize),
                _ => None,
            })
            .unwrap_or(20);
        let events = crate::net::api::diagnostics::network_recent_events_in(
            crate::net::runtime::default_runtime(),
            limit,
        )
        .await;
        let values: Vec<ExoValue> = events
            .into_iter()
            .map(|e| {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("layer"),
                    ExoValue::String(Cow::Owned(format!("{:?}", e.layer))),
                );
                map.insert(
                    String::from("kind"),
                    ExoValue::String(Cow::Owned(format!("{:?}", e.kind))),
                );
                map.insert(
                    String::from("message"),
                    ExoValue::String(Cow::Borrowed(e.message)),
                );
                map.insert(String::from("ts_ms"), ExoValue::Int(e.ts_ms as i64));
                ExoValue::Map(map)
            })
            .collect();
        ExoValue::Array(values)
    }

    pub async fn dns_resolve(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let name = match args.first() {
            Some(ExoValue::String(name)) => name.as_ref(),
            _ => return ExoValue::Error(String::from("usage: net.dns(name)")),
        };
        match crate::net::services::dns::resolve_ipv4(name).await {
            Some(addr) => {
                let octets = addr.octets();
                ExoValue::String(Cow::Owned(format!(
                    "{}.{}.{}.{}",
                    octets[0], octets[1], octets[2], octets[3]
                )))
            }
            None => ExoValue::Nil,
        }
    }

    pub async fn dns_resolve_ipv6(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let name = match args.first() {
            Some(ExoValue::String(name)) => name.as_ref(),
            _ => return ExoValue::Error(String::from("usage: net.dns6(name)")),
        };
        match crate::net::services::dns::resolve_ipv6(name).await {
            Some(addr) => ExoValue::String(Cow::Owned(Self::format_ipv6(addr.octets()))),
            None => ExoValue::Nil,
        }
    }

    pub async fn dns_resolve_txt(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let name = match args.first() {
            Some(ExoValue::String(name)) => name.as_ref(),
            _ => return ExoValue::Error(String::from("usage: net.dns_txt(name)")),
        };
        let Some(records) = crate::net::services::dns::resolve_txt(name).await else {
            return ExoValue::Nil;
        };
        ExoValue::Array(
            records
                .into_iter()
                .map(|record| ExoValue::String(Cow::Owned(record)))
                .collect(),
        )
    }

    pub async fn dns_resolve_mx(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let name = match args.first() {
            Some(ExoValue::String(name)) => name.as_ref(),
            _ => return ExoValue::Error(String::from("usage: net.dns_mx(name)")),
        };
        let Some(records) = crate::net::services::dns::resolve_mx(name).await else {
            return ExoValue::Nil;
        };
        ExoValue::Array(
            records
                .into_iter()
                .map(|record| {
                    let mut map = BTreeMap::new();
                    map.insert(
                        String::from("preference"),
                        ExoValue::Int(record.preference as i64),
                    );
                    map.insert(
                        String::from("exchange"),
                        ExoValue::String(Cow::Owned(record.exchange)),
                    );
                    ExoValue::Map(map)
                })
                .collect(),
        )
    }

    pub async fn dns_resolve_srv(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let name = match args.first() {
            Some(ExoValue::String(name)) => name.as_ref(),
            _ => return ExoValue::Error(String::from("usage: net.dns_srv(name)")),
        };
        let Some(records) = crate::net::services::dns::resolve_srv(name).await else {
            return ExoValue::Nil;
        };
        ExoValue::Array(
            records
                .into_iter()
                .map(|record| {
                    let mut map = BTreeMap::new();
                    map.insert(
                        String::from("priority"),
                        ExoValue::Int(record.priority as i64),
                    );
                    map.insert(String::from("weight"), ExoValue::Int(record.weight as i64));
                    map.insert(String::from("port"), ExoValue::Int(record.port as i64));
                    map.insert(
                        String::from("target"),
                        ExoValue::String(Cow::Owned(record.target)),
                    );
                    ExoValue::Map(map)
                })
                .collect(),
        )
    }

    pub async fn dns_reverse_ipv4(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let octets = match args.first() {
            Some(value) => match Self::parse_ipv4_arg(value) {
                Ok(octets) => octets,
                Err(err) => return ExoValue::Error(err),
            },
            None => return ExoValue::Error(String::from("usage: net.dns_ptr(ipv4)")),
        };
        match crate::net::services::dns::resolve_ptr_ipv4(crate::net::l3::ipv4::Ipv4Address::new(
            octets,
        ))
        .await
        {
            Some(name) => ExoValue::String(Cow::Owned(name)),
            None => ExoValue::Nil,
        }
    }

    pub async fn dns_reverse_ipv6(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let octets = match args.first() {
            Some(value) => match Self::parse_ipv6_arg(value) {
                Ok(octets) => octets,
                Err(err) => return ExoValue::Error(err),
            },
            None => return ExoValue::Error(String::from("usage: net.dns_ptr6(ipv6)")),
        };
        match crate::net::services::dns::resolve_ptr_ipv6(crate::net::l3::ipv6::Ipv6Address::new(
            octets,
        ))
        .await
        {
            Some(name) => ExoValue::String(Cow::Owned(name)),
            None => ExoValue::Nil,
        }
    }

    // ================================================================
    // ヘルパー
    // ================================================================

    /// ExoValueからIPv4アドレスをパースするヘルパー
    fn parse_ipv4_arg(val: &ExoValue<'_>) -> Result<[u8; 4], String> {
        match val {
            ExoValue::String(s) => {
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
            _ => Err(String::from("IP address must be a string")),
        }
    }

    /// ExoValueからIPv6アドレスをパースするヘルパー
    fn parse_ipv6_arg(val: &ExoValue<'_>) -> Result<[u8; 16], String> {
        fn parse_hextets(part: &str, original: &str) -> Result<Vec<u16>, String> {
            if part.is_empty() {
                return Ok(Vec::new());
            }

            let mut out = Vec::new();
            for segment in part.split(':') {
                if segment.is_empty() || segment.contains('.') || segment.len() > 4 {
                    return Err(format!("invalid IPv6: '{}'", original));
                }
                let word = u16::from_str_radix(segment, 16)
                    .map_err(|_| format!("invalid IPv6: '{}'", original))?;
                out.push(word);
            }
            Ok(out)
        }

        let s = match val {
            ExoValue::String(s) => s.trim(),
            _ => return Err(String::from("IPv6 address must be a string")),
        };
        if s.is_empty() {
            return Err(String::from("invalid IPv6: empty"));
        }

        let mut double_colon_split = s.split("::");
        let left_part = double_colon_split.next().unwrap_or_default();
        let right_part = double_colon_split.next();
        if double_colon_split.next().is_some() {
            return Err(format!("invalid IPv6: '{}'", s));
        }

        let left = parse_hextets(left_part, s)?;
        let words: Vec<u16> = if let Some(right_part) = right_part {
            let right = parse_hextets(right_part, s)?;
            if left.len() + right.len() >= 8 {
                return Err(format!("invalid IPv6: '{}'", s));
            }
            let mut out = Vec::with_capacity(8);
            out.extend_from_slice(&left);
            for _ in 0..(8 - left.len() - right.len()) {
                out.push(0);
            }
            out.extend_from_slice(&right);
            out
        } else {
            if left.len() != 8 {
                return Err(format!("invalid IPv6: '{}'", s));
            }
            left
        };

        if words.len() != 8 {
            return Err(format!("invalid IPv6: '{}'", s));
        }

        let mut octets = [0u8; 16];
        for (i, word) in words.iter().enumerate() {
            let bytes = word.to_be_bytes();
            octets[i * 2] = bytes[0];
            octets[i * 2 + 1] = bytes[1];
        }
        Ok(octets)
    }

    /// 非同期版 handle_open: イベントキュー経由で UDP bind を実行
    async fn handle_open(_args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let port = match _args.get(0) {
            Some(ExoValue::Int(n)) => *n as u16,
            Some(ExoValue::String(s)) => s.parse::<u16>().unwrap_or(0),
            _ => {
                return ExoValue::Error(String::from(
                    "open(port[, token]) requires a port integer",
                ));
            }
        };
        if port == 0 {
            return ExoValue::Error(String::from("Invalid port"));
        }
        let mut token_opt: Option<u64> = None;
        if let Some(arg2) = _args.get(1) {
            match arg2 {
                ExoValue::Int(n) => token_opt = Some(*n as u64),
                ExoValue::Capability(cap) => token_opt = Some(cap.id),
                _ => {}
            }
        }
        let domain_id = Self::current_domain_id();
        if let Some(t) = token_opt {
            let grants = manager().list_grants(domain_id, domain_id);
            if !grants.iter().any(|g| g.id == t) {
                return ExoValue::Error(String::from("Permission denied: token not owned"));
            }
            match crate::net::l4::udp::UdpEndpoint::bind_in(
                crate::net::runtime::default_runtime(),
                crate::net::types::InterfaceScope::Any,
                port,
                Some(t),
            ) {
                Ok(_) => ExoValue::Bool(true),
                Err(_) => ExoValue::Error(String::from("open failed")),
            }
        } else {
            if !manager().has_capability(domain_id, CAP_NET_BIND) {
                return ExoValue::Error(String::from("Permission denied: CAP_NET_BIND required"));
            }
            match crate::net::l4::udp::UdpEndpoint::bind_in(
                crate::net::runtime::default_runtime(),
                crate::net::types::InterfaceScope::Any,
                port,
                None,
            ) {
                Ok(_) => ExoValue::Bool(true),
                Err(_) => ExoValue::Error(String::from("open failed")),
            }
        }
    }
}

impl ShellNamespace for NetNamespace {
    fn name(&self) -> &str {
        "net"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        _args: &'a [ExoValue<'static>],
        _caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "config" => Self::config(_args).await,
                "stats" => Self::stats(_args).await,
                "arp" => Self::arp_cache().await,
                "arp_insert" => Self::arp_insert(_args).await,
                "dhcp_state" => Self::dhcp_state(_args).await,
                "dhcp_renew" => Self::dhcp_renew().await,
                "dhcp_discover" => Self::dhcp_discover().await,
                "dhcp_release" => Self::dhcp_release().await,
                "dhcp_inform" => Self::dhcp_inform().await,
                "dhcp_last_declined" => Self::dhcp_last_declined().await,
                "dhcp_last_released" => Self::dhcp_last_released().await,
                "open" => Self::handle_open(_args).await,
                // TCP/UDP接続管理
                "connections" | "netstat" => Self::netstat().await,
                "tcp" => Self::tcp_connections().await,
                "udp" => Self::udp_endpoints().await,
                // インターフェース管理
                "interfaces" | "ifaces" => Self::interfaces().await,
                "if_up" => Self::if_up(_args).await,
                "if_down" => Self::if_down(_args).await,
                // ルーティング
                "routes" => Self::routes().await,
                "route_add" => Self::route_add(_args).await,
                "route_del" => Self::route_del(_args).await,
                // ファイアウォール
                "firewall" => Self::firewall_status().await,
                "firewall_enable" => Self::firewall_enable().await,
                "firewall_disable" => Self::firewall_disable().await,
                "firewall_rules" => Self::firewall_rules().await,
                "firewall_stats" => Self::firewall_stats().await,
                "firewall_add" => Self::firewall_add(_args).await,
                "firewall_remove" => Self::firewall_remove(_args).await,
                "firewall_clear" => Self::firewall_clear().await,
                "firewall_policy" => Self::firewall_policy(_args).await,
                // DNS
                "dns" | "resolve" | "dns4" => Self::dns_resolve(_args).await,
                "dns6" => Self::dns_resolve_ipv6(_args).await,
                "dns_txt" => Self::dns_resolve_txt(_args).await,
                "dns_mx" => Self::dns_resolve_mx(_args).await,
                "dns_srv" => Self::dns_resolve_srv(_args).await,
                "dns_ptr" => Self::dns_reverse_ipv4(_args).await,
                "dns_ptr6" => Self::dns_reverse_ipv6(_args).await,
                // 診断
                "snapshot" => Self::snapshot().await,
                "events" => Self::events(_args).await,
                _ => ExoValue::Error(format!(
                    "Unknown method 'net.{}'\nValid methods:\n  \
                     config, stats, arp, arp_insert, ping, open,\n  \
                     connections/netstat, tcp, udp,\n  \
                     interfaces/ifaces, if_up, if_down,\n  \
                     routes, route_add, route_del,\n  \
                     firewall, firewall_enable, firewall_disable, firewall_rules, firewall_stats,\n  \
                     firewall_add, firewall_remove, firewall_clear, firewall_policy,\n  \
                     dns/dns4/resolve, dns6, dns_txt, dns_mx, dns_srv, dns_ptr, dns_ptr6,\n  \
                     snapshot, events,\n  \
                     dhcp_state, dhcp_renew, dhcp_discover, dhcp_release, dhcp_inform, dhcp_last_declined, dhcp_last_released",
                    method
                )),
            }
        })
    }
}
