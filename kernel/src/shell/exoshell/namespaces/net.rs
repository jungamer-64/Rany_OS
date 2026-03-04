// ============================================================================
// src/shell/exoshell/namespaces/net.rs - Network Namespace
// ============================================================================

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::{CAP_NET_RAW, CAP_NET_BIND, manager};
use crate::shell::exoshell::types::ExoValue;
use crate::net::runtime::stack::{bind_udp_endpoint_with_token_async, bind_udp_endpoint_async};
use alloc::boxed::Box;

/// ネットワーク名前空間
pub struct NetNamespace;

impl NetNamespace {
    /// 非同期版 open: イベントキュー経由で UDP bind を実行
    async fn dispatch_open_async(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let port = match args.get(0) {
            Some(ExoValue::Int(n)) => *n as u16,
            Some(ExoValue::String(s)) => s.parse::<u16>().unwrap_or(0),
            _ => return ExoValue::Error(String::from("open(port[, token]) requires a port integer")),
        };

        if port == 0 {
            return ExoValue::Error(String::from("Invalid port"));
        }

        let mut token_opt: Option<u64> = None;
        if let Some(arg2) = args.get(1) {
            match arg2 {
                ExoValue::Int(n) => token_opt = Some(*n as u64),
                ExoValue::Capability(cap) => token_opt = Some(cap.id),
                _ => {}
            }
        }

        let domain_id = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);

        if let Some(t) = token_opt {
            match bind_udp_endpoint_with_token_async(port, Some(t)).await {
                Some(_) => ExoValue::Bool(true),
                None => ExoValue::Error(String::from("open failed")),
            }
        } else {
            if !manager().has_capability(domain_id, CAP_NET_BIND) {
                return ExoValue::Error(String::from("Permission denied: CAP_NET_BIND required"));
            }
            match bind_udp_endpoint_async(port).await {
                Some(_) => ExoValue::Bool(true),
                None => ExoValue::Error(String::from("open failed")),
            }
        }
    }

    /// Dispatch methods for 'net' namespace（非推奨）
    ///
    /// # 非推奨
    /// 非同期版の `call()` インターフェースを使用すること。
    /// この同期 dispatch はレガシー互換のために残されている。
    #[deprecated(note = "Use async call() interface instead. Sync dispatch uses NETWORK_STACK lock.")]
    pub fn dispatch(
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match method {
            "config" => Self::config(),
            "stats" => Self::stats(),
            "arp" => Self::arp_cache(),
            "dhcp_state" => Self::dhcp_state(),
            "dhcp_discover" => Self::dhcp_discover(),
            "dhcp_request" => Self::dhcp_request(args),
            "dhcp_release" => Self::dhcp_release(),
            "dhcp_last_declined" => Self::dhcp_last_declined(),
            "dhcp_last_released" => Self::dhcp_last_released(),
            "dhcp_renew" => Self::dhcp_renew(),
            // dispatch_open は非同期版に移行済みのため dispatch() からは呼ばない
            "open" => ExoValue::Error(String::from("Use async call() interface for net.open")),
            _ => ExoValue::Error(format!("Unknown method 'net.{}'", method)),
        }
    }
    /// ネットワーク設定を取得（同期版 — レガシー互換）
    ///
    /// # 非推奨
    /// asyncコンテキストでは [`config_async()`] を使用すること。
    #[deprecated(note = "Use config_async() for async contexts.")]
    pub fn config() -> ExoValue<'static> {
        if let Some(cfg) = crate::net::api::config::get_network_config() {
            let mut map = BTreeMap::new();
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
        } else {
            ExoValue::Error(String::from("Network not configured"))
        }
    }

    /// ネットワーク統計（同期版 — レガシー互換）
    ///
    /// # 非推奨
    /// asyncコンテキストでは [`stats_async()`] を使用すること。
    #[deprecated(note = "Use stats_async() for async contexts.")]
    pub fn stats() -> ExoValue<'static> {
        if let Some(stats) = crate::net::api::config::get_network_stats() {
            let mut map = BTreeMap::new();
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
                String::from("rx_dropped"),
                ExoValue::Int(stats.rx_dropped as i64),
            );
            ExoValue::Map(map)
        } else {
            ExoValue::Error(String::from("No network statistics"))
        }
    }

    /// ARP キャッシュ（同期版 — レガシー互換）
    ///
    /// # 非推奨
    /// asyncコンテキストでは [`arp_cache_async()`] を使用すること。
    #[deprecated(note = "Use arp_cache_async() for async contexts.")]
    pub fn arp_cache() -> ExoValue<'static> {
        if let Some(entries) = crate::net::api::connections::get_arp_cache() {
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
        } else {
            ExoValue::Array(Vec::new())
        }
    }

    /// Insert an entry into the network stack's ARP cache.
    ///
    /// Takes two arguments: IP address string (e.g. "10.0.2.2") and MAC
    /// address string (e.g. "52:54:00:12:34:56"). Returns `true` on success.
    fn arp_insert(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        if args.len() != 2 {
            return ExoValue::Error(String::from("usage: net.arp_insert(ip, mac)"));
        }
        let ip = match &args[0] {
            ExoValue::String(s) => {
                // simple dotted-decimal parse
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
                // expected format xx:xx:xx:xx:xx:xx
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
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
                )
            }
            _ => return ExoValue::Error(String::from("mac must be string")),
        };
        let ok = crate::net::api::connections::arp_cache_insert(ip, mac);
        ExoValue::Bool(ok)
    }

    /// ネットワーク設定を取得（非同期版）
    pub async fn config_async() -> ExoValue<'static> {
        match crate::net::api::config::get_network_config_async().await {
            Some(cfg) => {
                let mut map = BTreeMap::new();
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
    pub async fn stats_async() -> ExoValue<'static> {
        match crate::net::api::config::get_network_stats_async().await {
            Some(stats) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("rx_packets"), ExoValue::Int(stats.rx_packets as i64));
                map.insert(String::from("tx_packets"), ExoValue::Int(stats.tx_packets as i64));
                map.insert(String::from("rx_bytes"), ExoValue::Int(stats.rx_bytes as i64));
                map.insert(String::from("tx_bytes"), ExoValue::Int(stats.tx_bytes as i64));
                map.insert(String::from("rx_errors"), ExoValue::Int(stats.rx_errors as i64));
                map.insert(String::from("rx_dropped"), ExoValue::Int(stats.rx_dropped as i64));
                ExoValue::Map(map)
            }
            None => ExoValue::Error(String::from("No network statistics")),
        }
    }

    /// ARPキャッシュ（非同期版）
    pub async fn arp_cache_async() -> ExoValue<'static> {
        let entries = crate::net::api::connections::get_arp_cache_async().await;
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

    fn format_ipv6(addr: [u8; 16]) -> String {
        format!("{}", crate::net::l3::ipv6::Ipv6Address::new(addr))
    }

    /// DHCP state snapshot (IPv4 + IPv6) — 同期版
    pub fn dhcp_state() -> ExoValue<'static> {
        let state = crate::net::api::dhcp::dhcp_state();
        Self::format_dhcp_state(state)
    }

    /// DHCP state snapshot — 非同期版（推奨）
    pub async fn dhcp_state_async() -> ExoValue<'static> {
        let state = crate::net::api::dhcp::dhcp_state_async().await;
        Self::format_dhcp_state(state)
    }

    /// DhcpRuntimeState を ExoValue に変換（共通ヘルパー）
    fn format_dhcp_state(state: crate::net::api::dhcp::DhcpRuntimeState) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(
            String::from("v4_state"),
            ExoValue::String(Cow::Owned(state.v4_state)),
        );
        map.insert(
            String::from("v4_assigned_ip"),
            match state.v4_assigned_ip {
                Some(ip) => ExoValue::String(Cow::Owned(format!(
                    "{}.{}.{}.{}",
                    ip[0], ip[1], ip[2], ip[3]
                ))),
                None => ExoValue::Nil,
            },
        );
        map.insert(
            String::from("v4_lease_remaining"),
            match state.v4_lease_remaining {
                Some(v) => ExoValue::Int(v as i64),
                None => ExoValue::Nil,
            },
        );
        map.insert(
            String::from("v4_last_declined"),
            match state.v4_last_declined {
                Some(ip) => ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))),
                None => ExoValue::Nil,
            },
        );
        map.insert(
            String::from("v4_last_released"),
            match state.v4_last_released {
                Some(ip) => ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))),
                None => ExoValue::Nil,
            },
        );
        map.insert(
            String::from("v6_state"),
            ExoValue::String(Cow::Owned(state.v6_state)),
        );
        map.insert(
            String::from("v6_assigned_ip"),
            match state.v6_assigned_ip {
                Some(ip) => ExoValue::String(Cow::Owned(Self::format_ipv6(ip))),
                None => ExoValue::Nil,
            },
        );
        map.insert(
            String::from("v6_preferred_remaining"),
            match state.v6_preferred_remaining {
                Some(v) => ExoValue::Int(v as i64),
                None => ExoValue::Nil,
            },
        );
        map.insert(
            String::from("v6_valid_remaining"),
            match state.v6_valid_remaining {
                Some(v) => ExoValue::Int(v as i64),
                None => ExoValue::Nil,
            },
        );
        ExoValue::Map(map)
    }

    /// Trigger DHCP renew/restart — 同期版
    pub fn dhcp_renew() -> ExoValue<'static> {
        match crate::net::api::dhcp::dhcp_renew() {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(e),
        }
    }

    /// DHCP renew — 非同期版（推奨）
    pub async fn dhcp_renew_async() -> ExoValue<'static> {
        match crate::net::api::dhcp::dhcp_renew_async().await {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(e),
        }
    }

    /// DHCP discover — 非同期版（推奨）
    pub async fn dhcp_discover_async() -> ExoValue<'static> {
        if let Some(info) = crate::net::api::dhcp::dhcp_discover_async().await {
            let mut map = BTreeMap::new();
            map.insert(
                String::from("server_ip"),
                ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", info.server_ip[0], info.server_ip[1], info.server_ip[2], info.server_ip[3]))),
            );
            map.insert(
                String::from("offered_ip"),
                ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", info.offered_ip[0], info.offered_ip[1], info.offered_ip[2], info.offered_ip[3]))),
            );
            ExoValue::Map(map)
        } else {
            ExoValue::Nil
        }
    }

    /// DHCP release — 非同期版（推奨）
    pub async fn dhcp_release_async() -> ExoValue<'static> {
        let released = crate::net::api::dhcp::dhcp_release_async().await;
        ExoValue::Bool(released)
    }

    /// DHCP last declined — 非同期版（推奨）
    pub async fn dhcp_last_declined_async() -> ExoValue<'static> {
        if let Some(ip) = crate::net::api::dhcp::dhcp_last_declined_async().await {
            ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])))
        } else {
            ExoValue::Nil
        }
    }

    /// DHCP last released — 非同期版（推奨）
    pub async fn dhcp_last_released_async() -> ExoValue<'static> {
        if let Some(ip) = crate::net::api::dhcp::dhcp_last_released_async().await {
            ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])))
        } else {
            ExoValue::Nil
        }
    }

    /// Send DHCPDISCOVER and report any currently stored offer
    pub fn dhcp_discover() -> ExoValue<'static> {
        if let Some(info) = crate::net::api::dhcp::dhcp_discover() {
            let mut map = BTreeMap::new();
            map.insert(
                String::from("server_ip"),
                ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", info.server_ip[0], info.server_ip[1], info.server_ip[2], info.server_ip[3]))),
            );
            map.insert(
                String::from("offered_ip"),
                ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", info.offered_ip[0], info.offered_ip[1], info.offered_ip[2], info.offered_ip[3]))),
            );
            ExoValue::Map(map)
        } else {
            ExoValue::Nil
        }
    }

    /// Send DHCPREQUEST to a specific server for a specific offered address.
    /// Arguments should be two IPv4 address strings (dotted).
    pub fn dhcp_request(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        fn parse_ip(val: &ExoValue<'static>) -> Option<[u8;4]> {
            match val {
                ExoValue::String(s) => {
                    let parts: Vec<_> = s.split('.').collect();
                    if parts.len() == 4 {
                        let mut out = [0u8;4];
                        for (i,p) in parts.iter().enumerate() {
                            if let Ok(n) = p.parse::<u8>() {
                                out[i] = n;
                            } else {
                                return None;
                            }
                        }
                        return Some(out);
                    }
                    None
                }
                _ => None,
            }
        }

        if args.len() < 2 {
            return ExoValue::Error(String::from("dhcp_request(server_ip, offered_ip) requires two arguments"));
        }
        let server = parse_ip(&args[0]).unwrap_or([0,0,0,0]);
        let offered = parse_ip(&args[1]).unwrap_or([0,0,0,0]);
        ExoValue::Bool(crate::net::api::dhcp::dhcp_request(server, offered))
    }

    /// Send DHCPRELEASE for current lease (if any)
    pub fn dhcp_release() -> ExoValue<'static> {
        crate::net::api::dhcp::dhcp_release();
        ExoValue::Bool(true)
    }

    /// last declined IP (string or nil)
    pub fn dhcp_last_declined() -> ExoValue<'static> {
        if let Some(ip) = crate::net::api::dhcp::dhcp_last_declined() {
            ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])))
        } else {
            ExoValue::Nil
        }
    }

    /// last released IP (string or nil)
    pub fn dhcp_last_released() -> ExoValue<'static> {
        if let Some(ip) = crate::net::api::dhcp::dhcp_last_released() {
            ExoValue::String(Cow::Owned(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])))
        } else {
            ExoValue::Nil
        }
    }

    /// ICMP エコー送信（完全非同期版）
    ///
    /// `IcmpEchoFuture` を使用し、イベントキュー経由で送信・応答待機を行う。
    /// 同期ロックやIRQ無効化を一切使用しない。
    /// Requires CAP_NET_RAW
    pub async fn ping(ip: [u8; 4], count: u16) -> ExoValue<'static> {
        // セキュリティチェック
        let domain_id = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);
        if !manager().has_capability(domain_id, CAP_NET_RAW) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_RAW required"));
        }

        let mut results = Vec::new();
        for seq in 1..=count {
            // 各パケット送信前にyield（他タスクに機会を与える）
            crate::task::yield_now().await;

            // 完全非同期: IcmpEchoFuture 経由で送信 + 応答待機
            match crate::net::api::icmp::ping_async(ip, seq).await {
                Ok(echo) => {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("seq"), ExoValue::Int(seq as i64));
                    // rtt_us（マイクロ秒）をミリ秒に変換
                    map.insert(String::from("rtt_ms"), ExoValue::Float(echo.rtt_us as f64 / 1000.0));
                    map.insert(String::from("success"), ExoValue::Bool(true));
                    results.push(ExoValue::Map(map));
                }
                Err(e) => {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("seq"), ExoValue::Int(seq as i64));
                    map.insert(
                        String::from("error"),
                        ExoValue::String(Cow::Owned(alloc::format!("{:?}", e)),
                    ));
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

    /// 非同期版 handle_open: イベントキュー経由で UDP bind を実行
    async fn handle_open_async(_args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let port = match _args.get(0) {
            Some(ExoValue::Int(n)) => *n as u16,
            Some(ExoValue::String(s)) => s.parse::<u16>().unwrap_or(0),
            _ => { return ExoValue::Error(String::from("open(port[, token]) requires a port integer")); }
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
        let domain_id = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_domain())
            .unwrap_or(0);
        if let Some(t) = token_opt {
            let grants = manager().list_grants(domain_id);
            if !grants.iter().any(|g| g.id == t) {
                return ExoValue::Error(String::from("Permission denied: token not owned"));
            }
            match bind_udp_endpoint_with_token_async(port, Some(t)).await {
                Some(_) => ExoValue::Bool(true),
                None => ExoValue::Error(String::from("open failed")),
            }
        } else {
            if !manager().has_capability(domain_id, CAP_NET_BIND) {
                return ExoValue::Error(String::from("Permission denied: CAP_NET_BIND required"));
            }
            match bind_udp_endpoint_async(port).await {
                Some(_) => ExoValue::Bool(true),
                None => ExoValue::Error(String::from("open failed")),
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
                "config" => Self::config_async().await,
                "stats" => Self::stats_async().await,
                "arp" => Self::arp_cache_async().await,
                "dhcp_state" => Self::dhcp_state_async().await,
                "dhcp_renew" => Self::dhcp_renew_async().await,
                "dhcp_discover" => Self::dhcp_discover_async().await,
                "dhcp_release" => Self::dhcp_release_async().await,
                "dhcp_last_declined" => Self::dhcp_last_declined_async().await,
                "dhcp_last_released" => Self::dhcp_last_released_async().await,
                "open" => Self::handle_open_async(_args).await,
                _ => ExoValue::Error(format!(
                    "Unknown method 'net.{}'\nValid methods: config, stats, arp, ping, open, dhcp_state, dhcp_renew, dhcp_discover, dhcp_release, dhcp_last_declined, dhcp_last_released",
                    method
                )),
            }
        })
    }
}
