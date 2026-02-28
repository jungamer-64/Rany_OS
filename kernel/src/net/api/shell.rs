use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::{TcpConnectionState, tcb_table};
use crate::net::runtime::bridge::send_real_icmp_echo;
use crate::net::runtime::stack;
use crate::net::services::dhcp;
use crate::sync::PoisonLock;

extern crate alloc;

/// Network configuration snapshot for shell commands.
#[derive(Debug, Clone)]
pub struct NetworkConfigSnapshot {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mac: [u8; 6],
}

/// Network statistics snapshot for shell commands.
#[derive(Debug, Clone, Copy)]
pub struct NetworkStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
}

/// TCP connection info for netstat.
#[derive(Debug, Clone)]
pub struct TcpConnectionInfo {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

/// UDP socket info for netstat.
#[derive(Debug, Clone)]
pub struct UdpSocketInfo {
    pub local_addr: String,
    pub remote_addr: String,
}

/// DHCP runtime state snapshot for v4/v6 clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpRuntimeState {
    pub v4_state: String,
    pub v4_assigned_ip: Option<[u8; 4]>,
    pub v4_lease_remaining: Option<u32>,
    pub v4_last_declined: Option<[u8; 4]>,
    pub v4_last_released: Option<[u8; 4]>,
    pub v6_state: String,
    pub v6_assigned_ip: Option<[u8; 16]>,
    pub v6_preferred_remaining: Option<u32>,
    pub v6_valid_remaining: Option<u32>,
}

/// ARP cache entry.
#[derive(Debug, Clone)]
pub struct ArpCacheEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub complete: bool,
}

/// DHCP offer info exposed for shell/API consumers.
#[derive(Debug, Clone)]
pub struct DhcpOfferInfo {
    pub server_ip: [u8; 4],
    pub offered_ip: [u8; 4],
}

// Fallback stats used if stack access fails.
static NETWORK_STATS: PoisonLock<NetworkStatsSnapshot> = PoisonLock::new(NetworkStatsSnapshot {
    rx_packets: 0,
    tx_packets: 0,
    rx_bytes: 0,
    tx_bytes: 0,
    rx_errors: 0,
    rx_dropped: 0,
});

pub fn get_network_config() -> Option<NetworkConfigSnapshot> {
    match stack::stack().lock() {
        Ok(guard) => guard.as_ref().map(|stack_guard| {
            let cfg = stack_guard.config();
            NetworkConfigSnapshot {
                ip: *cfg.ipv4.address.as_bytes(),
                netmask: *cfg.ipv4.subnet_mask.as_bytes(),
                gateway: *cfg.ipv4.gateway.as_bytes(),
                mac: *cfg.mac.as_bytes(),
            }
        }),
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_network_config)");
            None
        }
    }
}

pub fn get_network_stats() -> Option<NetworkStatsSnapshot> {
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(stack_guard) = guard.as_ref() {
                let stats = stack_guard.stats();
                return Some(NetworkStatsSnapshot {
                    rx_packets: stats.rx_packets.load(Ordering::Relaxed),
                    tx_packets: stats.tx_packets.load(Ordering::Relaxed),
                    rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
                    tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
                    rx_errors: stats.rx_errors.load(Ordering::Relaxed),
                    rx_dropped: stats.rx_dropped.load(Ordering::Relaxed),
                });
            }
        }
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_network_stats)");
            return None;
        }
    }

    let stats = match NETWORK_STATS.lock() {
        Ok(guard) => *guard,
        Err(_) => NetworkStatsSnapshot {
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_errors: 0,
            rx_dropped: 0,
        },
    };
    Some(stats)
}

pub fn send_icmp_echo(target: [u8; 4], seq: u16) -> Result<f32, String> {
    send_real_icmp_echo(target, seq)
        .map(|rtt| rtt as f32)
        .map_err(String::from)
}

pub fn get_tcp_connections() -> Option<Vec<TcpConnectionInfo>> {
    let snapshots = tcb_table().list_connections();
    if snapshots.is_empty() {
        return None;
    }

    let connections = snapshots
        .into_iter()
        .map(|snap| {
            let state = match snap.state {
                TcpConnectionState::Closed => "CLOSED",
                TcpConnectionState::Listen => "LISTEN",
                TcpConnectionState::SynSent => "SYN_SENT",
                TcpConnectionState::SynReceived => "SYN_RCVD",
                TcpConnectionState::Established => "ESTABLISHED",
                TcpConnectionState::FinWait1 => "FIN_WAIT1",
                TcpConnectionState::FinWait2 => "FIN_WAIT2",
                TcpConnectionState::CloseWait => "CLOSE_WAIT",
                TcpConnectionState::Closing => "CLOSING",
                TcpConnectionState::LastAck => "LAST_ACK",
                TcpConnectionState::TimeWait => "TIME_WAIT",
            };
            TcpConnectionInfo {
                local_addr: format!("{}", snap.local),
                remote_addr: format!("{}", snap.remote),
                state: String::from(state),
            }
        })
        .collect();

    Some(connections)
}

pub fn get_udp_sockets() -> Option<Vec<UdpSocketInfo>> {
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(ref stack_guard) = guard.as_ref() {
                let snapshots = stack_guard.list_udp_sockets();
                if snapshots.is_empty() {
                    return None;
                }
                return Some(
                    snapshots
                        .into_iter()
                        .map(|snap| UdpSocketInfo {
                            local_addr: format!("*:{}", snap.local_port),
                            remote_addr: String::from("*:*"),
                        })
                        .collect(),
                );
            }
        }
        Err(_) => {
            log::error!("[NET] Stack lock poisoned (get_udp_sockets)");
        }
    }
    None
}

pub fn dns_resolve(hostname: &str) -> Result<Vec<[u8; 4]>, String> {
    match hostname {
        "localhost" => Ok(alloc::vec![[127, 0, 0, 1]]),
        "gateway" | "router" => Ok(alloc::vec![[10, 0, 2, 2]]),
        _ => Err(String::from("DNS server not configured")),
    }
}

pub fn dhcp_discover() -> Option<DhcpOfferInfo> {
    let now = tcb_table().get_current_tick();
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            let _ = client.drive(now, 1000);
            if let Some(offer) = client.offered_lease() {
                return Some(DhcpOfferInfo {
                    server_ip: *offer.server_ip.as_bytes(),
                    offered_ip: *offer.ip_address.as_bytes(),
                });
            }
        }
    }
    None
}

pub fn dhcp_request(server_ip: [u8; 4], offered_ip: [u8; 4]) -> bool {
    use crate::net::services::dhcp::{
        DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_MAX_MESSAGE_SIZE, DHCP_SERVER_PORT,
        DhcpHeader, DhcpMessageType, DhcpOperation, DhcpOption,
    };

    let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];
    let xid = tcb_table().get_current_tick() as u32 ^ 0xDEAD_BEEF;

    let mut header_struct = DhcpHeader {
        op: DhcpOperation::Request as u8,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: xid.to_be_bytes(),
        secs: 0u16.to_be_bytes(),
        flags: 0x8000u16.to_be_bytes(),
        ciaddr: [0; 4],
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr: [0; 16],
        sname: [0; 64],
        file: [0; 128],
    };

    if let Some(cfg) = get_network_config() {
        header_struct.chaddr[..6].copy_from_slice(&cfg.mac);
    }

    if header_struct.encode_into(&mut buf[..DhcpHeader::SIZE]).is_err() {
        return false;
    }

    let mut opts = Vec::with_capacity(64);
    opts.extend_from_slice(&DHCP_MAGIC_COOKIE);
    opts.push(DhcpOption::MessageType as u8);
    opts.push(1);
    opts.push(DhcpMessageType::Request as u8);
    opts.push(DhcpOption::RequestedIp as u8);
    opts.push(4);
    opts.extend_from_slice(&offered_ip);
    opts.push(DhcpOption::ServerIdentifier as u8);
    opts.push(4);
    opts.extend_from_slice(&server_ip);
    opts.push(DhcpOption::End as u8);

    let total_len = DhcpHeader::SIZE + opts.len();
    if total_len > buf.len() {
        return false;
    }
    buf[DhcpHeader::SIZE..DhcpHeader::SIZE + opts.len()].copy_from_slice(&opts);

    let dst = if server_ip == [0, 0, 0, 0] {
        Ipv4Address::new([255, 255, 255, 255])
    } else {
        Ipv4Address::new(server_ip)
    };
    stack::send_udp(DHCP_CLIENT_PORT, dst, DHCP_SERVER_PORT, &buf[..total_len])
}

pub fn dhcp_release() {
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            client.release();
        }
    }
}

pub fn dhcp_last_declined() -> Option<[u8; 4]> {
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            return client.last_declined_ip().map(|ip| *ip.as_bytes());
        }
    }
    None
}

pub fn dhcp_last_released() -> Option<[u8; 4]> {
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            return client.last_released_ip().map(|ip| *ip.as_bytes());
        }
    }
    None
}

fn dhcp_v4_state_name(state: dhcp::DhcpState) -> &'static str {
    match state {
        dhcp::DhcpState::Init => "Init",
        dhcp::DhcpState::Selecting => "Selecting",
        dhcp::DhcpState::Requesting => "Requesting",
        dhcp::DhcpState::Bound => "Bound",
        dhcp::DhcpState::Renewing => "Renewing",
        dhcp::DhcpState::Rebinding => "Rebinding",
    }
}

fn dhcp_v6_state_name(state: dhcp::DhcpV6State) -> &'static str {
    match state {
        dhcp::DhcpV6State::Init => "Init",
        dhcp::DhcpV6State::SolicitSent => "SolicitSent",
        dhcp::DhcpV6State::Requesting => "Requesting",
        dhcp::DhcpV6State::Bound => "Bound",
        dhcp::DhcpV6State::Renewing => "Renewing",
        dhcp::DhcpV6State::Rebinding => "Rebinding",
    }
}

fn lease_remaining_secs(total: u32, obtained_at: u64, now: u64, tick_rate: u64) -> u32 {
    let elapsed = (now.saturating_sub(obtained_at)) / tick_rate;
    total.saturating_sub(core::cmp::min(elapsed, u32::MAX as u64) as u32)
}

pub fn init_dhcp_runtime() -> Result<(), String> {
    let mac = match stack::stack().lock() {
        Ok(guard) => match guard.as_ref() {
            Some(stack_guard) => stack_guard.config().mac,
            None => return Err(String::from("Network stack is not initialized")),
        },
        Err(_) => return Err(String::from("Network stack lock poisoned")),
    };

    dhcp::init(mac);
    dhcp::init_v6(mac);

    let now = tcb_table().get_current_tick();
    if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
        if let Some(ref client) = *guard {
            client.drive(now, 1000).map_err(String::from)?;
        }
    } else {
        return Err(String::from("DHCPv4 global client lock poisoned"));
    }

    if let Ok(guard6) = dhcp::DHCPV6_CLIENT.lock() {
        if let Some(ref client6) = *guard6 {
            client6.check_timeout(now, 1000).map_err(String::from)?;
        }
    } else {
        return Err(String::from("DHCPv6 global client lock poisoned"));
    }

    Ok(())
}

pub fn dhcp_state() -> DhcpRuntimeState {
    let now = tcb_table().get_current_tick();
    let tick_rate = 1000u64;

    let mut out = DhcpRuntimeState {
        v4_state: String::from("Init"),
        v4_assigned_ip: None,
        v4_lease_remaining: None,
        v4_last_declined: None,
        v4_last_released: None,
        v6_state: String::from("Init"),
        v6_assigned_ip: None,
        v6_preferred_remaining: None,
        v6_valid_remaining: None,
    };

    match dhcp::DHCP_CLIENT.lock() {
        Ok(guard) => {
            if let Some(ref client) = *guard {
                out.v4_state = String::from(dhcp_v4_state_name(client.state()));
                if let Some(lease) = client.lease() {
                    out.v4_assigned_ip = Some(*lease.ip_address.as_bytes());
                    out.v4_lease_remaining = Some(lease_remaining_secs(
                        lease.lease_time,
                        lease.obtained_at,
                        now,
                        tick_rate,
                    ));
                }
                out.v4_last_declined = client.last_declined_ip().map(|ip| *ip.as_bytes());
                out.v4_last_released = client.last_released_ip().map(|ip| *ip.as_bytes());
            }
        }
        Err(_) => out.v4_state = String::from("Poisoned"),
    }

    match dhcp::DHCPV6_CLIENT.lock() {
        Ok(guard6) => {
            if let Some(ref client6) = *guard6 {
                out.v6_state = String::from(dhcp_v6_state_name(client6.state()));
                if let Some(lease6) = client6.lease() {
                    out.v6_assigned_ip = Some(*lease6.addr.as_bytes());
                    out.v6_preferred_remaining = Some(lease_remaining_secs(
                        lease6.preferred_lifetime,
                        lease6.obtained_at,
                        now,
                        tick_rate,
                    ));
                    out.v6_valid_remaining = Some(lease_remaining_secs(
                        lease6.valid_lifetime,
                        lease6.obtained_at,
                        now,
                        tick_rate,
                    ));
                }
            }
        }
        Err(_) => out.v6_state = String::from("Poisoned"),
    }

    out
}

pub fn dhcp_renew() -> Result<(), String> {
    let now = tcb_table().get_current_tick();
    let mut touched = false;

    match dhcp::DHCP_CLIENT.lock() {
        Ok(guard) => {
            if let Some(ref client) = *guard {
                client.force_renew_or_restart(now);
                client.drive(now, 1000).map_err(String::from)?;
                touched = true;
            }
        }
        Err(_) => return Err(String::from("DHCPv4 global client lock poisoned")),
    }

    match dhcp::DHCPV6_CLIENT.lock() {
        Ok(guard6) => {
            if let Some(ref client6) = *guard6 {
                client6.force_renew_or_restart(now).map_err(String::from)?;
                client6.check_timeout(now, 1000).map_err(String::from)?;
                touched = true;
            }
        }
        Err(_) => return Err(String::from("DHCPv6 global client lock poisoned")),
    }

    if !touched {
        return Err(String::from("DHCP runtime is not initialized"));
    }

    Ok(())
}

pub fn get_arp_cache() -> Option<Vec<ArpCacheEntry>> {
    match stack::stack().lock() {
        Ok(guard) => {
            if let Some(stack_guard) = guard.as_ref() {
                let arp_entries = stack_guard.arp_cache();
                let entries: Vec<ArpCacheEntry> = arp_entries
                    .iter()
                    .map(|(ip, mac)| ArpCacheEntry {
                        ip: *ip.as_bytes(),
                        mac: *mac.as_bytes(),
                        complete: true,
                    })
                    .collect();
                if !entries.is_empty() {
                    return Some(entries);
                }
            }
        }
        Err(_) => log::error!("[NET] Stack lock poisoned (get_arp_cache) - returning demo output"),
    }
    None
}

pub fn arp_cache_insert(ip: Ipv4Address, mac: MacAddress) -> bool {
    if let Ok(mut guard) = stack::stack().lock() {
        if let Some(stack_ref) = guard.as_mut() {
            let now = crate::time::get_uptime_ms();
            stack_ref.arp_cache_insert(ip, mac, now);
            return true;
        }
    }
    false
}

pub fn init_network_shell() {
    // no-op: runtime state is sourced from the actual network stack/DHCP clients.
}
