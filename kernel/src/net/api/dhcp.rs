// ============================================================================
// kernel/src/net/api/dhcp.rs - DHCP操作（v4/v6）
// ============================================================================
//! DHCPv4/v6クライアントの初期化、discover/request/release/renew、状態取得。

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::tcb_table;
use crate::net::runtime::stack;
use crate::net::services::dhcp;

use super::config::get_network_config;

extern crate alloc;

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

/// DHCP offer info exposed for shell/API consumers.
#[derive(Debug, Clone)]
pub struct DhcpOfferInfo {
    pub server_ip: [u8; 4],
    pub offered_ip: [u8; 4],
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
    stack::send_udp_async(DHCP_CLIENT_PORT, dst, DHCP_SERVER_PORT, &buf[..total_len], 64)
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

    let (hostname, ip, dns_servers) = match stack::stack().lock() {
        Ok(guard) => match guard.as_ref() {
            Some(stack_guard) => {
                let cfg = stack_guard.config();
                let dns = if let Some(d) = cfg.ipv4.dns { vec![d] } else { vec![] };
                (String::from("ranyos"), cfg.ipv4.address, dns)
            }
            None => (String::from("ranyos"), Ipv4Address::new([0, 0, 0, 0]), vec![]),
        },
        Err(_) => (String::from("ranyos"), Ipv4Address::new([0, 0, 0, 0]), vec![]),
    };
    crate::net::services::mdns::init(hostname, ip);

    // DNS 初期化
    crate::net::services::dns::init(1000);
    if !dns_servers.is_empty() {
        if let Ok(guard) = crate::net::services::dns::client().lock() {
            if let Some(ref client) = *guard {
                client.set_ipv4_servers(dns_servers);
            }
        }
    }

    // Spawn DHCPv4 client task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        if let Ok(guard) = dhcp::DHCP_CLIENT.lock() {
            if let Some(client) = &*guard {
                let _ = client.run().await;
            }
        }
    }));

    // Spawn DHCPv6 client task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        if let Ok(guard) = dhcp::DHCPV6_CLIENT.lock() {
            if let Some(client6) = &*guard {
                let _ = client6.run().await;
            }
        }
    }));

    // Spawn mDNS service task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        if let Ok(mut guard) = crate::net::services::mdns::service().lock() {
            if let Some(ref mut service) = *guard {
                let _ = service.run().await;
            }
        }
    }));

    // Spawn DNS client task
    crate::task::Executor::spawn_global(crate::task::Task::new(async move {
        if let Ok(guard) = crate::net::services::dns::client().lock() {
            if let Some(ref client) = *guard {
                let _ = client.run().await;
            }
        }
    }));

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
                touched = true;
            }
        }
        Err(_) => return Err(String::from("DHCPv4 global client lock poisoned")),
    }

    match dhcp::DHCPV6_CLIENT.lock() {
        Ok(guard6) => {
            if let Some(ref client6) = *guard6 {
                client6.force_renew_or_restart(now).map_err(String::from)?;
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
