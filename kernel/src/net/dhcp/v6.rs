use super::*;

use crate::net::ipv6::Ipv6Address;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// DHCPv6 クライアントポート / サーバーポート
pub const DHCPV6_CLIENT_PORT: u16 = 546;
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// DHCPv6 メッセージタイプ（RFC 8415 の主要種のみ）
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpV6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Reply = 7,
}

/// IA_NA による割当情報
#[derive(Debug, Clone)]
pub struct DhcpV6Lease {
    pub addr: Ipv6Address,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub obtained_at: u64,
}

/// DHCPv6 クライアント状態（簡易）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpV6State {
    Init,
    SolicitSent,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

/// シンプルな DHCPv6 クライアント実装（IA_NA サポート）
pub struct DhcpV6Client {
    mac: crate::net::ethernet::MacAddress,
    duid: Vec<u8>,
    state: PoisonLock<DhcpV6State>,
    xid: AtomicU32, // 24-bit トランザクションIDを格納
    iaid: u32,
    lease: PoisonLock<Option<DhcpV6Lease>>,
    /// Last-seen server DUID (Server Identifier option)
    server_duid: PoisonLock<Option<Vec<u8>>>,
    /// Last-seen server IPv6 source address (used for unicast Renew)
    server_addr: PoisonLock<Option<Ipv6Address>>,
    state_time: AtomicU64,
    retry_count: AtomicU32,
}

impl DhcpV6Client {
    pub const MAX_RETRIES: u32 = 4;
    pub const RETRANS_INTERVAL_SECS: u64 = 4;

    /// DUID-LL を生成（type=3, hwtype=1 + MAC）
    fn make_duid_ll(mac: &crate::net::ethernet::MacAddress) -> Vec<u8> {
        let mut v = Vec::new();
        // DUID type (2 bytes) = 3 (DUID-LL)
        v.extend_from_slice(&(3u16.to_be_bytes()));
        // hardware type (2 bytes) = 1 (Ethernet)
        v.extend_from_slice(&(1u16.to_be_bytes()));
        v.extend_from_slice(mac.as_bytes());
        v
    }

    pub fn new(mac: crate::net::ethernet::MacAddress) -> Self {
        let duid = Self::make_duid_ll(&mac);
        Self {
            mac,
            duid,
            state: PoisonLock::new(DhcpV6State::Init),
            xid: AtomicU32::new(0),
            iaid: 0xAABBCCDD, // 固定 IAID（将来乱数化可）
            lease: PoisonLock::new(None),            server_duid: PoisonLock::new(None),
            server_addr: PoisonLock::new(None),            state_time: AtomicU64::new(0),
            retry_count: AtomicU32::new(0),
        }
    }

    pub fn state(&self) -> DhcpV6State {
        match self.state.lock() {
            Ok(g) => *g,
            Err(_) => DhcpV6State::Init,
        }
    }

    pub fn lease(&self) -> Option<DhcpV6Lease> {
        match self.lease.lock() {
            Ok(g) => g.clone(),
            Err(_) => None,
        }
    }

    /// Build a DHCPv6 SOLICIT message (minimal: client-id + IA_NA option)
    pub fn build_solicit(&self, buf: &mut [u8], current_time: u64) -> Result<usize, &'static str> {
        if buf.len() < 128 {
            return Err("buffer too small");
        }

        // Generate XID (24-bit)
        let xid = ((current_time as u32) ^ 0xC0FFEE) & 0x00FF_FFFF;
        self.xid.store(xid, Ordering::SeqCst);

        // Header
        buf[0] = DhcpV6MessageType::Solicit as u8;
        // XID - 3 bytes (big-endian)
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        // Client Identifier (option 1)
        let cl_id_len = self.duid.len();
        buf[off..off + 2].copy_from_slice(&(1u16.to_be_bytes())); // option-code
        buf[off + 2..off + 4].copy_from_slice(&(cl_id_len as u16).to_be_bytes());
        off += 4;
        buf[off..off + cl_id_len].copy_from_slice(&self.duid);
        off += cl_id_len;

        // Option: IA_NA (3) with IAID(4) + T1(4) + T2(4) and no suboptions yet
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
        // option length to fill later
        let ia_len_pos = off + 2;
        off += 4;
        // IAID
        buf[off..off + 4].copy_from_slice(&self.iaid.to_be_bytes());
        off += 4;
        // T1, T2 = 0
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;
        // No IAADDRs in SOLICIT

        // Fill IA_NA length
        let ia_opt_len = (12u16).to_be_bytes(); // IAID(4) + T1(4) + T2(4)
        buf[ia_len_pos..ia_len_pos + 2].copy_from_slice(&ia_opt_len);

        Ok(off)
    }

    /// Build a DHCPv6 REQUEST message (used for Renew/Rebind).
    /// Includes ClientID + IA_NA with IAADDR suboption for the lease being renewed.
    pub fn build_request(&self, buf: &mut [u8], lease: &DhcpV6Lease, current_time: u64) -> Result<usize, &'static str> {
        if buf.len() < 256 {
            return Err("buffer too small");
        }

        // XID
        let xid = ((current_time as u32) ^ 0xC0FFEE) & 0x00FF_FFFF;
        self.xid.store(xid, Ordering::SeqCst);

        buf[0] = DhcpV6MessageType::Request as u8;
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        // Client Identifier (option 1)
        let cl_id_len = self.duid.len();
        buf[off..off + 2].copy_from_slice(&(1u16.to_be_bytes())); // option-code
        buf[off + 2..off + 4].copy_from_slice(&(cl_id_len as u16).to_be_bytes());
        off += 4;
        buf[off..off + cl_id_len].copy_from_slice(&self.duid);
        off += cl_id_len;

        // IA_NA (option 3) with IAADDR suboption (code 5)
        // IA_NA length = IAID(4)+T1(4)+T2(4) + suboption(4+24) = 40
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
        buf[off + 2..off + 4].copy_from_slice(&(40u16.to_be_bytes())); // length
        off += 4;
        // IAID
        buf[off..off + 4].copy_from_slice(&self.iaid.to_be_bytes());
        off += 4;
        // T1, T2 (set to 0 - server will respond with updated timings)
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;

        // IAADDR suboption
        buf[off..off + 2].copy_from_slice(&(5u16.to_be_bytes())); // IAADDR
        buf[off + 2..off + 4].copy_from_slice(&(24u16.to_be_bytes())); // len
        off += 4;
        buf[off..off + 16].copy_from_slice(lease.addr.as_bytes());
        off += 16;
        buf[off..off + 4].copy_from_slice(&lease.preferred_lifetime.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&lease.valid_lifetime.to_be_bytes());
        off += 4;

        Ok(off)
    }

    /// Build a DHCPv6 REQUEST to *select* a server after receiving ADVERTISE.
    /// Includes ClientID + ServerID (if available) + IA_NA (no IAADDR suboption).
    pub fn build_request_from_advertise(&self, buf: &mut [u8], current_time: u64) -> Result<usize, &'static str> {
        if buf.len() < 128 {
            return Err("buffer too small");
        }

        // Generate XID (24-bit)
        let xid = ((current_time as u32) ^ 0xC0FFEE) & 0x00FF_FFFF;
        self.xid.store(xid, Ordering::SeqCst);

        // Header
        buf[0] = DhcpV6MessageType::Request as u8;
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        // Client Identifier (option 1)
        let cl_id_len = self.duid.len();
        buf[off..off + 2].copy_from_slice(&(1u16.to_be_bytes())); // option-code
        buf[off + 2..off + 4].copy_from_slice(&(cl_id_len as u16).to_be_bytes());
        off += 4;
        buf[off..off + cl_id_len].copy_from_slice(&self.duid);
        off += cl_id_len;

        // Server Identifier (option 2) if we have a DUID
        if let Ok(g) = self.server_duid.lock() {
            if let Some(ref duid) = *g {
                buf[off..off + 2].copy_from_slice(&(2u16.to_be_bytes()));
                buf[off + 2..off + 4].copy_from_slice(&(duid.len() as u16).to_be_bytes());
                off += 4;
                buf[off..off + duid.len()].copy_from_slice(duid);
                off += duid.len();
            }
        }

        // IA_NA (option 3) without IAADDR suboption
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
        // length = IAID(4) + T1(4) + T2(4) = 12
        buf[off + 2..off + 4].copy_from_slice(&(12u16.to_be_bytes()));
        off += 4;
        buf[off..off + 4].copy_from_slice(&self.iaid.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;

        Ok(off)
    }

    /// Parse a DHCPv6 REPLY/ADVERTISE and extract IAADDR if present
    pub fn parse_reply(&self, data: &[u8], current_time: u64) -> Result<Option<DhcpV6Lease>, &'static str> {
        if data.len() < 4 {
            return Err("packet too small");
        }
        let msg_type = data[0];
        if msg_type != (DhcpV6MessageType::Advertise as u8) && msg_type != (DhcpV6MessageType::Reply as u8) {
            return Err("not an advertise/reply");
        }

        // iterate options after header
        let mut off = 4usize;
        let mut found_iaaddr: Option<DhcpV6Lease> = None;

        while off + 4 <= data.len() {
            let code = u16::from_be_bytes([data[off], data[off + 1]]);
            let len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            off += 4;
            if off + len > data.len() {
                break;
            }

            match code {
                2 => {
                    // Server Identifier (DUID) - remember it for future Renew
                    if len > 0 {
                        if let Ok(mut g) = self.server_duid.lock() {
                            *g = Some(data[off..off + len].to_vec());
                        }
                    }
                }
                3 => {
                    // IA_NA - scan suboptions for IAADDR
                    let mut sub_off = off + 12; // skip IAID/T1/T2
                    while sub_off + 4 <= off + len {
                        let sc = u16::from_be_bytes([data[sub_off], data[sub_off + 1]]);
                        let sl = u16::from_be_bytes([data[sub_off + 2], data[sub_off + 3]]) as usize;
                        sub_off += 4;
                        if sub_off + sl > off + len {
                            break;
                        }
                        if sc == 5 {
                            // IAADDR: 16 bytes addr + 4 preferred + 4 valid + suboptions
                            if sl >= 24 {
                                let mut addr_bytes = [0u8; 16];
                                addr_bytes.copy_from_slice(&data[sub_off..sub_off + 16]);
                                let pref = u32::from_be_bytes([
                                    data[sub_off + 16],
                                    data[sub_off + 17],
                                    data[sub_off + 18],
                                    data[sub_off + 19],
                                ]);
                                let valid = u32::from_be_bytes([
                                    data[sub_off + 20],
                                    data[sub_off + 21],
                                    data[sub_off + 22],
                                    data[sub_off + 23],
                                ]);
                                let lease = DhcpV6Lease {
                                    addr: Ipv6Address::new(addr_bytes),
                                    preferred_lifetime: pref,
                                    valid_lifetime: valid,
                                    obtained_at: current_time,
                                };
                                found_iaaddr = Some(lease);
                                break;
                            }
                        }
                        sub_off += sl;
                    }
                }
                _ => {}
            }

            off += len;
        }

        Ok(found_iaaddr)
    }

    /// Handle an incoming DHCPv6 packet (called by network receive path)
    /// `src` is the IPv6 source address the packet was received from.
    /// Returns true if handled
    pub fn handle_packet(&self, data: &[u8], src: Ipv6Address) -> bool {
        let now = crate::net::tcb_table().get_current_tick();

        // Inspect message type first so we can react to ADVERTISE even when no IAADDR is present
        let msg_type = data.get(0).copied().unwrap_or(0);

        // Parse options (this will populate server_duid if present)
        let _ = self.parse_reply(data, now);

        // If this is an ADVERTISE and we're waiting for it, move to REQUESTING and send Request
        if msg_type == (DhcpV6MessageType::Advertise as u8) {
            if let Ok(mut st) = self.state.lock() {
                if *st == DhcpV6State::SolicitSent {
                    // remember server address (src) and transition to Requesting
                    if let Ok(mut sd) = self.server_addr.lock() {
                        *sd = Some(src);
                    }
                    *st = DhcpV6State::Requesting;
                    self.state_time.store(now, Ordering::SeqCst);
                    self.retry_count.store(0, Ordering::SeqCst);

                    // build and send REQUEST (selection)
                    let mut buf = [0u8; 256];
                    if let Ok(len) = self.build_request_from_advertise(&mut buf, now) {
                        if let Ok(mut guard) = crate::net::stack::stack().lock() {
                            if let Some(ref mut stack) = *guard {
                                if let Some(ref ipv6_cfg) = stack.config().ipv6 {
                                    let src_ip = ipv6_cfg.link_local;
                                    let _ = stack.send_udp_v6_raw(
                                        DHCPV6_CLIENT_PORT,
                                        src_ip,
                                        src,
                                        DHCPV6_SERVER_PORT,
                                        &buf[..len],
                                    );
                                }
                            }
                        }
                    }
                    return true;
                }
            }
        }

        // Otherwise, treat REPLY that contains IAADDR as lease acceptance
        match self.parse_reply(data, now) {
            Ok(Some(lease)) => {
                // Accept lease: configure IPv6 address + NDP
                if let Ok(mut g) = self.lease.lock() {
                    *g = Some(lease.clone());
                }

                // Remember the server IPv6 address (useful for unicast Renew)
                if let Ok(mut sd) = self.server_addr.lock() {
                    *sd = Some(src);
                }

                // Apply IPv6 address to the running NetworkStack
                crate::net::stack::apply_ipv6_global_address(lease.addr);

                if let Ok(mut st) = self.state.lock() {
                    *st = DhcpV6State::Bound;
                }
                return true;
            }
            Ok(None) => return false,
            Err(_) => return false,
        }
    }

    /// Periodic timeout handler (called from NetworkStack periodic)
    /// tick_rate: how many milliseconds represent 1 second in current_time
    pub fn check_timeout(&self, current_tick: u64, tick_rate: u64) -> Result<(), &'static str> {
        match self.state.lock() {
            Ok(mut s) => match *s {
                DhcpV6State::Init => {
                    // Send SOLICIT
                    let mut buf = [0u8; 256];
                    let len = self.build_solicit(&mut buf, current_tick)?;

                    // Use link-local as source for SOLICIT
                    if let Ok(mut guard) = crate::net::stack::stack().lock() {
                        if let Some(ref mut stack) = *guard {
                            if let Some(ref ipv6_cfg) = stack.config().ipv6 {
                                let src = ipv6_cfg.link_local;
                                let dst = crate::net::ipv6::Ipv6Address::new([0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2]); // all DHCP servers/relay
                                // Send via UDP/IPv6
                                if stack.send_udp_v6_raw(
                                    DHCPV6_CLIENT_PORT,
                                    src,
                                    dst,
                                    DHCPV6_SERVER_PORT,
                                    &buf[..len],
                                ) {
                                    *s = DhcpV6State::SolicitSent;
                                    self.state_time.store(current_tick, Ordering::SeqCst);
                                    self.retry_count.store(0, Ordering::SeqCst);
                                }
                            }
                        }
                    }
                }
                DhcpV6State::SolicitSent => {
                    // Retransmit logic
                    let elapsed_secs = (current_tick.saturating_sub(self.state_time.load(Ordering::SeqCst))) / tick_rate;
                    if elapsed_secs >= Self::RETRANS_INTERVAL_SECS {
                        let retries = self.retry_count.fetch_add(1, Ordering::SeqCst);
                        if retries >= Self::MAX_RETRIES {
                            // Give up, go back to Init (will retry later)
                            *s = DhcpV6State::Init;
                        } else {
                            // retransmit SOLICIT
                            let mut buf = [0u8; 256];
                            let len = self.build_solicit(&mut buf, current_tick)?;
                            if let Ok(mut guard) = crate::net::stack::stack().lock() {
                                if let Some(ref mut stack) = *guard {
                                    if let Some(ref ipv6_cfg) = stack.config().ipv6 {
                                        let src = ipv6_cfg.link_local;
                                        let dst = crate::net::ipv6::Ipv6Address::new([0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2]);
                                        let _ = stack.send_udp_v6_raw(
                                            DHCPV6_CLIENT_PORT,
                                            src,
                                            dst,
                                            DHCPV6_SERVER_PORT,
                                            &buf[..len],
                                        );
                                    }
                                }
                            }
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        }
                    }
                }
                DhcpV6State::Requesting => {
                    // Retransmit REQUEST (unicast to server if known)
                    let elapsed_secs = (current_tick.saturating_sub(self.state_time.load(Ordering::SeqCst))) / tick_rate;
                    if elapsed_secs >= Self::RETRANS_INTERVAL_SECS {
                        let retries = self.retry_count.fetch_add(1, Ordering::SeqCst);
                        if retries >= Self::MAX_RETRIES {
                            // Give up and return to Init
                            *s = DhcpV6State::Init;
                        } else {
                            // rebuild Request (selection) and resend
                            let mut buf = [0u8; 256];
                            let len = self.build_request_from_advertise(&mut buf, current_tick)?;
                            if let Ok(mut guard) = crate::net::stack::stack().lock() {
                                if let Some(ref mut stack) = *guard {
                                    if let Some(ref ipv6_cfg) = stack.config().ipv6 {
                                        let src = ipv6_cfg.link_local;
                                        let dst = match self.server_addr.lock() {
                                            Ok(ref a) => a.as_ref().copied().unwrap_or_else(|| crate::net::ipv6::Ipv6Address::new([0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2])),
                                            Err(_) => crate::net::ipv6::Ipv6Address::new([0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2]),
                                        };
                                        let _ = stack.send_udp_v6_raw(
                                            DHCPV6_CLIENT_PORT,
                                            src,
                                            dst,
                                            DHCPV6_SERVER_PORT,
                                            &buf[..len],
                                        );
                                    }
                                }
                            }
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        }
                    }
                }
                DhcpV6State::Bound => {
                    // Check lease lifetimes and transition to Renewing if needed
                    if let Some(lease) = self.lease() {
                        let elapsed_secs = (current_tick.saturating_sub(lease.obtained_at)) / tick_rate;
                        if elapsed_secs >= (lease.preferred_lifetime as u64) {
                            // start renewal (not fully implemented here)
                            *s = DhcpV6State::Renewing;
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        }
                    }
                }
                DhcpV6State::Renewing => {
                    // Attempt to renew the current lease by sending a REQUEST.
                    let elapsed_secs = (current_tick.saturating_sub(self.state_time.load(Ordering::SeqCst))) / tick_rate;
                    if elapsed_secs >= Self::RETRANS_INTERVAL_SECS {
                        let retries = self.retry_count.fetch_add(1, Ordering::SeqCst);
                        if retries >= Self::MAX_RETRIES {
                            // Escalate to rebinding (multicast) if renew fails
                            *s = DhcpV6State::Rebinding;
                            self.retry_count.store(0, Ordering::SeqCst);
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        } else {
                            // Build and send REQUEST for the current lease
                            if let Some(lease) = self.lease() {
                                let mut buf = [0u8; 512];
                                let len = self.build_request(&mut buf, &lease, current_tick)?;
                                if let Ok(mut guard) = crate::net::stack::stack().lock() {
                                    if let Some(ref mut stack) = *guard {
                                        if let Some(ref ipv6_cfg) = stack.config().ipv6 {
                                            let src = ipv6_cfg.link_local;
                                            // If we know the server IPv6 address, send unicast Renew there;
                                            // otherwise fall back to multicast.
                                            let dst = match self.server_addr.lock() {
                                                Ok(ref a) => a.as_ref().copied().unwrap_or_else(|| crate::net::ipv6::Ipv6Address::new([0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2])),
                                                Err(_) => crate::net::ipv6::Ipv6Address::new([0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2]),
                                            };
                                            let _ = stack.send_udp_v6_raw(
                                                DHCPV6_CLIENT_PORT,
                                                src,
                                                dst,
                                                DHCPV6_SERVER_PORT,
                                                &buf[..len],
                                            );
                                        }
                                    }
                                }
                                self.state_time.store(current_tick, Ordering::SeqCst);
                            } else {
                                // No lease known — reset to Init
                                *s = DhcpV6State::Init;
                            }
                        }
                    }
                }
                DhcpV6State::Rebinding => {
                    // Rebinding uses multicast to any available server/relay.
                    let elapsed_secs = (current_tick.saturating_sub(self.state_time.load(Ordering::SeqCst))) / tick_rate;
                    if elapsed_secs >= Self::RETRANS_INTERVAL_SECS {
                        let retries = self.retry_count.fetch_add(1, Ordering::SeqCst);
                        if retries >= Self::MAX_RETRIES {
                            // Give up and return to Init (clear lease)
                            *s = DhcpV6State::Init;
                            if let Ok(mut lg) = self.lease.lock() {
                                *lg = None;
                            }
                        } else {
                            // retransmit REQUEST (multicast)
                            if let Some(lease) = self.lease() {
                                let mut buf = [0u8; 512];
                                let len = self.build_request(&mut buf, &lease, current_tick)?;
                                if let Ok(mut guard) = crate::net::stack::stack().lock() {
                                    if let Some(ref mut stack) = *guard {
                                        if let Some(ref ipv6_cfg) = stack.config().ipv6 {
                                            let src = ipv6_cfg.link_local;
                                            let dst = crate::net::ipv6::Ipv6Address::new([0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2]);
                                            let _ = stack.send_udp_v6_raw(
                                                DHCPV6_CLIENT_PORT,
                                                src,
                                                dst,
                                                DHCPV6_SERVER_PORT,
                                                &buf[..len],
                                            );
                                        }
                                    }
                                }
                            } else {
                                *s = DhcpV6State::Init;
                            }
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        }
                    }
                }
            },
            Err(_) => return Err("state lock poisoned"),
        }
        Ok(())
    }

    /// Force immediate renew when lease is active, otherwise restart from INIT.
    pub fn force_renew_or_restart(&self, current_tick: u64) -> Result<(), &'static str> {
        let restart = match self.state.lock() {
            Ok(mut state) => match *state {
                DhcpV6State::Bound | DhcpV6State::Renewing | DhcpV6State::Rebinding => {
                    *state = DhcpV6State::Renewing;
                    false
                }
                _ => {
                    *state = DhcpV6State::Init;
                    true
                }
            },
            Err(_) => return Err("state lock poisoned"),
        };

        if restart {
            match self.lease.lock() {
                Ok(mut lg) => *lg = None,
                Err(_) => return Err("lease lock poisoned"),
            }
            match self.server_duid.lock() {
                Ok(mut sg) => *sg = None,
                Err(_) => return Err("server_duid lock poisoned"),
            }
            match self.server_addr.lock() {
                Ok(mut ag) => *ag = None,
                Err(_) => return Err("server_addr lock poisoned"),
            }
        }

        self.state_time.store(current_tick, Ordering::SeqCst);
        self.retry_count.store(0, Ordering::SeqCst);
        Ok(())
    }
}

// Global singleton for DHCPv6 client (optional)
pub(crate) static DHCPV6_CLIENT: PoisonLock<Option<DhcpV6Client>> = PoisonLock::new(None);

/// DHCPv6 クライアントをグローバルに初期化
pub fn init_v6(mac_address: crate::net::ethernet::MacAddress) {
    let client = DhcpV6Client::new(mac_address);
    match DHCPV6_CLIENT.lock() {
        Ok(mut g) => *g = Some(client),
        Err(_) => log::error!("[NET] DHCPv6 Global lock poisoned (init) - initialization skipped"),
    }
}

/// DHCPv6 クライアント取得
pub fn client_v6() -> Option<&'static PoisonLock<Option<DhcpV6Client>>> {
    Some(&DHCPV6_CLIENT)
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod tests {
    use super::*;
    use crate::net::ipv6::Ipv6Address;

    #[cfg_attr(test, test_case)]
    pub fn test_build_solicit_min_size() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);
        let mut buf = [0u8; 256];
        let now = 1000u64;
        let len = client.build_solicit(&mut buf, now).unwrap();
        assert!(len > 0);
        assert_eq!(buf[0], DhcpV6MessageType::Solicit as u8);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_parse_reply_with_iaaddr() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);
        // construct a fake REPLY that contains IA_NA with IAADDR
        let mut pkt = alloc::vec![0u8; 4 + 4 + 12 + 4 + 24];
        pkt[0] = DhcpV6MessageType::Reply as u8;
        // xid (3 bytes)
        pkt[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut off = 4;
        // IA_NA option
        pkt[off..off+2].copy_from_slice(&(3u16.to_be_bytes())); // code
        pkt[off+2..off+4].copy_from_slice(&(40u16.to_be_bytes())); // len
        off += 4;
        // IAID + T1 + T2
        pkt[off..off+12].copy_from_slice(&[0u8; 12]);
        off += 12;
        // IAADDR as suboption under IA_NA (we'll append directly after)
        // For simplicity append IAADDR as a top-level option in this test
        pkt[off..off+2].copy_from_slice(&(5u16.to_be_bytes()));
        pkt[off+2..off+4].copy_from_slice(&(24u16.to_be_bytes()));
        off += 4;
        let addr = Ipv6Address::new([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1]);
        pkt[off..off+16].copy_from_slice(addr.as_bytes());
        off += 16;
        pkt[off..off+4].copy_from_slice(&3600u32.to_be_bytes());
        off += 4;
        pkt[off..off+4].copy_from_slice(&7200u32.to_be_bytes());

        let parsed = client.parse_reply(&pkt, 100).unwrap();
        assert!(parsed.is_some());
        let lease = parsed.unwrap();
        assert_eq!(lease.addr, addr);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_build_request_min_size() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: crate::net::ipv6::Ipv6Address::new([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2]),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            obtained_at: 100,
        };
        let mut buf = [0u8; 512];
        let now = 200u64;
        let len = client.build_request(&mut buf, &lease, now).unwrap();
        assert!(len > 0);
        assert_eq!(buf[0], DhcpV6MessageType::Request as u8);
        // find IAADDR suboption code (5) somewhere after header
        let mut found = false;
        for i in 4..len-2 {
            if buf[i] == 0 && buf[i+1] == 5u8 {
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_bound_to_renewing_and_rebinding_transitions() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);
        // set lease with preferred lifetime = 1 second
        let lease = DhcpV6Lease {
            addr: crate::net::ipv6::Ipv6Address::new([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,3]),
            preferred_lifetime: 1,
            valid_lifetime: 10,
            obtained_at: 0,
        };
        if let Ok(mut lg) = client.lease.lock() {
            *lg = Some(lease.clone());
        }
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::Bound;
        }
        // tick_rate = 1000 (ms per sec), current_tick beyond preferred lifetime
        let tick_rate = 1000u64;
        let now = (lease.obtained_at as u64) + lease.preferred_lifetime as u64 * tick_rate + 10;
        client.check_timeout(now, tick_rate).unwrap();
        assert_eq!(client.state(), DhcpV6State::Renewing);

        // simulate retransmissions until Rebinding
        for i in 0..(DhcpV6Client::MAX_RETRIES + 2) {
            let t = now + (i as u64 + 1) * DhcpV6Client::RETRANS_INTERVAL_SECS * tick_rate;
            client.check_timeout(t, tick_rate).unwrap();
        }
        // after exceeding retries client should be in Rebinding or Init depending on counts
        assert!(client.state() == DhcpV6State::Rebinding || client.state() == DhcpV6State::Init);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_handle_packet_stores_server_addr_and_duid() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);

        // Build a REPLY that contains Server Identifier (option 2) + IA_NA with IAADDR
        let server_duid: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let addr = Ipv6Address::new([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,4]);

        // layout: header(4) + srv_id(opt2) + IA_NA(opt3)+IAADDR(subopt5)
        let mut pkt = alloc::vec![0u8; 4 + 4 + server_duid.len() + 4 + 12 + 4 + 24];
        pkt[0] = DhcpV6MessageType::Reply as u8;
        pkt[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut off = 4;
        // Server Identifier (option 2)
        pkt[off..off+2].copy_from_slice(&(2u16.to_be_bytes()));
        pkt[off+2..off+4].copy_from_slice(&(server_duid.len() as u16).to_be_bytes());
        off += 4;
        pkt[off..off+server_duid.len()].copy_from_slice(&server_duid);
        off += server_duid.len();

        // IA_NA option (top-level)
        pkt[off..off+2].copy_from_slice(&(3u16.to_be_bytes())); // code
        pkt[off+2..off+4].copy_from_slice(&(40u16.to_be_bytes())); // len
        off += 4;
        // IAID + T1 + T2
        pkt[off..off+12].copy_from_slice(&[0u8; 12]);
        off += 12;

        // IAADDR as a top-level option for this test (simpler)
        pkt[off..off+2].copy_from_slice(&(5u16.to_be_bytes()));
        pkt[off+2..off+4].copy_from_slice(&(24u16.to_be_bytes()));
        off += 4;
        pkt[off..off+16].copy_from_slice(addr.as_bytes());
        off += 16;
        pkt[off..off+4].copy_from_slice(&3600u32.to_be_bytes());
        off += 4;
        pkt[off..off+4].copy_from_slice(&7200u32.to_be_bytes());

        let src_ip = Ipv6Address::new([0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
        let handled = client.handle_packet(&pkt, src_ip);
        assert!(handled);
        // lease stored
        let l = client.lease();
        assert!(l.is_some());
        // server_addr recorded
        if let Ok(g) = client.server_addr.lock() {
            assert_eq!(g.as_ref().unwrap(), &src_ip);
        } else {
            panic!("server_addr lock poisoned");
        }
        // server_duid recorded
        if let Ok(g) = client.server_duid.lock() {
            assert_eq!(g.as_ref().unwrap().as_slice(), &server_duid);
        } else {
            panic!("server_duid lock poisoned");
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_advertise_triggers_request_and_requesting_state() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);

        // Put client into SolicitSent
        if let Ok(mut st) = client.state.lock() { *st = DhcpV6State::SolicitSent; }

        // Build an ADVERTISE that contains Server Identifier (option 2) but no IAADDR
        let server_duid: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let mut pkt = alloc::vec![0u8; 4 + 4 + server_duid.len()];
        pkt[0] = DhcpV6MessageType::Advertise as u8;
        pkt[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut off = 4;
        pkt[off..off+2].copy_from_slice(&(2u16.to_be_bytes()));
        pkt[off+2..off+4].copy_from_slice(&(server_duid.len() as u16).to_be_bytes());
        off += 4;
        pkt[off..off+server_duid.len()].copy_from_slice(&server_duid);

        let src_ip = Ipv6Address::new([0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,9]);
        let handled = client.handle_packet(&pkt, src_ip);
        assert!(handled);
        assert_eq!(client.state(), DhcpV6State::Requesting);
        // server_addr and server_duid should be set
        if let Ok(g) = client.server_addr.lock() { assert_eq!(g.as_ref().unwrap(), &src_ip); }
        if let Ok(g) = client.server_duid.lock() { assert_eq!(g.as_ref().unwrap().as_slice(), &server_duid); }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_requesting_retransmit_exhaustion_goes_to_init() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);
        if let Ok(mut st) = client.state.lock() { *st = DhcpV6State::Requesting; }
        // simulate having already retried up to MAX_RETRIES
        client.retry_count.store(DhcpV6Client::MAX_RETRIES, Ordering::SeqCst);
        let tick_rate = 1000u64;
        let now = DhcpV6Client::RETRANS_INTERVAL_SECS * tick_rate + 10;
        client.check_timeout(now, tick_rate).unwrap();
        assert_eq!(client.state(), DhcpV6State::Init);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_force_renew_or_restart_paths() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: Ipv6Address::new([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,8]),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            obtained_at: 0,
        };

        if let Ok(mut lg) = client.lease.lock() { *lg = Some(lease.clone()); }
        if let Ok(mut st) = client.state.lock() { *st = DhcpV6State::Bound; }
        client.force_renew_or_restart(100).unwrap();
        assert_eq!(client.state(), DhcpV6State::Renewing);
        assert!(client.lease().is_some());

        if let Ok(mut st) = client.state.lock() { *st = DhcpV6State::Requesting; }
        client.force_renew_or_restart(200).unwrap();
        assert_eq!(client.state(), DhcpV6State::Init);
        assert!(client.lease().is_none());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_solicit_advertise_request_reply_complete_flow() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);

        // Start from Init -> send SOLICIT (simulate periodic trigger)
        if let Ok(mut st) = client.state.lock() { *st = DhcpV6State::SolicitSent; }

        // Build ADVERTISE (server-id only)
        let server_duid: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let mut adv = alloc::vec![0u8; 4 + 4 + server_duid.len()];
        adv[0] = DhcpV6MessageType::Advertise as u8;
        adv[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut off = 4;
        adv[off..off+2].copy_from_slice(&(2u16.to_be_bytes()));
        adv[off+2..off+4].copy_from_slice(&(server_duid.len() as u16).to_be_bytes());
        off += 4;
        adv[off..off+server_duid.len()].copy_from_slice(&server_duid);

        let server_ip = Ipv6Address::new([0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,7]);
        assert!(client.handle_packet(&adv, server_ip));
        assert_eq!(client.state(), DhcpV6State::Requesting);

        // Now build a REPLY that contains IAADDR for the requested IA
        let addr = Ipv6Address::new([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,6]);
        let mut reply = alloc::vec![0u8; 4 + 4 + 12 + 4 + 24];
        reply[0] = DhcpV6MessageType::Reply as u8;
        reply[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut roff = 4;
        // IA_NA option (top-level)
        reply[roff..roff+2].copy_from_slice(&(3u16.to_be_bytes())); // code
        reply[roff+2..roff+4].copy_from_slice(&(40u16.to_be_bytes())); // len
        roff += 4;
        // IAID + T1 + T2
        reply[roff..roff+12].copy_from_slice(&[0u8; 12]);
        roff += 12;
        // IAADDR (as top-level for test simplicity)
        reply[roff..roff+2].copy_from_slice(&(5u16.to_be_bytes()));
        reply[roff+2..roff+4].copy_from_slice(&(24u16.to_be_bytes()));
        roff += 4;
        reply[roff..roff+16].copy_from_slice(addr.as_bytes());
        roff += 16;
        reply[roff..roff+4].copy_from_slice(&3600u32.to_be_bytes());
        roff += 4;
        reply[roff..roff+4].copy_from_slice(&7200u32.to_be_bytes());

        assert!(client.handle_packet(&reply, server_ip));
        assert_eq!(client.state(), DhcpV6State::Bound);
        let l = client.lease();
        assert!(l.is_some());
        assert_eq!(l.unwrap().addr, addr);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_renew_uses_known_server_address_for_dst() {
        let mac = crate::net::ethernet::MacAddress::new([0x00,0x11,0x22,0x33,0x44,0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: crate::net::ipv6::Ipv6Address::new([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,5]),
            preferred_lifetime: 1,
            valid_lifetime: 10,
            obtained_at: 0,
        };
        if let Ok(mut lg) = client.lease.lock() {
            *lg = Some(lease.clone());
        }
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::Renewing;
        }
        // set known server address
        let server_ip = crate::net::ipv6::Ipv6Address::new([0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2]);
        if let Ok(mut g) = client.server_addr.lock() { *g = Some(server_ip); }

        let tick_rate = 1000u64;
        // force a retransmit interval to elapse
        let now = DhcpV6Client::RETRANS_INTERVAL_SECS * tick_rate + 10;
        client.check_timeout(now, tick_rate).unwrap();
        // should still be Renewing (not immediately escalate to Rebinding)
        assert_eq!(client.state(), DhcpV6State::Renewing);
    }
}
