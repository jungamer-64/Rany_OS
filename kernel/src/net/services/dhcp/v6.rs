use super::*;

use crate::net::l3::ipv6::Ipv6Address;
use crate::task::{self, TimeoutResult};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// DHCPv6 クライアントポート / サーバーポート
pub const DHCPV6_CLIENT_PORT: u16 = 546;
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// DHCPv6 メッセージタイプ（RFC 8415 準拠）
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpV6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    InformationRequest = 11,
}

/// IA_NA による割当情報
#[derive(Debug, Clone)]
pub struct DhcpV6Lease {
    pub addr: Ipv6Address,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub t1: u32,
    pub t2: u32,
    pub obtained_at: u64,
    /// DHCPv6 Option 23 (DNS Recursive Name Server) から取得した DNS サーバー
    pub dns_servers: Vec<Ipv6Address>,
    /// DHCPv6 Option 24 (Domain Search List) から取得したドメイン名
    pub domain_search: Vec<alloc::string::String>,
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
    runtime: crate::net::runtime::NetRuntimeHandle,
    mac: crate::net::l2::ethernet::MacAddress,
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
    /// キャッシュ済みリンクローカルIPv6アドレス（初回取得後はロックフリー）
    cached_link_local: PoisonLock<Option<Ipv6Address>>,
}

impl DhcpV6Client {
    pub const MAX_RETRIES: u32 = 4;
    pub const RETRANS_INTERVAL_SECS: u64 = 4;

    #[inline]
    fn all_dhcp_servers_multicast() -> Ipv6Address {
        // RFC 8415: All_DHCP_Relay_Agents_and_Servers = ff02::1:2
        Ipv6Address::new([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2])
    }

    /// スタック設定からリンクローカルIPv6アドレスを取得（キャッシュ付き）
    ///
    /// 初回アクセス時にキャッシュし、以降はロックフリーで高速に返す。
    /// リンクローカルアドレスはMAC由来のため起動後は不変。
    ///
    /// ## 設計根拠
    /// - `handle_packet()` / `check_timeout()` は同期関数であり、イベントハンドラの
    ///   スタックロック保持中に呼ばれるため、async版（GetLinkLocal）は使用不可
    ///   （再帰的ロック取得→デッドロック）
    /// - 短期間の読み取りロックで初回のみアクセスし、以降はキャッシュを参照する
    fn get_link_local(&self) -> Option<Ipv6Address> {
        // キャッシュ済みの場合はスタックロック不要
        if let Ok(guard) = self.cached_link_local.lock() {
            if let Some(addr) = *guard {
                return Some(addr);
            }
        }

        // 初回のみスタックロックで取得してキャッシュ
        let result = match crate::net::runtime::stack::stack_in(self.runtime).lock() {
            Ok(guard) => guard
                .as_ref()
                .and_then(|s| s.config().ipv6.map(|c| c.link_local)),
            Err(_) => {
                log::error!("[NET] DHCPv6: Global Stack poisoned - cannot get link-local");
                None
            }
        };

        if let Some(addr) = result {
            if let Ok(mut guard) = self.cached_link_local.lock() {
                *guard = Some(addr);
            }
        }

        result
    }

    /// 非同期イベントキュー経由でUDPv6パケットを送信（ロック競合回避）
    fn enqueue_v6_send(
        &self,
        src: Ipv6Address,
        dst: Ipv6Address,
        payload: kernel_api::resource::net::PacketPayload,
    ) -> bool {
        crate::net::runtime::stack::enqueue_udp_v6_send_scoped_in(
            self.runtime,
            crate::net::types::InterfaceScope::Any,
            DHCPV6_CLIENT_PORT,
            src,
            dst,
            DHCPV6_SERVER_PORT,
            payload,
            64,
        )
    }

    fn enqueue_v6_send_bytes(&self, src: Ipv6Address, dst: Ipv6Address, payload: &[u8]) -> bool {
        crate::net::payload::payload_from_bytes(payload)
            .is_some_and(|payload| self.enqueue_v6_send(src, dst, payload))
    }

    /// DUID-LL を生成（type=3, hwtype=1 + MAC）
    fn make_duid_ll(mac: &crate::net::l2::ethernet::MacAddress) -> Vec<u8> {
        let mut v = Vec::new();
        // DUID type (2 bytes) = 3 (DUID-LL)
        v.extend_from_slice(&(3u16.to_be_bytes()));
        // hardware type (2 bytes) = 1 (Ethernet)
        v.extend_from_slice(&(1u16.to_be_bytes()));
        v.extend_from_slice(mac.as_bytes());
        v
    }

    pub fn new(mac: crate::net::l2::ethernet::MacAddress) -> Self {
        Self::new_in(crate::net::runtime::default_runtime(), mac)
    }

    pub fn new_in(
        runtime: crate::net::runtime::NetRuntimeHandle,
        mac: crate::net::l2::ethernet::MacAddress,
    ) -> Self {
        let duid = Self::make_duid_ll(&mac);
        // MAC アドレスベースの IAID（一意だが予測困難性は不要）
        let mac_bytes = mac.as_bytes();
        let iaid = u32::from_be_bytes([mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]]);
        Self {
            runtime,
            mac,
            duid,
            state: PoisonLock::new(DhcpV6State::Init),
            xid: AtomicU32::new(0),
            iaid,
            lease: PoisonLock::new(None),
            server_duid: PoisonLock::new(None),
            server_addr: PoisonLock::new(None),
            state_time: AtomicU64::new(0),
            retry_count: AtomicU32::new(0),
            cached_link_local: PoisonLock::new(None),
        }
    }

    /// DHCPv6 クライアントのメインループ（非同期）
    pub async fn run(&self) -> Result<(), &'static str> {
        let socket =
            crate::net::runtime::stack::bind_udp_endpoint_in(self.runtime, DHCPV6_CLIENT_PORT)
                .await
                .ok_or("Failed to bind DHCPv6 socket")?;

        log::info!("[NET] DHCPv6 client task started");

        loop {
            let now = crate::task::current_tick();

            // タイムアウトチェックと必要に応じた SOLICIT/REQUEST 送信
            self.check_timeout(now, 1000)?;

            // 応答待機
            match task::with_timeout(socket.recv(), 1000).await {
                TimeoutResult::Completed(Some((_if_id, src, _ttl, packet))) => {
                    // Get the actual source IPv6 address from UdpAddr (RFC 8415 compliant)
                    let src_v6 = match src {
                        crate::net::l4::udp::UdpAddr::V6 { ip, .. } => ip,
                        crate::net::l4::udp::UdpAddr::V4 { .. } => {
                            // Fallback to loopback if somehow received on IPv4 (should not happen for DHCPv6)
                            Ipv6Address::LOOPBACK
                        }
                    };

                    let handled = match &packet {
                        kernel_api::resource::net::PacketPayload::Single(packet) => {
                            self.handle_packet(packet.data(), src_v6)
                        }
                        kernel_api::resource::net::PacketPayload::Chain(_) => {
                            let data = crate::net::payload::PacketPayloadView::new(&packet)
                                .read_vec(0, packet.total_len());
                            self.handle_packet(&data, src_v6)
                        }
                    };
                    if handled {
                        log::info!("[NET] DHCPv6 packet handled from {}", src_v6);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn state(&self) -> DhcpV6State {
        match self.state.lock() {
            Ok(g) => *g,
            Err(_) => DhcpV6State::Init,
        }
    }

    /// 暗号学的安全な24bitトランザクションIDを生成し保存する
    fn generate_secure_xid(&self) {
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        let xid = u32::from_be_bytes([0, random_bytes[0], random_bytes[1], random_bytes[2]]);
        self.xid.store(xid, Ordering::SeqCst);
    }

    pub fn lease(&self) -> Option<DhcpV6Lease> {
        match self.lease.lock() {
            Ok(g) => g.clone(),
            Err(_) => None,
        }
    }

    /// Build a DHCPv6 SOLICIT message (minimal: client-id + IA_NA option)
    pub fn build_solicit(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.len() < 128 {
            return Err("buffer too small");
        }

        // Use current XID (should be generated once by the caller for the transaction)
        let xid = self.xid.load(Ordering::SeqCst);

        // Header
        buf[0] = DhcpV6MessageType::Solicit as u8;
        // XID - 3 bytes (big-endian)
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        // Helper to safely append options
        let append_opt = |buf: &mut [u8],
                          offset: &mut usize,
                          code: u16,
                          data: &[u8]|
         -> Result<(), &'static str> {
            if *offset + 4 + data.len() > buf.len() {
                return Err("Buffer overflow during option writing");
            }
            buf[*offset..*offset + 2].copy_from_slice(&code.to_be_bytes());
            buf[*offset + 2..*offset + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
            buf[*offset + 4..*offset + 4 + data.len()].copy_from_slice(data);
            *offset += 4 + data.len();
            Ok(())
        };

        // Client Identifier (option 1)
        append_opt(buf, &mut off, 1, &self.duid)?;

        // Option: IA_NA (3) with IAID(4) + T1(4) + T2(4) and no suboptions yet
        if off + 16 > buf.len() {
            return Err("Buffer overflow during IA_NA writing");
        }
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
        buf[off + 2..off + 4].copy_from_slice(&(12u16.to_be_bytes())); // length
        off += 4;
        // IAID
        buf[off..off + 4].copy_from_slice(&self.iaid.to_be_bytes());
        off += 4;
        // T1, T2 = 0
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;

        Ok(off)
    }

    /// Build a DHCPv6 REQUEST message (used for Renew/Rebind).
    /// Includes ClientID + IA_NA with IAADDR suboption for the lease being renewed.
    pub fn build_request(
        &self,
        buf: &mut [u8],
        lease: &DhcpV6Lease,
    ) -> Result<usize, &'static str> {
        if buf.len() < 256 {
            return Err("buffer too small");
        }

        // Use current XID
        let xid = self.xid.load(Ordering::SeqCst);

        buf[0] = DhcpV6MessageType::Request as u8;
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        // Helper to safely append options
        let append_opt = |buf: &mut [u8],
                          offset: &mut usize,
                          code: u16,
                          data: &[u8]|
         -> Result<(), &'static str> {
            if *offset + 4 + data.len() > buf.len() {
                return Err("Buffer overflow during option writing");
            }
            buf[*offset..*offset + 2].copy_from_slice(&code.to_be_bytes());
            buf[*offset + 2..*offset + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
            buf[*offset + 4..*offset + 4 + data.len()].copy_from_slice(data);
            *offset += 4 + data.len();
            Ok(())
        };

        // Client Identifier (option 1)
        append_opt(buf, &mut off, 1, &self.duid)?;

        // IA_NA (option 3) with IAADDR suboption (code 5)
        // IA_NA length = IAID(4)+T1(4)+T2(4) + suboption(4+24) = 40
        if off + 44 > buf.len() {
            return Err("Buffer overflow during IA_NA writing");
        }
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
        buf[off + 2..off + 4].copy_from_slice(&(40u16.to_be_bytes())); // length
        off += 4;
        // IAID
        buf[off..off + 4].copy_from_slice(&self.iaid.to_be_bytes());
        off += 4;
        // T1, T2
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
    pub fn build_request_from_advertise(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.len() < 128 {
            return Err("buffer too small");
        }

        // Use current XID
        let xid = self.xid.load(Ordering::SeqCst);

        // Header
        buf[0] = DhcpV6MessageType::Request as u8;
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        // Helper to safely append options
        let append_opt = |buf: &mut [u8],
                          offset: &mut usize,
                          code: u16,
                          data: &[u8]|
         -> Result<(), &'static str> {
            if *offset + 4 + data.len() > buf.len() {
                return Err("Buffer overflow during option writing");
            }
            buf[*offset..*offset + 2].copy_from_slice(&code.to_be_bytes());
            buf[*offset + 2..*offset + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
            buf[*offset + 4..*offset + 4 + data.len()].copy_from_slice(data);
            *offset += 4 + data.len();
            Ok(())
        };

        // Client Identifier (option 1)
        append_opt(buf, &mut off, 1, &self.duid)?;

        // Server Identifier (option 2) if we have a DUID
        if let Ok(g) = self.server_duid.lock() {
            if let Some(ref duid) = *g {
                append_opt(buf, &mut off, 2, duid)?;
            }
        }

        // IA_NA (option 3) without IAADDR suboption
        if off + 16 > buf.len() {
            return Err("Buffer overflow during IA_NA writing");
        }
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
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

    /// Build a DHCPv6 RENEW message (RFC 8415 Section 18.2.3)
    /// Sent to the server that originally assigned the lease (unicast).
    /// Includes ClientID + ServerID + IA_NA with IAADDR suboption.
    pub fn build_renew(&self, buf: &mut [u8], lease: &DhcpV6Lease) -> Result<usize, &'static str> {
        if buf.len() < 256 {
            return Err("buffer too small");
        }

        let xid = self.xid.load(Ordering::SeqCst);

        buf[0] = DhcpV6MessageType::Renew as u8;
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        let append_opt = |buf: &mut [u8],
                          offset: &mut usize,
                          code: u16,
                          data: &[u8]|
         -> Result<(), &'static str> {
            if *offset + 4 + data.len() > buf.len() {
                return Err("Buffer overflow during option writing");
            }
            buf[*offset..*offset + 2].copy_from_slice(&code.to_be_bytes());
            buf[*offset + 2..*offset + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
            buf[*offset + 4..*offset + 4 + data.len()].copy_from_slice(data);
            *offset += 4 + data.len();
            Ok(())
        };

        // Client Identifier (option 1)
        append_opt(buf, &mut off, 1, &self.duid)?;

        // Server Identifier (option 2) — RFC 8415 requires this for Renew
        if let Ok(g) = self.server_duid.lock() {
            if let Some(ref duid) = *g {
                append_opt(buf, &mut off, 2, duid)?;
            }
        }

        // IA_NA (option 3) with IAADDR suboption
        if off + 44 > buf.len() {
            return Err("Buffer overflow during IA_NA writing");
        }
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
        buf[off + 2..off + 4].copy_from_slice(&(40u16.to_be_bytes())); // length
        off += 4;
        buf[off..off + 4].copy_from_slice(&self.iaid.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // T1
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // T2
        off += 4;
        // IAADDR suboption
        buf[off..off + 2].copy_from_slice(&(5u16.to_be_bytes()));
        buf[off + 2..off + 4].copy_from_slice(&(24u16.to_be_bytes()));
        off += 4;
        buf[off..off + 16].copy_from_slice(lease.addr.as_bytes());
        off += 16;
        buf[off..off + 4].copy_from_slice(&lease.preferred_lifetime.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&lease.valid_lifetime.to_be_bytes());
        off += 4;

        Ok(off)
    }

    /// Build a DHCPv6 REBIND message (RFC 8415 Section 18.2.5)
    /// Sent to All_DHCP_Relay_Agents_and_Servers (multicast).
    /// Includes ClientID + IA_NA with IAADDR suboption (no ServerID — any server may respond).
    pub fn build_rebind(&self, buf: &mut [u8], lease: &DhcpV6Lease) -> Result<usize, &'static str> {
        if buf.len() < 256 {
            return Err("buffer too small");
        }

        let xid = self.xid.load(Ordering::SeqCst);

        buf[0] = DhcpV6MessageType::Rebind as u8;
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        let append_opt = |buf: &mut [u8],
                          offset: &mut usize,
                          code: u16,
                          data: &[u8]|
         -> Result<(), &'static str> {
            if *offset + 4 + data.len() > buf.len() {
                return Err("Buffer overflow during option writing");
            }
            buf[*offset..*offset + 2].copy_from_slice(&code.to_be_bytes());
            buf[*offset + 2..*offset + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
            buf[*offset + 4..*offset + 4 + data.len()].copy_from_slice(data);
            *offset += 4 + data.len();
            Ok(())
        };

        // Client Identifier (option 1)
        append_opt(buf, &mut off, 1, &self.duid)?;

        // No Server Identifier for Rebind (RFC 8415 Section 18.2.5)

        // IA_NA (option 3) with IAADDR suboption
        if off + 44 > buf.len() {
            return Err("Buffer overflow during IA_NA writing");
        }
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
        buf[off + 2..off + 4].copy_from_slice(&(40u16.to_be_bytes())); // length
        off += 4;
        buf[off..off + 4].copy_from_slice(&self.iaid.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // T1
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // T2
        off += 4;
        // IAADDR suboption
        buf[off..off + 2].copy_from_slice(&(5u16.to_be_bytes()));
        buf[off + 2..off + 4].copy_from_slice(&(24u16.to_be_bytes()));
        off += 4;
        buf[off..off + 16].copy_from_slice(lease.addr.as_bytes());
        off += 16;
        buf[off..off + 4].copy_from_slice(&lease.preferred_lifetime.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&lease.valid_lifetime.to_be_bytes());
        off += 4;

        Ok(off)
    }

    /// Build a DHCPv6 RELEASE message (RFC 8415 Section 18.2.6)
    /// Includes ClientID + ServerID + IA_NA with IAADDR suboption.
    pub fn build_release(
        &self,
        buf: &mut [u8],
        lease: &DhcpV6Lease,
    ) -> Result<usize, &'static str> {
        if buf.len() < 256 {
            return Err("buffer too small");
        }

        let xid = self.xid.load(Ordering::SeqCst);

        buf[0] = DhcpV6MessageType::Release as u8;
        buf[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
        let mut off = 4usize;

        let append_opt = |buf: &mut [u8],
                          offset: &mut usize,
                          code: u16,
                          data: &[u8]|
         -> Result<(), &'static str> {
            if *offset + 4 + data.len() > buf.len() {
                return Err("Buffer overflow during option writing");
            }
            buf[*offset..*offset + 2].copy_from_slice(&code.to_be_bytes());
            buf[*offset + 2..*offset + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
            buf[*offset + 4..*offset + 4 + data.len()].copy_from_slice(data);
            *offset += 4 + data.len();
            Ok(())
        };

        // Client Identifier (option 1)
        append_opt(buf, &mut off, 1, &self.duid)?;

        // Server Identifier (option 2) — RFC 8415 requires this for Release
        if let Ok(g) = self.server_duid.lock() {
            if let Some(ref duid) = *g {
                append_opt(buf, &mut off, 2, duid)?;
            }
        }

        // IA_NA (option 3) with IAADDR suboption
        if off + 44 > buf.len() {
            return Err("Buffer overflow during IA_NA writing");
        }
        buf[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // IA_NA
        buf[off + 2..off + 4].copy_from_slice(&(40u16.to_be_bytes())); // length
        off += 4;
        buf[off..off + 4].copy_from_slice(&self.iaid.to_be_bytes());
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // T1
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // T2
        off += 4;
        // IAADDR suboption
        buf[off..off + 2].copy_from_slice(&(5u16.to_be_bytes()));
        buf[off + 2..off + 4].copy_from_slice(&(24u16.to_be_bytes()));
        off += 4;
        buf[off..off + 16].copy_from_slice(lease.addr.as_bytes());
        off += 16;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // preferred=0 (releasing)
        off += 4;
        buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // valid=0 (releasing)
        off += 4;

        Ok(off)
    }

    /// DHCPv6 RELEASE を送信してリースをクリアする
    pub fn release(&self) {
        let lease = match self.lease.lock() {
            Ok(g) => g.clone(),
            Err(_) => {
                log::error!("[NET] DHCPv6: lease lock poisoned (release)");
                return;
            }
        };

        if let Some(lease) = lease {
            // Generate new XID for the Release transaction
            self.generate_secure_xid();

            let mut buf = [0u8; 512];
            match self.build_release(&mut buf, &lease) {
                Ok(len) => {
                    if let Some(src) = self.get_link_local() {
                        // Send to server address if known, otherwise multicast
                        let all_dhcp_servers = Self::all_dhcp_servers_multicast();
                        let dst = match self.server_addr.lock() {
                            Ok(ref a) => a.as_ref().copied().unwrap_or(all_dhcp_servers),
                            Err(_) => all_dhcp_servers,
                        };
                        self.enqueue_v6_send_bytes(src, dst, &buf[..len]);
                        log::info!("[NET] DHCPv6: RELEASE sent for {}", lease.addr);
                    }
                }
                Err(e) => {
                    log::error!("[NET] DHCPv6: Failed to build RELEASE: {}", e);
                }
            }
        }

        // Clear lease and reset state
        if let Ok(mut lg) = self.lease.lock() {
            *lg = None;
        }
        if let Ok(mut st) = self.state.lock() {
            *st = DhcpV6State::Init;
        }
        if let Ok(mut sg) = self.server_duid.lock() {
            *sg = None;
        }
        if let Ok(mut ag) = self.server_addr.lock() {
            *ag = None;
        }
        self.state_time.store(0, Ordering::SeqCst);
        self.retry_count.store(0, Ordering::SeqCst);
    }

    /// Parse a DHCPv6 REPLY/ADVERTISE and extract IAADDR if present.
    /// Also parses DNS Recursive Name Server (option 23), Domain Search List (option 24),
    /// and Status Code (option 13).
    pub fn parse_reply(
        &self,
        data: &[u8],
        current_time: u64,
    ) -> Result<Option<DhcpV6Lease>, &'static str> {
        if data.len() < 4 {
            return Err("packet too small");
        }
        let msg_type = data[0];
        if msg_type != (DhcpV6MessageType::Advertise as u8)
            && msg_type != (DhcpV6MessageType::Reply as u8)
        {
            return Err("not an advertise/reply");
        }

        // Security Fix: Verify Transaction ID (XID) (RFC 8415 Section 7.1)
        // XID is 3 bytes starting at offset 1.
        let xid = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        if xid != self.xid.load(Ordering::SeqCst) {
            log::warn!(
                "[NET] DHCPv6: XID mismatch (expected 0x{:06x}, got 0x{:06x}) - possible spoofing",
                self.xid.load(Ordering::SeqCst),
                xid
            );
            return Err("XID mismatch");
        }

        // iterate options after header
        let mut off = 4usize;
        let mut found_addr: Option<(Ipv6Address, u32, u32)> = None;
        let mut found_t1: u32 = 0;
        let mut found_t2: u32 = 0;
        let mut dns_servers: Vec<Ipv6Address> = Vec::new();
        let mut domain_search: Vec<alloc::string::String> = Vec::new();
        let mut status_code: Option<u16> = None;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
                    // IA_NA - scan suboptions for IAADDR and Status Code
                    if len >= 12 {
                        found_t1 = u32::from_be_bytes([
                            data[off + 4],
                            data[off + 5],
                            data[off + 6],
                            data[off + 7],
                        ]);
                        found_t2 = u32::from_be_bytes([
                            data[off + 8],
                            data[off + 9],
                            data[off + 10],
                            data[off + 11],
                        ]);
                        let mut sub_off = off + 12; // skip IAID/T1/T2
                        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                        while sub_off + 4 <= off + len {
                            let sc = u16::from_be_bytes([data[sub_off], data[sub_off + 1]]);
                            let sl =
                                u16::from_be_bytes([data[sub_off + 2], data[sub_off + 3]]) as usize;
                            sub_off += 4;
                            if sub_off + sl > off + len {
                                break;
                            }
                            match sc {
                                5 => {
                                    // IAADDR: 16 bytes addr + 4 preferred + 4 valid
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
                                        found_addr =
                                            Some((Ipv6Address::new(addr_bytes), pref, valid));
                                    }
                                }
                                13 => {
                                    // Status Code (within IA_NA)
                                    if sl >= 2 {
                                        let sc_val =
                                            u16::from_be_bytes([data[sub_off], data[sub_off + 1]]);
                                        status_code = Some(sc_val);
                                    }
                                }
                                _ => {}
                            }
                            sub_off += sl;
                        }
                    }
                }
                13 => {
                    // Status Code (top-level)
                    if len >= 2 {
                        let sc_val = u16::from_be_bytes([data[off], data[off + 1]]);
                        status_code = Some(sc_val);
                    }
                }
                23 => {
                    // DNS Recursive Name Server (RFC 3646)
                    // Contains one or more IPv6 addresses (16 bytes each)
                    let count = len / 16;
                    for i in 0..count {
                        if dns_servers.len() >= 8 {
                            break;
                        }
                        let start = off + i * 16;
                        if start + 16 <= off + len {
                            let mut addr_bytes = [0u8; 16];
                            addr_bytes.copy_from_slice(&data[start..start + 16]);
                            dns_servers.push(Ipv6Address::new(addr_bytes));
                        }
                    }
                }
                24 => {
                    // Domain Search List (RFC 3646)
                    // DNS-encoded domain name list
                    let domain_data = &data[off..off + len];
                    Self::parse_domain_search_list(domain_data, &mut domain_search);
                }
                _ => {}
            }

            off += len;
        }

        // If a non-zero status code was found, treat as error
        if let Some(sc) = status_code {
            if sc != 0 {
                log::warn!("[NET] DHCPv6: Received status code {} in reply", sc);
                return Ok(None);
            }
        }

        match found_addr {
            Some((addr, pref, valid)) => {
                // RFC 8415 Section 21.4: T1/T2 defaults if 0
                let mut t1 = found_t1;
                let mut t2 = found_t2;
                if t1 == 0 {
                    t1 = pref / 2;
                }
                if t2 == 0 {
                    t2 = (pref as u64 * 8 / 10) as u32;
                }

                let lease = DhcpV6Lease {
                    addr,
                    preferred_lifetime: pref,
                    valid_lifetime: valid,
                    t1,
                    t2,
                    obtained_at: current_time,
                    dns_servers,
                    domain_search,
                };
                Ok(Some(lease))
            }
            None => Ok(None),
        }
    }

    /// DNS エンコードされたドメインサーチリストをパースする (RFC 1035 Section 4.1.4 形式)
    /// Security: 圧縮ポインタの検出、ラベル長・合計長のバリデーション、無限ループ防止を追加。
    fn parse_domain_search_list(data: &[u8], out: &mut Vec<alloc::string::String>) {
        let mut off = 0usize;
        let mut name_count = 0;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and name_count limit.;
        while off < data.len() && name_count < 10 {
            let mut labels: Vec<&[u8]> = Vec::new();
            let mut total_len = 0usize;
            let mut label_count = 0;

            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                if off >= data.len() || label_count >= 64 {
                    break;
                }

                let first = data[off];
                if first == 0 {
                    off += 1;
                    break; // end of domain name
                }

                // RFC 1035 Section 4.1.4: Compression pointer (11xxxxxx)
                // DHCP オプションでは通常使用されないが、脆弱性回避のため検出時は処理を中断する。
                if (first & 0xC0) == 0xC0 {
                    log::warn!(
                        "[NET] DHCPv6: DNS compression pointer detected in domain search list - unsupported"
                    );
                    return;
                }

                // 予約済みビット (01xxxxxx, 10xxxxxx) のチェック
                if (first & 0xC0) != 0 {
                    log::warn!("[NET] DHCPv6: Invalid label type bits 0x{:02x}", first);
                    return;
                }

                let label_len = first as usize;
                off += 1;

                // RFC 1035: Labels are max 63 bytes
                if label_len > 63 || off + label_len > data.len() {
                    log::warn!("[NET] DHCPv6: Malformed label length {}", label_len);
                    return;
                }

                labels.push(&data[off..off + label_len]);
                off += label_len;
                total_len += label_len + 1; // +1 for the dot/length byte
                label_count += 1;

                // RFC 1035: Total name length is max 255 bytes
                if total_len > 255 {
                    log::warn!("[NET] DHCPv6: Domain name too long (> 255)");
                    return;
                }
            }

            if !labels.is_empty() {
                let domain: alloc::string::String = labels
                    .iter()
                    .map(|l| core::str::from_utf8(l).unwrap_or("?"))
                    .collect::<Vec<_>>()
                    .join(".");
                out.push(domain);
                name_count += 1;
            }
        }
    }

    /// Handle an incoming DHCPv6 packet (called by network receive path)
    /// `src` is the IPv6 source address the packet was received from.
    /// Returns true if handled
    pub fn handle_packet(&self, data: &[u8], src: Ipv6Address) -> bool {
        let now = crate::net::l4::endpoint::tcb_table().get_current_tick();

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
                    // transition to Requesting: Generate a new secure XID
                    self.generate_secure_xid();

                    *st = DhcpV6State::Requesting;
                    self.state_time.store(now, Ordering::SeqCst);
                    self.retry_count.store(0, Ordering::SeqCst);

                    // build and send REQUEST (selection) via async event queue
                    let mut buf = [0u8; 256];
                    if let Ok(len) = self.build_request_from_advertise(&mut buf) {
                        if let Some(src_ip) = self.get_link_local() {
                            self.enqueue_v6_send_bytes(src_ip, src, &buf[..len]);
                        }
                    }
                    return true;
                }
            }
            // ADVERTISE は OFFER に相当し、リース受理にはならない。
            // SolicitSent 以外の状態で受信した ADVERTISE は無視する。
            return false;
        }

        // Only treat REPLY messages as lease acceptance (RFC 8415)
        if msg_type != (DhcpV6MessageType::Reply as u8) {
            return false;
        }

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

                // Apply IPv6 address to the running NetworkStack (fire-and-forget via event queue)
                crate::net::l4::endpoint::event::enqueue_event_ignore_in(
                    self.runtime,
                    crate::net::l4::endpoint::event::NetworkEvent::ApplyIpv6Address {
                        addr: lease.addr.octets(),
                        result_slot: alloc::sync::Arc::new(crate::sync::PoisonLock::new(None)),
                        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
                    },
                );

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
    ///
    /// 非同期イベントキュー経由で送信（ロック競合回避）:
    /// `get_link_local()` で短時間ロックのみ取得し、送信は `enqueue_v6_send()` を使用する。
    pub fn check_timeout(&self, current_tick: u64, _tick_rate: u64) -> Result<(), &'static str> {
        let all_dhcp_servers = Self::all_dhcp_servers_multicast();

        match self.state.lock() {
            Ok(mut s) => match *s {
                DhcpV6State::Init => {
                    // Start new transaction: Generate cryptographically secure SOLICIT XID
                    self.generate_secure_xid();

                    // Send SOLICIT
                    let mut buf = [0u8; 256];
                    let len = self.build_solicit(&mut buf)?;

                    // Use link-local as source for SOLICIT (async event queue)
                    if let Some(src) = self.get_link_local() {
                        if self.enqueue_v6_send_bytes(src, all_dhcp_servers, &buf[..len]) {
                            *s = DhcpV6State::SolicitSent;
                            self.state_time.store(current_tick, Ordering::SeqCst);
                            self.retry_count.store(0, Ordering::SeqCst);
                        }
                    }
                }
                DhcpV6State::SolicitSent => {
                    // Retransmit logic (RFC 8415 Section 15: Exponential backoff with 10% jitter)
                    let retry = self.retry_count.load(Ordering::SeqCst);
                    // IRT = 1s, MRT = 120s
                    let base_t = (1u64 << core::cmp::min(retry, 7)).min(120);

                    // RFC 8415: RT = (1 + RAND) * T, where RAND is [-0.1, 0.1]
                    let rnd = (current_tick ^ (self.mac.as_bytes()[5] as u64)) % 21; // 0..20
                    let jitter_percent = (rnd as i64) - 10; // -10% .. +10%
                    let base_ms = (base_t * 1000) as i64;
                    let jitter_ms = (base_t as i64 * jitter_percent) / 10;
                    let interval_ms = (base_ms + jitter_ms).max(100) as u64;
                    let interval_ticks = interval_ms; // already >= 100ms

                    let elapsed_ms =
                        current_tick.saturating_sub(self.state_time.load(Ordering::SeqCst));
                    if elapsed_ms >= interval_ticks {
                        let retries = self.retry_count.fetch_add(1, Ordering::SeqCst);
                        if retries >= Self::MAX_RETRIES {
                            // Give up, go back to Init (will retry later)
                            *s = DhcpV6State::Init;
                        } else {
                            // retransmit SOLICIT using SAME XID
                            let mut buf = [0u8; 256];
                            let len = self.build_solicit(&mut buf)?;
                            if let Some(src) = self.get_link_local() {
                                self.enqueue_v6_send_bytes(src, all_dhcp_servers, &buf[..len]);
                            }
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        }
                    }
                }
                DhcpV6State::Requesting => {
                    // Retransmit REQUEST (RFC 8415 Section 15: IRT = 1s, MRT = 30s)
                    let retry = self.retry_count.load(Ordering::SeqCst);
                    let base_t = (1u64 << core::cmp::min(retry, 5)).min(30);

                    let rnd = (current_tick ^ (self.mac.as_bytes()[5] as u64)) % 21;
                    let jitter_percent = (rnd as i64) - 10;
                    let base_ms = (base_t * 1000) as i64;
                    let jitter_ms = (base_t as i64 * jitter_percent) / 10;
                    let interval_ms = (base_ms + jitter_ms).max(100) as u64;
                    let interval_ticks = interval_ms;

                    let elapsed_ms =
                        current_tick.saturating_sub(self.state_time.load(Ordering::SeqCst));
                    if elapsed_ms >= interval_ticks {
                        let retries = self.retry_count.fetch_add(1, Ordering::SeqCst);
                        if retries >= Self::MAX_RETRIES {
                            // Give up and return to Init
                            *s = DhcpV6State::Init;
                        } else {
                            // resend Request using SAME XID
                            let mut buf = [0u8; 256];
                            let len = self.build_request_from_advertise(&mut buf)?;
                            if let Some(src) = self.get_link_local() {
                                let dst = match self.server_addr.lock() {
                                    Ok(ref a) => a.as_ref().copied().unwrap_or(all_dhcp_servers),
                                    Err(_) => all_dhcp_servers,
                                };
                                self.enqueue_v6_send_bytes(src, dst, &buf[..len]);
                            }
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        }
                    }
                }
                DhcpV6State::Bound => {
                    // Check lease lifetimes and transition to Renewing if needed
                    if let Some(lease) = self.lease() {
                        let elapsed_ms = current_tick.saturating_sub(lease.obtained_at);
                        if elapsed_ms >= (lease.t1 as u64 * 1000) {
                            // start renewal: Generate secure XID for Renew transaction
                            self.generate_secure_xid();

                            *s = DhcpV6State::Renewing;
                            self.state_time.store(current_tick, Ordering::SeqCst);
                            self.retry_count.store(0, Ordering::SeqCst);

                            // Send first RENEW immediately
                            let mut buf = [0u8; 512];
                            if let Ok(len) = self.build_renew(&mut buf, &lease) {
                                if let Some(src) = self.get_link_local() {
                                    let dst = match self.server_addr.lock() {
                                        Ok(ref a) => {
                                            a.as_ref().copied().unwrap_or(all_dhcp_servers)
                                        }
                                        Err(_) => all_dhcp_servers,
                                    };
                                    self.enqueue_v6_send_bytes(src, dst, &buf[..len]);
                                }
                            }
                        }
                    }
                }
                DhcpV6State::Renewing => {
                    // Attempt to renew (RFC 8415 Section 18.2.3: IRT = 10s, MRT = 600s)
                    let retry = self.retry_count.load(Ordering::SeqCst);
                    let base_t = (10u64 << core::cmp::min(retry, 6)).min(600);

                    let rnd = (current_tick ^ (self.mac.as_bytes()[5] as u64)) % 21;
                    let jitter_percent = (rnd as i64) - 10;
                    let base_ms = (base_t * 1000) as i64;
                    let jitter_ms = (base_t as i64 * jitter_percent) / 10;
                    let interval_ms = (base_ms + jitter_ms).max(100) as u64;
                    let interval_ticks = interval_ms;

                    if let Some(lease) = self.lease() {
                        let elapsed_ms = current_tick.saturating_sub(lease.obtained_at);
                        if elapsed_ms >= (lease.t2 as u64 * 1000) {
                            // Escalate to rebinding (multicast) if T2 expires
                            *s = DhcpV6State::Rebinding;
                            self.retry_count.store(0, Ordering::SeqCst);
                            self.state_time.store(current_tick, Ordering::SeqCst);

                            // Send first REBIND immediately
                            let mut buf = [0u8; 512];
                            if let Ok(len) = self.build_rebind(&mut buf, &lease) {
                                if let Some(src) = self.get_link_local() {
                                    self.enqueue_v6_send_bytes(src, all_dhcp_servers, &buf[..len]);
                                }
                            }
                            return Ok(());
                        }

                        let elapsed_state_ms =
                            current_tick.saturating_sub(self.state_time.load(Ordering::SeqCst));
                        if elapsed_state_ms >= interval_ticks {
                            self.retry_count.fetch_add(1, Ordering::SeqCst);
                            // Send RENEW (msg type 5) to the original server using SAME XID
                            let mut buf = [0u8; 512];
                            let len = self.build_renew(&mut buf, &lease)?;
                            if let Some(src) = self.get_link_local() {
                                let dst = match self.server_addr.lock() {
                                    Ok(ref a) => a.as_ref().copied().unwrap_or(all_dhcp_servers),
                                    Err(_) => all_dhcp_servers,
                                };
                                self.enqueue_v6_send_bytes(src, dst, &buf[..len]);
                            }
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        }
                    } else {
                        // No lease known — reset to Init
                        *s = DhcpV6State::Init;
                    }
                }
                DhcpV6State::Rebinding => {
                    // Rebinding (RFC 8415 Section 18.2.5: IRT = 10s, MRT = 600s)
                    let retry = self.retry_count.load(Ordering::SeqCst);
                    let base_t = (10u64 << core::cmp::min(retry, 6)).min(600);

                    let rnd = (current_tick ^ (self.mac.as_bytes()[5] as u64)) % 21;
                    let jitter_percent = (rnd as i64) - 10;
                    let base_ms = (base_t * 1000) as i64;
                    let jitter_ms = (base_t as i64 * jitter_percent) / 10;
                    let interval_ms = (base_ms + jitter_ms).max(100) as u64;
                    let interval_ticks = interval_ms;

                    if let Some(lease) = self.lease() {
                        let elapsed_ms = current_tick.saturating_sub(lease.obtained_at);
                        if elapsed_ms >= (lease.valid_lifetime as u64 * 1000) {
                            // Give up and return to Init (clear lease)
                            *s = DhcpV6State::Init;
                            if let Ok(mut lg) = self.lease.lock() {
                                *lg = None;
                            }
                            return Ok(());
                        }

                        let elapsed_state_ms =
                            current_tick.saturating_sub(self.state_time.load(Ordering::SeqCst));
                        if elapsed_state_ms >= interval_ticks {
                            self.retry_count.fetch_add(1, Ordering::SeqCst);
                            // Send REBIND (msg type 6) to multicast using SAME XID
                            let mut buf = [0u8; 512];
                            let len = self.build_rebind(&mut buf, &lease)?;
                            if let Some(src) = self.get_link_local() {
                                self.enqueue_v6_send_bytes(src, all_dhcp_servers, &buf[..len]);
                            }
                            self.state_time.store(current_tick, Ordering::SeqCst);
                        }
                    } else {
                        *s = DhcpV6State::Init;
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

pub fn init_v6_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    mac_address: crate::net::l2::ethernet::MacAddress,
) {
    let client = DhcpV6Client::new_in(runtime, mac_address);
    match super::primary_v6_client_lock_in(runtime).lock() {
        Ok(mut g) => *g = Some(client),
        Err(_) => log::error!("[NET] DHCPv6 Global lock poisoned (init) - initialization skipped"),
    }
}

pub(crate) fn update_client_v6_mac(mac_address: crate::net::l2::ethernet::MacAddress) {
    match super::primary_v6_client_lock_in(crate::net::runtime::default_runtime()).lock() {
        Ok(mut guard) => {
            if let Some(client) = guard.as_mut() {
                client.mac = mac_address;
                client.duid = DhcpV6Client::make_duid_ll(&mac_address);
                if let Ok(mut cache) = client.cached_link_local.lock() {
                    *cache = None;
                }
            }
        }
        Err(_) => log::error!("[NET] DHCPv6 Global lock poisoned (update_client_v6_mac)"),
    }
}
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod tests {
    use super::*;
    use crate::net::l3::ipv6::Ipv6Address;

    #[cfg_attr(test, test_case)]
    pub fn test_build_solicit_min_size() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        let mut buf = [0u8; 256];
        let now = 1000u64;

        // Setup XID
        client
            .xid
            .store(((now as u32) ^ 0xDEADBEEF) & 0x00FF_FFFF, Ordering::SeqCst);

        let len = client.build_solicit(&mut buf).unwrap();
        assert!(len > 0);
        assert_eq!(buf[0], DhcpV6MessageType::Solicit as u8);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_parse_reply_with_iaaddr() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        // construct a fake REPLY that contains IA_NA with IAADDR
        let mut pkt = alloc::vec![0u8; 4 + 4 + 12 + 4 + 24];
        pkt[0] = DhcpV6MessageType::Reply as u8;
        // xid (3 bytes)
        pkt[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut off = 4;
        // IA_NA option
        pkt[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // code
        pkt[off + 2..off + 4].copy_from_slice(&(40u16.to_be_bytes())); // len
        off += 4;
        // IAID + T1 + T2
        pkt[off..off + 12].copy_from_slice(&[0u8; 12]);
        off += 12;
        // IAADDR as suboption under IA_NA (we'll append directly after)
        // For simplicity append IAADDR as a top-level option in this test
        pkt[off..off + 2].copy_from_slice(&(5u16.to_be_bytes()));
        pkt[off + 2..off + 4].copy_from_slice(&(24u16.to_be_bytes()));
        off += 4;
        let addr = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[off..off + 16].copy_from_slice(addr.as_bytes());
        off += 16;
        pkt[off..off + 4].copy_from_slice(&3600u32.to_be_bytes());
        off += 4;
        pkt[off..off + 4].copy_from_slice(&7200u32.to_be_bytes());

        let parsed = client.parse_reply(&pkt, 100).unwrap();
        assert!(parsed.is_some());
        let lease = parsed.unwrap();
        assert_eq!(lease.addr, addr);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_build_request_min_size() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: crate::net::l3::ipv6::Ipv6Address::new([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ]),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            t1: 0,
            t2: 0,
            obtained_at: 100,
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
        };
        let mut buf = [0u8; 512];
        let now = 200u64;

        // Setup XID
        client
            .xid
            .store(((now as u32) ^ 0xBEEFBEEF) & 0x00FF_FFFF, Ordering::SeqCst);

        let len = client.build_request(&mut buf, &lease).unwrap();
        assert!(len > 0);
        assert_eq!(buf[0], DhcpV6MessageType::Request as u8);
        // find IAADDR suboption code (5) somewhere after header
        let mut found = false;
        for i in 4..len - 2 {
            if buf[i] == 0 && buf[i + 1] == 5u8 {
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_bound_to_renewing_and_rebinding_transitions() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        // set lease with T1 = 1 second, T2 = 2 seconds, valid = 10 seconds
        let lease = DhcpV6Lease {
            addr: crate::net::l3::ipv6::Ipv6Address::new([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
            ]),
            preferred_lifetime: 5,
            valid_lifetime: 10,
            t1: 1,
            t2: 2,
            obtained_at: 0,
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
        };
        if let Ok(mut lg) = client.lease.lock() {
            *lg = Some(lease.clone());
        }
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::Bound;
        }
        // tick_rate = 1000 (ms per sec), current_tick beyond T1
        let tick_rate = 1000u64;
        let now = (lease.obtained_at as u64) + lease.t1 as u64 * tick_rate + 10;
        client.check_timeout(now, tick_rate).unwrap();
        assert_eq!(client.state(), DhcpV6State::Renewing);

        // move time beyond T2
        let now_t2 = (lease.obtained_at as u64) + lease.t2 as u64 * tick_rate + 10;
        client.check_timeout(now_t2, tick_rate).unwrap();
        assert_eq!(client.state(), DhcpV6State::Rebinding);

        // move time beyond valid_lifetime
        let now_valid = (lease.obtained_at as u64) + lease.valid_lifetime as u64 * tick_rate + 10;
        client.check_timeout(now_valid, tick_rate).unwrap();
        assert_eq!(client.state(), DhcpV6State::Init);
        assert!(client.lease().is_none());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_handle_packet_stores_server_addr_and_duid() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);

        // Build a REPLY that contains Server Identifier (option 2) + IA_NA with IAADDR
        let server_duid: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let addr = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);

        // layout: header(4) + srv_id(opt2) + IA_NA(opt3)+IAADDR(subopt5)
        let mut pkt = alloc::vec![0u8; 4 + 4 + server_duid.len() + 4 + 12 + 4 + 24];
        pkt[0] = DhcpV6MessageType::Reply as u8;
        pkt[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut off = 4;
        // Server Identifier (option 2)
        pkt[off..off + 2].copy_from_slice(&(2u16.to_be_bytes()));
        pkt[off + 2..off + 4].copy_from_slice(&(server_duid.len() as u16).to_be_bytes());
        off += 4;
        pkt[off..off + server_duid.len()].copy_from_slice(&server_duid);
        off += server_duid.len();

        // IA_NA option (top-level)
        pkt[off..off + 2].copy_from_slice(&(3u16.to_be_bytes())); // code
        pkt[off + 2..off + 4].copy_from_slice(&(40u16.to_be_bytes())); // len
        off += 4;
        // IAID + T1 + T2
        pkt[off..off + 12].copy_from_slice(&[0u8; 12]);
        off += 12;

        // IAADDR as a top-level option for this test (simpler)
        pkt[off..off + 2].copy_from_slice(&(5u16.to_be_bytes()));
        pkt[off + 2..off + 4].copy_from_slice(&(24u16.to_be_bytes()));
        off += 4;
        pkt[off..off + 16].copy_from_slice(addr.as_bytes());
        off += 16;
        pkt[off..off + 4].copy_from_slice(&3600u32.to_be_bytes());
        off += 4;
        pkt[off..off + 4].copy_from_slice(&7200u32.to_be_bytes());

        let src_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
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
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);

        // Put client into SolicitSent
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::SolicitSent;
        }

        // Build an ADVERTISE that contains Server Identifier (option 2) but no IAADDR
        let server_duid: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let mut pkt = alloc::vec![0u8; 4 + 4 + server_duid.len()];
        pkt[0] = DhcpV6MessageType::Advertise as u8;
        pkt[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut off = 4;
        pkt[off..off + 2].copy_from_slice(&(2u16.to_be_bytes()));
        pkt[off + 2..off + 4].copy_from_slice(&(server_duid.len() as u16).to_be_bytes());
        off += 4;
        pkt[off..off + server_duid.len()].copy_from_slice(&server_duid);

        let src_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let handled = client.handle_packet(&pkt, src_ip);
        assert!(handled);
        assert_eq!(client.state(), DhcpV6State::Requesting);
        // server_addr and server_duid should be set
        if let Ok(g) = client.server_addr.lock() {
            assert_eq!(g.as_ref().unwrap(), &src_ip);
        }
        if let Ok(g) = client.server_duid.lock() {
            assert_eq!(g.as_ref().unwrap().as_slice(), &server_duid);
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_requesting_retransmit_exhaustion_goes_to_init() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::Requesting;
        }
        // simulate having already retried up to MAX_RETRIES
        client
            .retry_count
            .store(DhcpV6Client::MAX_RETRIES, Ordering::SeqCst);
        let tick_rate = 1000u64;
        let now = DhcpV6Client::RETRANS_INTERVAL_SECS * tick_rate + 10;
        client.check_timeout(now, tick_rate).unwrap();
        assert_eq!(client.state(), DhcpV6State::Init);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_force_renew_or_restart_paths() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            t1: 0,
            t2: 0,
            obtained_at: 0,
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
        };

        if let Ok(mut lg) = client.lease.lock() {
            *lg = Some(lease.clone());
        }
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::Bound;
        }
        client.force_renew_or_restart(100).unwrap();
        assert_eq!(client.state(), DhcpV6State::Renewing);
        assert!(client.lease().is_some());

        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::Requesting;
        }
        client.force_renew_or_restart(200).unwrap();
        assert_eq!(client.state(), DhcpV6State::Init);
        assert!(client.lease().is_none());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_solicit_advertise_request_reply_complete_flow() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);

        // Start from Init -> send SOLICIT (simulate periodic trigger)
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::SolicitSent;
        }

        // Build ADVERTISE (server-id only)
        let server_duid: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let mut adv = alloc::vec![0u8; 4 + 4 + server_duid.len()];
        adv[0] = DhcpV6MessageType::Advertise as u8;
        adv[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut off = 4;
        adv[off..off + 2].copy_from_slice(&(2u16.to_be_bytes()));
        adv[off + 2..off + 4].copy_from_slice(&(server_duid.len() as u16).to_be_bytes());
        off += 4;
        adv[off..off + server_duid.len()].copy_from_slice(&server_duid);

        let server_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        assert!(client.handle_packet(&adv, server_ip));
        assert_eq!(client.state(), DhcpV6State::Requesting);

        // Now build a REPLY that contains IAADDR for the requested IA
        let addr = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6]);
        let mut reply = alloc::vec![0u8; 4 + 4 + 12 + 4 + 24];
        reply[0] = DhcpV6MessageType::Reply as u8;
        reply[1..4].copy_from_slice(&0u32.to_be_bytes()[1..4]);
        let mut roff = 4;
        // IA_NA option (top-level)
        reply[roff..roff + 2].copy_from_slice(&(3u16.to_be_bytes())); // code
        reply[roff + 2..roff + 4].copy_from_slice(&(40u16.to_be_bytes())); // len
        roff += 4;
        // IAID + T1 + T2
        reply[roff..roff + 12].copy_from_slice(&[0u8; 12]);
        roff += 12;
        // IAADDR (as top-level for test simplicity)
        reply[roff..roff + 2].copy_from_slice(&(5u16.to_be_bytes()));
        reply[roff + 2..roff + 4].copy_from_slice(&(24u16.to_be_bytes()));
        roff += 4;
        reply[roff..roff + 16].copy_from_slice(addr.as_bytes());
        roff += 16;
        reply[roff..roff + 4].copy_from_slice(&3600u32.to_be_bytes());
        roff += 4;
        reply[roff..roff + 4].copy_from_slice(&7200u32.to_be_bytes());

        assert!(client.handle_packet(&reply, server_ip));
        assert_eq!(client.state(), DhcpV6State::Bound);
        let l = client.lease();
        assert!(l.is_some());
        assert_eq!(l.unwrap().addr, addr);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_renew_uses_known_server_address_for_dst() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: crate::net::l3::ipv6::Ipv6Address::new([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
            ]),
            preferred_lifetime: 1,
            valid_lifetime: 10,
            t1: 0,
            t2: 0,
            obtained_at: 0,
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
        };
        if let Ok(mut lg) = client.lease.lock() {
            *lg = Some(lease.clone());
        }
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::Renewing;
        }
        // set known server address
        let server_ip = crate::net::l3::ipv6::Ipv6Address::new([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);
        if let Ok(mut g) = client.server_addr.lock() {
            *g = Some(server_ip);
        }

        let tick_rate = 1000u64;
        // force a retransmit interval to elapse
        let now = DhcpV6Client::RETRANS_INTERVAL_SECS * tick_rate + 10;
        client.check_timeout(now, tick_rate).unwrap();
        // should still be Renewing (not immediately escalate to Rebinding)
        assert_eq!(client.state(), DhcpV6State::Renewing);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_build_renew_uses_correct_msg_type() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa]),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            t1: 0,
            t2: 0,
            obtained_at: 0,
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
        };
        // Set server DUID
        if let Ok(mut g) = client.server_duid.lock() {
            *g = Some(alloc::vec![0x01, 0x02, 0x03, 0x04]);
        }
        client.xid.store(0x123456, Ordering::SeqCst);
        let mut buf = [0u8; 512];
        let len = client.build_renew(&mut buf, &lease).unwrap();
        assert!(len > 0);
        assert_eq!(buf[0], DhcpV6MessageType::Renew as u8); // msg type 5
        // Verify IAADDR suboption exists
        let mut found_iaaddr = false;
        for i in 4..len.saturating_sub(1) {
            if buf[i] == 0 && buf[i + 1] == 5 {
                found_iaaddr = true;
                break;
            }
        }
        assert!(found_iaaddr, "IAADDR suboption not found in Renew");
    }

    #[cfg_attr(test, test_case)]
    pub fn test_build_rebind_uses_correct_msg_type() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb]),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            t1: 0,
            t2: 0,
            obtained_at: 0,
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
        };
        client.xid.store(0xABCDEF, Ordering::SeqCst);
        let mut buf = [0u8; 512];
        let len = client.build_rebind(&mut buf, &lease).unwrap();
        assert!(len > 0);
        assert_eq!(buf[0], DhcpV6MessageType::Rebind as u8); // msg type 6
        // Rebind should NOT contain Server Identifier (option 2)
        let mut found_server_id = false;
        let mut off = 4usize;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while off + 4 <= len {
            let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let opt_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            off += 4;
            if code == 2 {
                found_server_id = true;
            }
            off += opt_len;
        }
        assert!(!found_server_id, "Rebind must not contain Server ID");
    }

    #[cfg_attr(test, test_case)]
    pub fn test_build_release_uses_correct_msg_type() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc]),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            t1: 0,
            t2: 0,
            obtained_at: 0,
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
        };
        if let Ok(mut g) = client.server_duid.lock() {
            *g = Some(alloc::vec![0xAA, 0xBB]);
        }
        client.xid.store(0x654321, Ordering::SeqCst);
        let mut buf = [0u8; 512];
        let len = client.build_release(&mut buf, &lease).unwrap();
        assert!(len > 0);
        assert_eq!(buf[0], DhcpV6MessageType::Release as u8); // msg type 8
    }

    #[cfg_attr(test, test_case)]
    pub fn test_release_clears_lease_and_state() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);
        let lease = DhcpV6Lease {
            addr: Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xd]),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            t1: 0,
            t2: 0,
            obtained_at: 0,
            dns_servers: Vec::new(),
            domain_search: Vec::new(),
        };
        if let Ok(mut lg) = client.lease.lock() {
            *lg = Some(lease);
        }
        if let Ok(mut st) = client.state.lock() {
            *st = DhcpV6State::Bound;
        }
        if let Ok(mut sg) = client.server_duid.lock() {
            *sg = Some(alloc::vec![0x01]);
        }
        if let Ok(mut ag) = client.server_addr.lock() {
            *ag = Some(Ipv6Address::new([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]));
        }

        client.release();

        assert_eq!(client.state(), DhcpV6State::Init);
        assert!(client.lease().is_none());
        if let Ok(g) = client.server_duid.lock() {
            assert!(g.is_none());
        }
        if let Ok(g) = client.server_addr.lock() {
            assert!(g.is_none());
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_parse_reply_with_dns_servers() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);

        // Build a REPLY with IA_NA/IAADDR + DNS Recursive Name Server (option 23)
        let dns1 = Ipv6Address::new([
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ]);
        let dns2 = Ipv6Address::new([
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x44,
        ]);
        let addr = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe]);

        // header(4) + IA_NA(4+12 + subopt IAADDR 4+24) + DNS(4+32)
        let mut pkt = alloc::vec![0u8; 4 + 4 + 12 + 4 + 24 + 4 + 32];
        pkt[0] = DhcpV6MessageType::Reply as u8;
        let mut off = 4usize;

        // IA_NA option (code=3, len=40)
        pkt[off..off + 2].copy_from_slice(&3u16.to_be_bytes());
        pkt[off + 2..off + 4].copy_from_slice(&40u16.to_be_bytes());
        off += 4;
        // IAID + T1 + T2 = 0
        pkt[off..off + 12].copy_from_slice(&[0u8; 12]);
        off += 12;
        // IAADDR suboption (code=5, len=24)
        pkt[off..off + 2].copy_from_slice(&5u16.to_be_bytes());
        pkt[off + 2..off + 4].copy_from_slice(&24u16.to_be_bytes());
        off += 4;
        pkt[off..off + 16].copy_from_slice(addr.as_bytes());
        off += 16;
        pkt[off..off + 4].copy_from_slice(&3600u32.to_be_bytes()); // preferred
        off += 4;
        pkt[off..off + 4].copy_from_slice(&7200u32.to_be_bytes()); // valid
        off += 4;

        // DNS Recursive Name Server (option 23, len=32: 2 addresses)
        pkt[off..off + 2].copy_from_slice(&23u16.to_be_bytes());
        pkt[off + 2..off + 4].copy_from_slice(&32u16.to_be_bytes());
        off += 4;
        pkt[off..off + 16].copy_from_slice(dns1.as_bytes());
        off += 16;
        pkt[off..off + 16].copy_from_slice(dns2.as_bytes());

        let parsed = client.parse_reply(&pkt, 500).unwrap();
        assert!(parsed.is_some());
        let lease = parsed.unwrap();
        assert_eq!(lease.addr, addr);
        assert_eq!(lease.dns_servers.len(), 2);
        assert_eq!(lease.dns_servers[0], dns1);
        assert_eq!(lease.dns_servers[1], dns2);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_parse_reply_with_status_code_error() {
        let mac = crate::net::l2::ethernet::MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let client = DhcpV6Client::new(mac);

        // Build a REPLY with Status Code = 2 (NoBinding)
        let mut pkt = alloc::vec![0u8; 4 + 4 + 2];
        pkt[0] = DhcpV6MessageType::Reply as u8;
        let mut off = 4usize;
        // Status Code option (code=13, len=2)
        pkt[off..off + 2].copy_from_slice(&13u16.to_be_bytes());
        pkt[off + 2..off + 4].copy_from_slice(&2u16.to_be_bytes());
        off += 4;
        pkt[off..off + 2].copy_from_slice(&2u16.to_be_bytes()); // NoBinding

        let parsed = client.parse_reply(&pkt, 100).unwrap();
        assert!(parsed.is_none(), "Non-zero status code should return None");
    }

    #[cfg_attr(test, test_case)]
    pub fn test_parse_domain_search_list() {
        // DNS-encoded domain: "example.com" → [7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0]
        let data = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 4, b't', b'e',
            b's', b't', 3, b'n', b'e', b't', 0,
        ];
        let mut out = Vec::new();
        DhcpV6Client::parse_domain_search_list(&data, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], "example.com");
        assert_eq!(out[1], "test.net");
    }
}
