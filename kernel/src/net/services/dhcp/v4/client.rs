// ============================================================================
// kernel/src/net/services/dhcp/v4/client.rs - サービス / DHCP / v4 / クライアント
// ============================================================================

use super::{
    DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_MAX_MESSAGE_SIZE, DhcpClient, DhcpHeader, DhcpLease,
    DhcpMessageType, DhcpOperation, DhcpOption, DhcpResponseResult, DhcpState, ParsedOptions,
};
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;
use crate::sync::PoisonLock;
use crate::task::{self, TimeoutResult};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

impl DhcpClient {
    /// 最大再試行回数
    pub const MAX_RETRIES: u32 = 4;

    /// ARP probe waiting time (seconds)
    pub(super) const PROBE_WAIT_SECS: u64 = 1;

    /// Default retry interval used for retransmits (seconds)
    pub(super) const RETRY_INTERVAL_SECS: u64 = 4;

    /// 新しいDHCPクライアントを作成
    pub fn new(mac_address: MacAddress) -> Self {
        Self::new_in(crate::net::runtime::default_runtime(), mac_address)
    }

    /// 指定runtimeに属するDHCPクライアントを作成
    pub fn new_in(runtime: crate::net::runtime::NetRuntimeHandle, mac_address: MacAddress) -> Self {
        Self {
            runtime,
            mac_address,
            state: PoisonLock::new(DhcpState::Init),
            xid: AtomicU32::new(0),
            lease: PoisonLock::new(None),
            offered_lease: PoisonLock::new(None),
            offered_probe_at: AtomicU64::new(0),
            last_declined: AtomicU32::new(0),
            last_released: AtomicU32::new(0),
            state_time: AtomicU64::new(0),
            retry_count: AtomicU32::new(0),
        }
    }

    /// DHCPクライアントのメインループ（非同期）
    ///
    /// 指定されたポートでUDPソケットをバインドし、DHCP状態機械を駆動します。
    pub async fn run(&self) -> Result<(), &'static str> {
        // DHCPクライアントポート(68)でバインド
        let socket = crate::net::l4::udp::UdpEndpoint::bind_in(
            self.runtime,
            crate::net::types::InterfaceScope::Any,
            DHCP_CLIENT_PORT,
            None,
        )
        .map_err(|_| "Failed to bind DHCP socket")?;

        log::info!("[NET] DHCPv4 client task started");

        loop {
            let now = crate::task::current_tick();

            // 状態機械を駆動（タイムアウトチェックと必要に応じたパケット送信）
            self.drive(now, 1000).await?;

            // パケット受信を待機。再送タイマーを考慮して1秒でタイムアウト。
            match task::with_timeout(socket.recv(), 1000).await {
                TimeoutResult::Completed(Some((_if_id, _src, _ttl, packet))) => {
                    let now = crate::task::current_tick();
                    let response = self.process_response_payload(packet, now);
                    match response {
                        Ok(DhcpResponseResult::Ack(result)) => {
                            let crate::net::services::dhcp::DhcpAckResult { lease, applied } =
                                result;
                            log::info!("[NET] DHCPv4 ACK received: {:?}", lease.ip_address);
                            // リースをイベントキュー経由でスタックに適用（デッドロック回避）
                            crate::net::runtime::command::enqueue_command_ignore_in(
                                self.runtime,
                                crate::net::runtime::command::RuntimeCommand::Control(
                                    crate::net::runtime::command::ControlCommand::DhcpApplyLease {
                                        if_id: None,
                                        config: applied,
                                    },
                                ),
                            );
                            // mDNS のローカル IP を更新
                            if let Ok(mut guard) =
                                crate::net::services::mdns::service_in(self.runtime).lock()
                            {
                                if let Some(ref mut mdns) = *guard {
                                    mdns.set_local_ip(lease.ip_address);
                                }
                            }
                        }
                        Ok(DhcpResponseResult::Offer(lease)) => {
                            log::info!(
                                "[NET] DHCPv4 OFFER received: {:?} from {:?}",
                                lease.ip_address,
                                lease.server_ip
                            );
                        }
                        Ok(DhcpResponseResult::Nak) => {
                            log::warn!("[NET] DHCPv4 NAK received");
                        }
                        Err(e) => {
                            log::warn!("[NET] DHCPv4 response error: {}", e);
                        }
                    }
                }
                TimeoutResult::TimedOut => {
                    // タイムアウトした場合はループの先頭に戻り、drive() で再送チェックが行われる
                }
                TimeoutResult::Completed(None) => {
                    log::warn!("[NET] DHCPv4 socket closed unexpectedly");
                    break;
                }
            }
        }

        Ok(())
    }

    /// 現在の状態を取得
    pub fn state(&self) -> DhcpState {
        match self.state.lock() {
            Ok(g) => *g,
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (state) - returning Init");
                DhcpState::Init
            }
        }
    }

    /// Offer されているリースを取得 (テスト・外部 API 用)
    pub fn offered_lease(&self) -> Option<DhcpLease> {
        match self.offered_lease.lock() {
            Ok(g) => g.clone(),
            Err(_) => {
                log::error!("[NET] DHCP Offer lock poisoned (offered_lease) - returning None");
                None
            }
        }
    }

    pub fn with_offered_lease<F, R>(&self, f: F) -> R
    where
        F: FnOnce(Option<&DhcpLease>) -> R,
    {
        match self.offered_lease.lock() {
            Ok(g) => f(g.as_ref()),
            Err(_) => f(None),
        }
    }

    /// 現在のリースを取得
    pub fn lease(&self) -> Option<DhcpLease> {
        match self.lease.lock() {
            Ok(g) => g.clone(),
            Err(_) => {
                log::error!("[NET] DHCP Lease lock poisoned (lease) - returning None");
                None
            }
        }
    }

    pub fn with_lease<F, R>(&self, f: F) -> R
    where
        F: FnOnce(Option<&DhcpLease>) -> R,
    {
        match self.lease.lock() {
            Ok(g) => f(g.as_ref()),
            Err(_) => f(None),
        }
    }

    /// Acquire the current DHCP state (internal helper)
    fn lock_dhcp_state(&self) -> Result<DhcpState, &'static str> {
        match self.state.lock() {
            Ok(g) => Ok(*g),
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (lock_dhcp_state)");
                Err("State lock poisoned")
            }
        }
    }

    /// Determine which lease should be used when constructing a REQUEST packet.
    ///
    /// Returns `(lease, is_renewal)` where `is_renewal` is true if the client
    /// is in the `Renewing` state.  For non‑renewal requests we use the
    /// offered lease (if available) when not already bound.
    fn get_lease_for_request(
        &self,
        current_state: DhcpState,
    ) -> Result<(DhcpLease, bool), &'static str> {
        // If we're renewing, or already bound/rebinding, use the
        // active lease.  Otherwise fall back to the offered lease.
        if current_state == DhcpState::Renewing
            || current_state == DhcpState::Bound
            || current_state == DhcpState::Rebinding
        {
            self.with_lease(|lease_opt| {
                if let Some(l) = lease_opt {
                    let is_renew_or_rebind = current_state == DhcpState::Renewing
                        || current_state == DhcpState::Rebinding;
                    Ok((l.clone(), is_renew_or_rebind))
                } else {
                    Err("No active lease available")
                }
            })
        } else {
            // not bound yet; use offered_lease
            self.with_offered_lease(|offer_opt| {
                if let Some(l) = offer_opt {
                    Ok((l.clone(), false))
                } else {
                    Err("No offered lease available")
                }
            })
        }
    }

    /// INFORM / REQUEST 共通で利用する、現在有効なリースを取得する
    pub(super) fn get_active_lease(&self) -> Result<DhcpLease, &'static str> {
        self.with_lease(|g| g.cloned().ok_or("No active lease available"))
    }

    /// **テスト用**: リースを強制的に設定します。
    ///
    /// 通常のランタイムでは使用しませんが、ユニット/スモーク
    /// テストが内部状態を操作するためのAPIとして公開しています。
    pub fn set_lease_for_test(&self, lease: DhcpLease) {
        if let Ok(mut guard) = self.lease.lock() {
            *guard = Some(lease);
        }
    }

    /// Return last declined IP recorded (if any)
    pub fn last_declined_ip(&self) -> Option<Ipv4Address> {
        let v = self.last_declined.load(Ordering::SeqCst);
        if v == 0 {
            None
        } else {
            Some(Ipv4Address::from_u32(v))
        }
    }

    /// Return last released IP recorded (if any)
    pub fn last_released_ip(&self) -> Option<Ipv4Address> {
        let v = self.last_released.load(Ordering::SeqCst);
        if v == 0 {
            None
        } else {
            Some(Ipv4Address::from_u32(v))
        }
    }

    pub fn matches_response(&self, data: &[u8]) -> bool {
        if data.len() < DhcpHeader::SIZE + 4 {
            return false;
        }
        let Some(header) = DhcpHeader::decode_from(data) else {
            return false;
        };
        if header.op != DhcpOperation::Reply as u8 {
            return false;
        }
        if header.xid() != self.xid.load(Ordering::SeqCst) {
            return false;
        }
        if header.hlen < 6 {
            return false;
        }
        if header.chaddr[0..6] != *self.mac_address.as_bytes() {
            return false;
        }
        data[DhcpHeader::SIZE..DhcpHeader::SIZE + 4] == DHCP_MAGIC_COOKIE
    }

    pub fn matches_response_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> bool {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        if view.total_len() < DhcpHeader::SIZE + 4 {
            return false;
        }
        let Some(header_bytes) = view.read_array::<{ DhcpHeader::SIZE }>(0) else {
            return false;
        };
        let Some(header) = DhcpHeader::decode_from(&header_bytes) else {
            return false;
        };
        if header.op != DhcpOperation::Reply as u8 {
            return false;
        }
        if header.xid() != self.xid.load(Ordering::SeqCst) {
            return false;
        }
        if header.hlen < 6 {
            return false;
        }
        if header.chaddr[0..6] != *self.mac_address.as_bytes() {
            return false;
        }
        view.read_array::<4>(DhcpHeader::SIZE) == Some(DHCP_MAGIC_COOKIE)
    }

    /// DHCPDISCOVER メッセージを構築
    pub fn build_discover(
        &self,
        buffer: &mut [u8],
        current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DHCP_MAX_MESSAGE_SIZE {
            return Err("Buffer too small (need DHCP_MAX_MESSAGE_SIZE)");
        }

        // Acquire state and only generate a new XID when starting a new discovery
        let mut state_guard = match self.state.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (build_discover) - aborting");
                return Err("State lock poisoned");
            }
        };

        if *state_guard == DhcpState::Init {
            // Use cryptographically secure random value for XID to prevent spoofing
            let random_bytes = crate::net::security::tls::crypto::random::generate_random();
            let xid = u32::from_be_bytes([
                random_bytes[0],
                random_bytes[1],
                random_bytes[2],
                random_bytes[3],
            ]);
            self.xid.store(xid, Ordering::SeqCst);
        }
        let xid = self.xid.load(Ordering::SeqCst);

        // ヘッダを構築 (236 bytes)
        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
        buffer[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
        // ciaddr, yiaddr, siaddr, giaddr = 0
        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        // オプション開始 (Magic Cookie 4 bytes)
        let mut offset = DhcpHeader::SIZE;
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // Helper to safely append options
        let mut append_opt = |opt: u8, data: &[u8]| -> Result<(), &'static str> {
            if data.len() > 255 {
                return Err("DHCP option length exceeds 255 bytes");
            }
            if offset + 2 + data.len() > buffer.len() {
                return Err("Buffer overflow during option writing");
            }
            buffer[offset] = opt;
            buffer[offset + 1] = data.len() as u8;
            buffer[offset + 2..offset + 2 + data.len()].copy_from_slice(data);
            offset += 2 + data.len();
            Ok(())
        };

        // メッセージタイプ: DISCOVER
        append_opt(
            DhcpOption::MessageType as u8,
            &[DhcpMessageType::Discover as u8],
        )?;

        // パラメータ要求リスト
        append_opt(
            DhcpOption::ParameterRequestList as u8,
            &[
                DhcpOption::SubnetMask as u8,
                DhcpOption::Router as u8,
                DhcpOption::DnsServer as u8,
                DhcpOption::DomainName as u8,
                DhcpOption::LeaseTime as u8,
                DhcpOption::ServerIdentifier as u8,
                DhcpOption::RenewalTime as u8,
                DhcpOption::RebindingTime as u8,
            ],
        )?;

        // クライアント識別子
        let mut client_id = [0u8; 7];
        client_id[0] = 1; // Ethernet
        client_id[1..7].copy_from_slice(self.mac_address.as_bytes());
        append_opt(DhcpOption::ClientIdentifier as u8, &client_id)?;

        // 最大メッセージサイズ (Option 57)
        let max_size = (DHCP_MAX_MESSAGE_SIZE as u16).to_be_bytes();
        append_opt(DhcpOption::MaximumMessageSize as u8, &max_size)?;

        // ホスト名 (Option 12)
        append_opt(DhcpOption::Hostname as u8, b"ranyos")?;

        // 終端
        if offset >= buffer.len() {
            return Err("Buffer overflow at End option");
        }
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        // 状態を更新
        *state_guard = DhcpState::Selecting;
        drop(state_guard);

        self.state_time.store(current_tick, Ordering::SeqCst);
        Ok(offset)
    }

    /// DHCPREQUEST メッセージを構築
    pub fn build_request(
        &self,
        buffer: &mut [u8],
        current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DHCP_MAX_MESSAGE_SIZE {
            return Err("Buffer too small (need DHCP_MAX_MESSAGE_SIZE)");
        }

        let current_state = self.lock_dhcp_state()?;
        let (lease, is_renew_or_rebind) = self.get_lease_for_request(current_state)?;

        let xid = self.xid.load(Ordering::SeqCst);

        // ヘッダを構築
        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs

        // Flags: unicast for renewing, broadcast for rebinding and normal REQUEST
        let flags: u16 = if current_state == DhcpState::Renewing {
            0
        } else {
            0x8000
        };
        buffer[10..12].copy_from_slice(&flags.to_be_bytes());

        // ciaddr must be set for renewals and rebinding; cleared for new requests (RFC 2131 Table 5)
        if is_renew_or_rebind {
            buffer[12..16].copy_from_slice(lease.ip_address.as_bytes());
        } else {
            buffer[12..16].fill(0);
        }

        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        // オプション書き込み
        // マジッククッキー
        let mut offset = DhcpHeader::SIZE;
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // Helper to safely append options
        let mut append_opt = |opt: u8, data: &[u8]| -> Result<(), &'static str> {
            if data.len() > 255 {
                return Err("DHCP option length exceeds 255 bytes");
            }
            if offset + 2 + data.len() > buffer.len() {
                return Err("Buffer overflow during option writing");
            }
            buffer[offset] = opt;
            buffer[offset + 1] = data.len() as u8;
            buffer[offset + 2..offset + 2 + data.len()].copy_from_slice(data);
            offset += 2 + data.len();
            Ok(())
        };

        // メッセージタイプ: REQUEST
        append_opt(
            DhcpOption::MessageType as u8,
            &[DhcpMessageType::Request as u8],
        )?;

        // RFC 2131 Section 4.3.2: omit ServerIdentifier and RequestedIp during RENEWING/REBINDING
        if !is_renew_or_rebind {
            append_opt(DhcpOption::RequestedIp as u8, lease.ip_address.as_bytes())?;
            append_opt(
                DhcpOption::ServerIdentifier as u8,
                lease.server_ip.as_bytes(),
            )?;
        }

        append_opt(
            DhcpOption::ParameterRequestList as u8,
            &[
                DhcpOption::SubnetMask as u8,
                DhcpOption::Router as u8,
                DhcpOption::DnsServer as u8,
                DhcpOption::DomainName as u8,
                DhcpOption::LeaseTime as u8,
                DhcpOption::ServerIdentifier as u8,
                DhcpOption::RenewalTime as u8,
                DhcpOption::RebindingTime as u8,
            ],
        )?;

        let mut client_id = [0u8; 7];
        client_id[0] = 1; // Ethernet
        client_id[1..7].copy_from_slice(self.mac_address.as_bytes());
        append_opt(DhcpOption::ClientIdentifier as u8, &client_id)?;

        // 最大メッセージサイズ (Option 57)
        let max_size = (DHCP_MAX_MESSAGE_SIZE as u16).to_be_bytes();
        append_opt(DhcpOption::MaximumMessageSize as u8, &max_size)?;

        if offset >= buffer.len() {
            return Err("Buffer overflow at End option");
        }
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        self.state_time.store(current_tick, Ordering::SeqCst);
        Ok(offset)
    }

    /// DHCPINFORM メッセージを構築
    pub fn build_inform(
        &self,
        buffer: &mut [u8],
        current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DHCP_MAX_MESSAGE_SIZE {
            return Err("Buffer too small (need DHCP_MAX_MESSAGE_SIZE)");
        }

        let lease = self.get_active_lease()?;

        // INFORM は既存トランザクションと独立した新規XIDを使用する
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        let xid = u32::from_be_bytes([
            random_bytes[0],
            random_bytes[1],
            random_bytes[2],
            random_bytes[3],
        ]);
        self.xid.store(xid, Ordering::SeqCst);

        // ヘッダを構築
        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
        buffer[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast

        // INFORM では ciaddr に既存クライアントIPを設定する
        buffer[12..16].copy_from_slice(lease.ip_address.as_bytes());
        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        // オプション書き込み
        let mut offset = DhcpHeader::SIZE;
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // Helper to safely append options
        let mut append_opt = |opt: u8, data: &[u8]| -> Result<(), &'static str> {
            if data.len() > 255 {
                return Err("DHCP option length exceeds 255 bytes");
            }
            if offset + 2 + data.len() > buffer.len() {
                return Err("Buffer overflow during option writing");
            }
            buffer[offset] = opt;
            buffer[offset + 1] = data.len() as u8;
            buffer[offset + 2..offset + 2 + data.len()].copy_from_slice(data);
            offset += 2 + data.len();
            Ok(())
        };

        // メッセージタイプ: INFORM
        append_opt(
            DhcpOption::MessageType as u8,
            &[DhcpMessageType::Inform as u8],
        )?;

        // パラメータ要求リスト
        append_opt(
            DhcpOption::ParameterRequestList as u8,
            &[
                DhcpOption::SubnetMask as u8,
                DhcpOption::Router as u8,
                DhcpOption::DnsServer as u8,
                DhcpOption::DomainName as u8,
                DhcpOption::Hostname as u8,
            ],
        )?;

        // クライアント識別子
        let mut client_id = [0u8; 7];
        client_id[0] = 1; // Ethernet
        client_id[1..7].copy_from_slice(self.mac_address.as_bytes());
        append_opt(DhcpOption::ClientIdentifier as u8, &client_id)?;

        // 最大メッセージサイズ (Option 57)
        let max_size = (DHCP_MAX_MESSAGE_SIZE as u16).to_be_bytes();
        append_opt(DhcpOption::MaximumMessageSize as u8, &max_size)?;

        // ホスト名 (Option 12)
        append_opt(DhcpOption::Hostname as u8, b"ranyos")?;

        if offset >= buffer.len() {
            return Err("Buffer overflow at End option");
        }
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        self.state_time.store(current_tick, Ordering::SeqCst);
        Ok(offset)
    }

    // ── Helper: parse a 4-byte IPv4 address from an option value ──
    pub(super) fn parse_ipv4_option(opt_data: &[u8]) -> Option<Ipv4Address> {
        if opt_data.len() >= 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&opt_data[..4]);
            Some(Ipv4Address::new(bytes))
        } else {
            None
        }
    }

    // ── Helper: parse a 4-byte big-endian u32 from an option value ──
    pub(super) fn parse_u32_option(opt_data: &[u8]) -> Option<u32> {
        if opt_data.len() >= 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&opt_data[..4]);
            Some(u32::from_be_bytes(bytes))
        } else {
            None
        }
    }

    pub(super) fn parse_ipv4_option_ref(
        opt_data: crate::net::payload::PayloadSpanRef<'_>,
    ) -> Option<Ipv4Address> {
        if opt_data.total_len() != 4 {
            return None;
        }
        let bytes = opt_data.read_array::<4>(0)?;
        Some(Ipv4Address::new(bytes))
    }

    pub(super) fn parse_u32_option_ref(
        opt_data: crate::net::payload::PayloadSpanRef<'_>,
    ) -> Option<u32> {
        if opt_data.total_len() != 4 {
            return None;
        }
        let bytes = opt_data.read_array::<4>(0)?;
        Some(u32::from_be_bytes(bytes))
    }

    /// ヘッダを検証し、参照を返す
    pub(super) fn validate_header<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<&'a DhcpHeader, &'static str> {
        if data.len() < DhcpHeader::SIZE + 4 {
            return Err("Packet too small");
        }

        let header =
            crate::util::get_ref::<DhcpHeader>(data, 0).ok_or("Dhcp header slice out of bounds")?;

        if header.xid() != self.xid.load(Ordering::SeqCst) {
            return Err("Transaction ID mismatch");
        }

        if header.op != DhcpOperation::Reply as u8 {
            return Err("Not a DHCP reply");
        }

        let hlen = header.hlen as usize;
        if hlen < 6 {
            log::warn!("[NET] DHCP header hlen ({}) too small - rejecting", hlen);
            return Err("Invalid hardware address length in DHCP header");
        }
        {
            let mut mac_bytes = [0u8; 6];
            mac_bytes.copy_from_slice(&header.chaddr[0..6]);
            if mac_bytes != *self.mac_address.as_bytes() {
                log::warn!(
                    "[NET] DHCP CHADDR does not match client MAC - rejecting (chaddr={:?} expected={:?})",
                    &header.chaddr[0..6],
                    self.mac_address.as_bytes()
                );
                return Err("CHADDR does not match client MAC");
            }
        }

        let options_start = DhcpHeader::SIZE;
        if data[options_start..options_start + 4] != DHCP_MAGIC_COOKIE {
            return Err("Invalid magic cookie");
        }

        Ok(header)
    }

    pub(super) fn validate_header_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> Result<DhcpHeader, &'static str> {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        if view.total_len() < DhcpHeader::SIZE + 4 {
            return Err("Packet too small");
        }
        let header_bytes = view
            .read_array::<{ DhcpHeader::SIZE }>(0)
            .ok_or("Dhcp header slice out of bounds")?;
        let header = DhcpHeader::decode_from(&header_bytes).ok_or("Dhcp header decode failed")?;

        if header.xid() != self.xid.load(Ordering::SeqCst) {
            return Err("Transaction ID mismatch");
        }

        if header.op != DhcpOperation::Reply as u8 {
            return Err("Not a DHCP reply");
        }

        let hlen = header.hlen as usize;
        if hlen < 6 {
            log::warn!("[NET] DHCP header hlen ({}) too small - rejecting", hlen);
            return Err("Invalid hardware address length in DHCP header");
        }

        if header.chaddr[0..6] != *self.mac_address.as_bytes() {
            log::warn!(
                "[NET] DHCP CHADDR does not match client MAC - rejecting (chaddr={:?} expected={:?})",
                &header.chaddr[0..6],
                self.mac_address.as_bytes()
            );
            return Err("CHADDR does not match client MAC");
        }

        if view.read_array::<4>(DhcpHeader::SIZE) != Some(DHCP_MAGIC_COOKIE) {
            return Err("Invalid magic cookie");
        }

        Ok(header)
    }

    pub(super) fn apply_option_span_ref(
        opts: &mut ParsedOptions,
        opt: u8,
        opt_data: crate::net::payload::PayloadSpanRef<'_>,
    ) {
        match opt {
            53 => {
                if let Some(value) = opt_data.byte_at(0) {
                    opts.message_type = DhcpMessageType::from_u8(value);
                }
            }
            1 => opts.subnet_mask = Self::parse_ipv4_option_ref(opt_data),
            3 => opts.router = Self::parse_ipv4_option_ref(opt_data),
            6 => {
                let server_count = opt_data.total_len() / 4;
                for index in 0..server_count {
                    if opts.dns_servers.len() >= 8 {
                        break;
                    }
                    let Some(chunk) = opt_data.slice(index * 4, 4) else {
                        break;
                    };
                    let Some(bytes) = chunk.read_array::<4>(0) else {
                        break;
                    };
                    opts.dns_servers.push(Ipv4Address::new(bytes));
                }
            }
            51 => {
                if let Some(value) = Self::parse_u32_option_ref(opt_data) {
                    opts.lease_time = value;
                }
            }
            58 => opts.renewal_time = Self::parse_u32_option_ref(opt_data),
            59 => opts.rebinding_time = Self::parse_u32_option_ref(opt_data),
            54 => opts.server_id = Self::parse_ipv4_option_ref(opt_data),
            12 => opts.hostname = Some(opt_data.range()),
            15 => opts.domain_name = Some(opt_data.range()),
            _ => {}
        }
    }

    /// オプション領域を解析して ParsedOptions を返す
    pub(super) fn parse_options(data: &[u8]) -> ParsedOptions {
        let mut opts = ParsedOptions {
            message_type: None,
            subnet_mask: None,
            router: None,
            dns_servers: Vec::new(),
            lease_time: 86400u32, // デフォルト1日
            renewal_time: None,
            rebinding_time: None,
            server_id: None,
            metadata_payload: None,
            hostname: None,
            domain_name: None,
        };

        let mut offset = DhcpHeader::SIZE + 4;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset < data.len() {
            let opt = data[offset];

            if opt == DhcpOption::Pad as u8 {
                offset += 1;
                continue;
            }

            if opt == DhcpOption::End as u8 {
                break;
            }

            if offset + 1 >= data.len() {
                break;
            }

            let len = data[offset + 1] as usize;
            if offset + 2 + len > data.len() {
                log::warn!(
                    "[NET] DHCP option length {} at offset {} overruns packet (len {}) - stopping parse",
                    len,
                    offset,
                    data.len()
                );
                break;
            }

            let opt_data = &data[offset + 2..offset + 2 + len];
            match opt {
                53 => {
                    if let Some(value) = opt_data.first() {
                        opts.message_type = DhcpMessageType::from_u8(*value);
                    }
                }
                1 => opts.subnet_mask = Self::parse_ipv4_option(opt_data),
                3 => opts.router = Self::parse_ipv4_option(opt_data),
                6 => {
                    for chunk in opt_data
                        .chunks_exact(4)
                        .take(8usize.saturating_sub(opts.dns_servers.len()))
                    {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(chunk);
                        opts.dns_servers.push(Ipv4Address::new(bytes));
                    }
                }
                51 => {
                    if let Some(value) = Self::parse_u32_option(opt_data) {
                        opts.lease_time = value;
                    }
                }
                58 => opts.renewal_time = Self::parse_u32_option(opt_data),
                59 => opts.rebinding_time = Self::parse_u32_option(opt_data),
                54 => opts.server_id = Self::parse_ipv4_option(opt_data),
                12 => {}
                15 => {}
                _ => {}
            }
            offset += 2 + len;
        }

        opts
    }

    pub(super) fn parse_options_payload(
        payload: kernel_api::resource::net::PacketPayload,
    ) -> ParsedOptions {
        let view = crate::net::payload::PacketPayloadView::new(&payload);
        let mut opts = ParsedOptions {
            message_type: None,
            subnet_mask: None,
            router: None,
            dns_servers: Vec::new(),
            lease_time: 86400u32,
            renewal_time: None,
            rebinding_time: None,
            server_id: None,
            metadata_payload: None,
            hostname: None,
            domain_name: None,
        };

        let mut offset = DhcpHeader::SIZE + 4;
        while offset < view.total_len() {
            let Some(opt) = view.read_array::<1>(offset).map(|bytes| bytes[0]) else {
                break;
            };

            if opt == DhcpOption::Pad as u8 {
                offset += 1;
                continue;
            }
            if opt == DhcpOption::End as u8 {
                break;
            }
            if offset + 1 >= view.total_len() {
                break;
            }

            let Some(len) = view
                .read_array::<1>(offset + 1)
                .map(|bytes| bytes[0] as usize)
            else {
                break;
            };
            if offset + 2 + len > view.total_len() {
                log::warn!(
                    "[NET] DHCP option length {} at offset {} overruns packet (len {}) - stopping parse",
                    len,
                    offset,
                    view.total_len()
                );
                break;
            }

            let Some(opt_data) =
                crate::net::payload::PayloadSpanRef::from_range(&payload, offset + 2, len)
            else {
                break;
            };
            Self::apply_option_span_ref(&mut opts, opt, opt_data);
            offset += 2 + len;
        }

        opts.metadata_payload = Some(payload);

        opts
    }

    /// ACK を Requesting 状態で検証する
    pub(super) fn validate_ack_requesting(
        &self,
        server_id: Ipv4Address,
        yiaddr: Ipv4Address,
    ) -> Result<(), &'static str> {
        match self.offered_lease.lock() {
            Ok(off) => {
                let offered = off.as_ref().ok_or("No offer for ACK")?;
                if offered.server_ip != server_id {
                    return Err("ACK server identifier does not match offered server");
                }
                if offered.ip_address != yiaddr {
                    return Err("ACK yiaddr does not match offered IP");
                }
                Ok(())
            }
            Err(_) => {
                log::error!(
                    "[NET] DHCP Offer lock poisoned (process_response Ack) - cannot verify ACK"
                );
                Err("Offer lock poisoned")
            }
        }
    }

    /// ACK を Renewing/Rebinding 状態で検証する
    pub(super) fn validate_ack_renewing(
        &self,
        server_id: Ipv4Address,
        yiaddr: Ipv4Address,
    ) -> Result<(), &'static str> {
        match self.lease.lock() {
            Ok(l) => {
                let lease_guard = l.as_ref().ok_or("No active lease for ACK")?;
                if lease_guard.server_ip != server_id {
                    return Err("ACK server identifier does not match bound server");
                }
                if lease_guard.ip_address != yiaddr {
                    return Err("ACK yiaddr does not match bound IP");
                }
                Ok(())
            }
            Err(_) => {
                log::error!(
                    "[NET] DHCP Lease lock poisoned (process_response Ack) - cannot verify ACK"
                );
                Err("Lease lock poisoned")
            }
        }
    }

    /// ACK を Informing 状態で検証する
    pub(super) fn validate_ack_informing(
        &self,
        server_id: Ipv4Address,
        yiaddr: Ipv4Address,
    ) -> Result<(), &'static str> {
        let zero = Ipv4Address::new([0, 0, 0, 0]);
        match self.lease.lock() {
            Ok(l) => {
                let lease_guard = l.as_ref().ok_or("No active lease for INFORM ACK")?;
                if lease_guard.server_ip != zero && lease_guard.server_ip != server_id {
                    return Err("ACK server identifier does not match bound server");
                }
                if yiaddr != zero && yiaddr != lease_guard.ip_address {
                    return Err("ACK yiaddr does not match bound IP");
                }
                Ok(())
            }
            Err(_) => {
                log::error!(
                    "[NET] DHCP Lease lock poisoned (process_response Inform Ack) - cannot verify ACK"
                );
                Err("Lease lock poisoned")
            }
        }
    }

    /// OFFER の既存オファーとの整合性を検証する
    pub(super) fn validate_offer_server(&self, server_id: Ipv4Address) -> Result<(), &'static str> {
        match self.offered_lease.lock() {
            Ok(off) => {
                if let Some(ref o) = *off {
                    if o.server_ip != server_id {
                        return Err("Offer server identifier does not match existing offer");
                    }
                }
                Ok(())
            }
            Err(_) => {
                log::error!(
                    "[NET] DHCP Offer lock poisoned (process_response Offer) - cannot verify offer"
                );
                Err("Offer lock poisoned")
            }
        }
    }

    /// ACK の状態依存検証を実行する
    pub(super) fn validate_ack_state(
        &self,
        current_state: DhcpState,
        server_id: Ipv4Address,
        yiaddr: Ipv4Address,
    ) -> Result<(), &'static str> {
        match current_state {
            DhcpState::Requesting => self.validate_ack_requesting(server_id, yiaddr),
            DhcpState::Renewing | DhcpState::Rebinding => {
                self.validate_ack_renewing(server_id, yiaddr)
            }
            DhcpState::Informing => self.validate_ack_informing(server_id, yiaddr),
            _ => Ok(()),
        }
    }

    /// OFFER / ACK の整合性を検証する
    pub(super) fn validate_offer_ack(
        &self,
        msg_type: DhcpMessageType,
        header: &DhcpHeader,
        server_id: Ipv4Address,
    ) -> Result<(), &'static str> {
        let current_state = match self.state.lock() {
            Ok(g) => *g,
            Err(_) => {
                log::error!(
                    "[NET] DHCP State lock poisoned (process_response) - cannot verify response"
                );
                return Err("State lock poisoned");
            }
        };

        if msg_type == DhcpMessageType::Offer && header.yiaddr() == Ipv4Address::new([0, 0, 0, 0]) {
            return Err("Missing yiaddr in Offer");
        }
        if msg_type == DhcpMessageType::Ack
            && current_state != DhcpState::Informing
            && header.yiaddr() == Ipv4Address::new([0, 0, 0, 0])
        {
            return Err("Missing yiaddr in Ack");
        }

        if msg_type == DhcpMessageType::Offer {
            self.validate_offer_server(server_id)
        } else {
            self.validate_ack_state(current_state, server_id, header.yiaddr())
        }
    }

    /// ParsedOptions と DhcpHeader からリース情報を構築する
    pub(super) fn build_lease(
        header: &DhcpHeader,
        opts: &ParsedOptions,
        current_tick: u64,
    ) -> DhcpLease {
        let t1 = opts.renewal_time.unwrap_or(opts.lease_time / 2);
        // Promote to u64 before multiplying so large lease times do not panic in debug builds.
        let t2 = opts
            .rebinding_time
            .unwrap_or(((opts.lease_time as u64 * 7) / 8) as u32);

        DhcpLease {
            ip_address: header.yiaddr(),
            subnet_mask: opts
                .subnet_mask
                .unwrap_or(Ipv4Address::new([255, 255, 255, 0])),
            gateway: opts.router,
            server_ip: opts.server_id.unwrap_or(header.siaddr()),
            lease_time: opts.lease_time,
            t1,
            t2,
            obtained_at: current_tick,
        }
    }

    /// ACK 受信時の状態に応じてリースを構築する
    pub(super) fn build_ack_lease(
        &self,
        current_state: DhcpState,
        header: &DhcpHeader,
        opts: &ParsedOptions,
        current_tick: u64,
    ) -> Result<DhcpLease, &'static str> {
        if current_state != DhcpState::Informing {
            return Ok(Self::build_lease(header, opts, current_tick));
        }

        let prev = self.get_active_lease()?;
        let zero = Ipv4Address::new([0, 0, 0, 0]);

        let ParsedOptions {
            subnet_mask,
            router,
            server_id,
            ..
        } = opts;

        let yiaddr = header.yiaddr();
        let ip_address = if yiaddr == zero {
            prev.ip_address
        } else {
            yiaddr
        };

        Ok(DhcpLease {
            ip_address,
            subnet_mask: subnet_mask.unwrap_or(prev.subnet_mask),
            gateway: router.or(prev.gateway),
            server_ip: server_id.unwrap_or(prev.server_ip),
            // INFORM はアドレス割当更新ではないため既存のリースタイマを維持する
            lease_time: prev.lease_time,
            t1: prev.t1,
            t2: prev.t2,
            obtained_at: prev.obtained_at,
        })
    }
}
