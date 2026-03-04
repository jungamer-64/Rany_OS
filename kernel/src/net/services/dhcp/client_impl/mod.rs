use super::*;
use crate::task::{self, TimeoutResult};

mod offer_handling;
impl DhcpClient {
    /// 最大再試行回数
    pub const MAX_RETRIES: u32 = 4;

    /// ARP probe waiting time (seconds)
    pub(super) const PROBE_WAIT_SECS: u64 = 1;

    /// Default retry interval used for retransmits (seconds)
    pub(super) const RETRY_INTERVAL_SECS: u64 = 4; 

    /// 新しいDHCPクライアントを作成
    pub fn new(mac_address: MacAddress) -> Self {
        Self {
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
        let socket = crate::net::runtime::stack::bind_udp_endpoint_async(DHCP_CLIENT_PORT).await.ok_or("Failed to bind DHCP socket")?;
        
        log::info!("[NET] DHCPv4 client task started");

        let mut loop_count: u64 = 0;
        loop {
            let now = crate::task::timer::current_tick();
            loop_count += 1;
            if loop_count <= 10 || loop_count % 10 == 0 {
                log::info!("[NET] DHCP loop #{} state={:?} tick={}", loop_count, self.state(), now);
            }
            
            // 状態機械を駆動（タイムアウトチェックと必要に応じたパケット送信）
            match self.drive(now, 1000) {
                Ok(()) => {}
                Err(e) => {
                    log::error!("[NET] DHCP drive() error: {} (state={:?}, tick={})", e, self.state(), now);
                    return Err(e);
                }
            }
            
            // パケット受信を待機。再送タイマーを考慮して1秒でタイムアウト。
            match task::with_timeout(socket.recv(), 1000).await {
                TimeoutResult::Completed(Some((_src, _ttl, packet))) => {
                    let now = crate::task::timer::current_tick();
                    log::info!("[NET] DHCP recv: got packet len={}", packet.data().len());
                    // 応答パケットを処理
                    match self.process_response(packet.data(), now) {
                        Ok(DhcpResponseResult::Ack(lease)) => {
                            log::info!("[NET] DHCPv4 ACK received: {:?}", lease.ip_address);
                            // リースをイベントキュー経由でスタックに適用（デッドロック回避）
                            let hostname_bytes = lease.hostname.clone().unwrap_or_default();
                            crate::net::l4::endpoint::event::send_event_ignore(
                                crate::net::l4::endpoint::event::NetworkEvent::AsyncDhcpApplyLease {
                                    ip: *lease.ip_address.as_bytes(),
                                    subnet: *lease.subnet_mask.as_bytes(),
                                    gateway: lease.gateway.map(|a| *a.as_bytes()).unwrap_or([0, 0, 0, 0]),
                                    dns: lease.dns_servers.first().map(|a| *a.as_bytes()).unwrap_or([0, 0, 0, 0]),
                                    hostname: hostname_bytes,
                                },
                            );
                            // mDNS のローカル IP を更新
                            if let Ok(mut guard) = crate::net::services::mdns::service().lock() {
                                if let Some(ref mut mdns) = *guard {
                                    mdns.set_local_ip(lease.ip_address);
                                }
                            }
                        }
                        Ok(DhcpResponseResult::Offer(lease)) => {
                            log::info!("[NET] DHCPv4 OFFER received: {:?} from {:?}", lease.ip_address, lease.server_ip);
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
                    log::info!("[NET] DHCP recv timeout (tick={})", crate::task::timer::current_tick());
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
            let lease_opt = match self.lease.lock() {
                Ok(g) => g.clone(),
                Err(_) => return Err("Lease lock poisoned"),
            };
            if let Some(l) = lease_opt {
                let is_renewal = current_state == DhcpState::Renewing;
                Ok((l, is_renewal))
            } else {
                Err("No active lease available")
            }
        } else {
            // not bound yet; use offered_lease
            let offer_opt = match self.offered_lease.lock() {
                Ok(g) => g.clone(),
                Err(_) => return Err("Offer lock poisoned"),
            };
            if let Some(l) = offer_opt {
                Ok((l, false))
            } else {
                Err("No offered lease available")
            }
        }
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
            let xid = u32::from_be_bytes([random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3]]);
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
        append_opt(DhcpOption::MessageType as u8, &[DhcpMessageType::Discover as u8])?;

        // パラメータ要求リスト
        append_opt(DhcpOption::ParameterRequestList as u8, &[
            DhcpOption::SubnetMask as u8,
            DhcpOption::Router as u8,
            DhcpOption::DnsServer as u8,
            DhcpOption::DomainName as u8,
            DhcpOption::LeaseTime as u8,
            DhcpOption::ServerIdentifier as u8,
            DhcpOption::RenewalTime as u8,
            DhcpOption::RebindingTime as u8,
        ])?;

        // クライアント識別子
        let mut client_id = [0u8; 7];
        client_id[0] = 1; // Ethernet
        client_id[1..7].copy_from_slice(self.mac_address.as_bytes());
        append_opt(DhcpOption::ClientIdentifier as u8, &client_id)?;

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
        let (lease, is_renewal) = self.get_lease_for_request(current_state)?;

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
        let flags: u16 = if current_state == DhcpState::Renewing { 0 } else { 0x8000 };
        buffer[10..12].copy_from_slice(&flags.to_be_bytes());

        // ciaddr must be set for renewals; cleared for new requests
        if is_renewal {
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
        append_opt(DhcpOption::MessageType as u8, &[DhcpMessageType::Request as u8])?;

        if !is_renewal {
            append_opt(DhcpOption::RequestedIp as u8, lease.ip_address.as_bytes())?;
            append_opt(DhcpOption::ServerIdentifier as u8, lease.server_ip.as_bytes())?;
        }

        append_opt(DhcpOption::ParameterRequestList as u8, &[
            DhcpOption::SubnetMask as u8,
            DhcpOption::Router as u8,
            DhcpOption::DnsServer as u8,
            DhcpOption::DomainName as u8,
            DhcpOption::LeaseTime as u8,
            DhcpOption::ServerIdentifier as u8,
            DhcpOption::RenewalTime as u8,
            DhcpOption::RebindingTime as u8,
        ])?;

        let mut client_id = [0u8; 7];
        client_id[0] = 1; // Ethernet
        client_id[1..7].copy_from_slice(self.mac_address.as_bytes());
        append_opt(DhcpOption::ClientIdentifier as u8, &client_id)?;

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

    /// ヘッダを検証し、参照を返す
    pub(super) fn validate_header<'a>(&self, data: &'a [u8]) -> Result<&'a DhcpHeader, &'static str> {
        if data.len() < DhcpHeader::SIZE + 4 {
            return Err("Packet too small");
        }

        let header =
            crate::util::get_ref::<DhcpHeader>(data, 0).expect("Dhcp header slice out of bounds");

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
                log::warn!("[NET] DHCP CHADDR does not match client MAC - rejecting (chaddr={:?} expected={:?})", &header.chaddr[0..6], self.mac_address.as_bytes());
                return Err("CHADDR does not match client MAC");
            }
        }

        let options_start = DhcpHeader::SIZE;
        if data[options_start..options_start + 4] != DHCP_MAGIC_COOKIE {
            return Err("Invalid magic cookie");
        }

        Ok(header)
    }

    /// 単一のDHCPオプションを ParsedOptions に適用する
    pub(super) fn apply_option(opts: &mut ParsedOptions, opt: u8, opt_data: &[u8]) {
        match opt {
            53 => {
                if !opt_data.is_empty() {
                    opts.message_type = DhcpMessageType::from_u8(opt_data[0]);
                }
            }
            1 => opts.subnet_mask = Self::parse_ipv4_option(opt_data),
            3 => opts.router = Self::parse_ipv4_option(opt_data),
            6 => {
                // Limit the number of DNS servers to prevent memory exhaustion
                for chunk in opt_data.chunks(4) {
                    if chunk.len() == 4 && opts.dns_servers.len() < 8 {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(chunk);
                        opts.dns_servers.push(Ipv4Address::new(bytes));
                    }
                }
            }
            51 => {
                if let Some(v) = Self::parse_u32_option(opt_data) {
                    opts.lease_time = v;
                }
            }
            58 => opts.renewal_time = Self::parse_u32_option(opt_data),
            59 => opts.rebinding_time = Self::parse_u32_option(opt_data),
            54 => opts.server_id = Self::parse_ipv4_option(opt_data),
            12 => opts.hostname = Some(opt_data.to_vec()),
            15 => opts.domain_name = Some(opt_data.to_vec()),
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
            hostname: None,
            domain_name: None,
        };

        let mut offset = DhcpHeader::SIZE + 4;
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
                log::warn!("[NET] DHCP option length {} at offset {} overruns packet (len {}) - stopping parse", len, offset, data.len());
                break;
            }

            Self::apply_option(&mut opts, opt, &data[offset + 2..offset + 2 + len]);
            offset += 2 + len;
        }

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
                log::error!("[NET] DHCP Offer lock poisoned (process_response Ack) - cannot verify ACK");
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
                log::error!("[NET] DHCP Lease lock poisoned (process_response Ack) - cannot verify ACK");
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
                log::error!("[NET] DHCP Offer lock poisoned (process_response Offer) - cannot verify offer");
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
        let siaddr = header.siaddr();
        if siaddr != Ipv4Address::new([0, 0, 0, 0]) && siaddr != server_id {
            log::warn!("[NET] DHCP server identifier ({:?}) and siaddr ({:?}) mismatch", server_id, siaddr);
            return Err("Server identifier mismatch");
        }

        if header.yiaddr() == Ipv4Address::new([0, 0, 0, 0]) {
            return Err("Missing yiaddr in Offer/Ack");
        }

        let current_state = match self.state.lock() {
            Ok(g) => *g,
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (process_response) - cannot verify response");
                return Err("State lock poisoned");
            }
        };

        if msg_type == DhcpMessageType::Offer {
            self.validate_offer_server(server_id)
        } else {
            self.validate_ack_state(current_state, server_id, header.yiaddr())
        }
    }

    /// ParsedOptions と DhcpHeader からリース情報を構築する
    pub(super) fn build_lease(header: &DhcpHeader, opts: ParsedOptions, current_tick: u64) -> DhcpLease {
        let t1 = opts.renewal_time.unwrap_or(opts.lease_time / 2);
        let t2 = opts.rebinding_time.unwrap_or((opts.lease_time * 7) / 8);

        DhcpLease {
            ip_address: header.yiaddr(),
            subnet_mask: opts.subnet_mask.unwrap_or(Ipv4Address::new([255, 255, 255, 0])),
            gateway: opts.router,
            dns_servers: opts.dns_servers,
            server_ip: opts.server_id.unwrap_or(header.siaddr()),
            lease_time: opts.lease_time,
            t1,
            t2,
            obtained_at: current_tick,
            hostname: opts.hostname,
            domain_name: opts.domain_name,
        }
    }
}

/// DHCP応答処理結果
#[derive(Debug)]
pub enum DhcpResponseResult {
    /// OFFERを受信
    Offer(DhcpLease),
    /// ACKを受信 (リース取得成功)
    Ack(DhcpLease),
    /// NAKを受信 (リース取得失敗)
    Nak,
}

/// グローバルDHCPクライアント
pub(crate) static DHCP_CLIENT: PoisonLock<Option<DhcpClient>> = PoisonLock::new(None);

/// DHCPクライアントを初期化
pub fn init(mac_address: MacAddress) {
    let client = DhcpClient::new(mac_address);
    match DHCP_CLIENT.lock() {
        Ok(mut g) => *g = Some(client),
        Err(_) => log::error!("[NET] DHCP Global lock poisoned (init) - initialization skipped"),
    }
}

/// DHCPクライアントを取得
pub fn client() -> Option<&'static PoisonLock<Option<DhcpClient>>> {
    Some(&DHCP_CLIENT)
}



