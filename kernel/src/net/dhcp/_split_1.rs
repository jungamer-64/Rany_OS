use super::*;


mod _split_1;
pub use _split_1::*;
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
        if buffer.len() < DhcpHeader::SIZE + 64 {
            return Err("Buffer too small");
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
            let xid = (current_tick as u32) ^ 0xDEADBEEF;
            self.xid.store(xid, Ordering::SeqCst);
        }
        let xid = self.xid.load(Ordering::SeqCst);

        // ヘッダを構築
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

        // オプション開始
        let mut offset = DhcpHeader::SIZE;

        // マジッククッキー
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // メッセージタイプ: DISCOVER
        buffer[offset] = DhcpOption::MessageType as u8;
        buffer[offset + 1] = 1;
        buffer[offset + 2] = DhcpMessageType::Discover as u8;
        offset += 3;

        // パラメータ要求リスト (SubnetMask, Router, DNS, DomainName, LeaseTime, ServerIdentifier, Renewal (T1), Rebinding (T2))
        buffer[offset] = DhcpOption::ParameterRequestList as u8;
        buffer[offset + 1] = 8;
        buffer[offset + 2] = DhcpOption::SubnetMask as u8;
        buffer[offset + 3] = DhcpOption::Router as u8;
        buffer[offset + 4] = DhcpOption::DnsServer as u8;
        buffer[offset + 5] = DhcpOption::DomainName as u8;
        buffer[offset + 6] = DhcpOption::LeaseTime as u8;
        buffer[offset + 7] = DhcpOption::ServerIdentifier as u8;
        buffer[offset + 8] = DhcpOption::RenewalTime as u8;
        buffer[offset + 9] = DhcpOption::RebindingTime as u8;
        offset += 10;

        // クライアント識別子
        buffer[offset] = DhcpOption::ClientIdentifier as u8;
        buffer[offset + 1] = 7;
        buffer[offset + 2] = 1; // Ethernet
        buffer[offset + 3..offset + 9].copy_from_slice(self.mac_address.as_bytes());
        offset += 9;

        // ホスト名 (Option 12)
        {
            let hostname = b"ranyos";
            buffer[offset] = DhcpOption::Hostname as u8;
            buffer[offset + 1] = hostname.len() as u8;
            buffer[offset + 2..offset + 2 + hostname.len()].copy_from_slice(hostname);
            offset += 2 + hostname.len();
        }

        // 終端
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        // 状態を更新 (we already hold the lock)
        *state_guard = DhcpState::Selecting;
        drop(state_guard);

        self.state_time.store(current_tick, Ordering::SeqCst);

        Ok(offset)
    }

    /// Acquire the current DHCP state (helper for lock + error handling).
    pub(super) fn lock_dhcp_state(&self) -> Result<DhcpState, &'static str> {
        match self.state.lock() {
            Ok(g) => Ok(*g),
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned");
                Err("State lock poisoned")
            }
        }
    }

    /// Retrieve the lease corresponding to the current DHCP state for REQUEST building.
    pub(super) fn get_lease_for_request(&self, state: DhcpState) -> Result<(DhcpLease, bool), &'static str> {
        match state {
            DhcpState::Requesting => {
                let offered = match self.offered_lease.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        log::error!("[NET] DHCP Offer lock poisoned (build_request)");
                        return Err("Offer lock poisoned");
                    }
                };
                Ok((offered.clone().ok_or("No offer available")?, false))
            }
            DhcpState::Renewing | DhcpState::Rebinding => {
                let l = match self.lease.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        log::error!("[NET] DHCP Lease lock poisoned (build_request)");
                        return Err("Lease lock poisoned");
                    }
                };
                Ok((l.clone().ok_or("No active lease")?, true))
            }
            _ => Err("Invalid state for building request"),
        }
    }

    /// Write DHCP REQUEST options into `buffer` starting at `offset`, returning new offset.
    pub(super) fn write_request_options(
        &self,
        buffer: &mut [u8],
        mut offset: usize,
        lease: &DhcpLease,
        is_renewal: bool,
    ) -> usize {
        // マジッククッキー
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // メッセージタイプ: REQUEST
        buffer[offset] = DhcpOption::MessageType as u8;
        buffer[offset + 1] = 1;
        buffer[offset + 2] = DhcpMessageType::Request as u8;
        offset += 3;

        if !is_renewal {
            buffer[offset] = DhcpOption::RequestedIp as u8;
            buffer[offset + 1] = 4;
            buffer[offset + 2..offset + 6].copy_from_slice(lease.ip_address.as_bytes());
            offset += 6;

            buffer[offset] = DhcpOption::ServerIdentifier as u8;
            buffer[offset + 1] = 4;
            buffer[offset + 2..offset + 6].copy_from_slice(lease.server_ip.as_bytes());
            offset += 6;
        }

        buffer[offset] = DhcpOption::ParameterRequestList as u8;
        buffer[offset + 1] = 8;
        buffer[offset + 2] = DhcpOption::SubnetMask as u8;
        buffer[offset + 3] = DhcpOption::Router as u8;
        buffer[offset + 4] = DhcpOption::DnsServer as u8;
        buffer[offset + 5] = DhcpOption::DomainName as u8;
        buffer[offset + 6] = DhcpOption::LeaseTime as u8;
        buffer[offset + 7] = DhcpOption::ServerIdentifier as u8;
        buffer[offset + 8] = DhcpOption::RenewalTime as u8;
        buffer[offset + 9] = DhcpOption::RebindingTime as u8;
        offset += 10;

        buffer[offset] = DhcpOption::ClientIdentifier as u8;
        buffer[offset + 1] = 7;
        buffer[offset + 2] = 1; // Ethernet
        buffer[offset + 3..offset + 9].copy_from_slice(self.mac_address.as_bytes());
        offset += 9;

        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        offset
    }

    /// DHCPREQUEST メッセージを構築
    pub fn build_request(
        &self,
        buffer: &mut [u8],
        current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DhcpHeader::SIZE + 64 {
            return Err("Buffer too small");
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
        let offset = self.write_request_options(buffer, DhcpHeader::SIZE, &lease, is_renewal);

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
                for chunk in opt_data.chunks(4) {
                    if chunk.len() == 4 {
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;


