use super::*;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};

mod state_handlers;

impl TcpProcessor {
    /// Default maximum number of concurrent TCP connections
    pub const DEFAULT_MAX_CONNECTIONS: usize = 512;
    /// Maximum number of semi-open connections (SYN-RECEIVED)
    pub const MAX_SEMI_OPEN_CONNECTIONS: usize = 128;

    /// Create a new TCP processor
    pub fn new() -> Self {
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        TcpProcessor {
            connections: BTreeMap::new(),
            listeners: BTreeMap::new(),
            semi_open_count: 0,
            syncookie_secret: random_bytes,
        }
    }

    /// Generate a SYN Cookie (RFC 4987)
    fn generate_syncookie(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
        client_isn: u32,
        mss_idx: u8,
    ) -> u32 {
        use crate::net::security::tls::crypto::hmac::hmac_sha256;

        let mut data = [0u8; 40];
        let local_v6 = local.as_ipv6();
        let remote_v6 = remote.as_ipv6();
        data[0..16].copy_from_slice(&local_v6);
        data[16..18].copy_from_slice(&local.port().to_be_bytes());
        data[18..34].copy_from_slice(&remote_v6);
        data[34..36].copy_from_slice(&remote.port().to_be_bytes());

        let timestamp = (crate::task::current_tick() / 64000) as u32;
        data[36..40].copy_from_slice(&timestamp.to_be_bytes());

        let hash = hmac_sha256(&self.syncookie_secret, &data);

        let hash_val = u32::from_be_bytes([hash[0], hash[1], hash[2], 0]);
        // Mix client ISN into the hash (masked to 24 bits) to bind cookie to the specific SYN.
        // This prevents off-path spoofing attacks where the attacker doesn't know the ISN.
        let mixed_hash = hash_val.wrapping_add(client_isn) & 0xFFFFFF00;

        let time_bits = (timestamp & 0x1F) << 3;
        let mss_bits = mss_idx & 0x07;

        mixed_hash | (time_bits | mss_bits as u32) as u32
    }

    /// Verify a SYN Cookie and return MSS if valid
    fn verify_syncookie(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
        ack_num: u32,
        seq_num: u32,
    ) -> Option<u16> {
        use crate::net::security::tls::crypto::hmac::hmac_sha256;

        let cookie = ack_num.wrapping_sub(1);
        let client_isn = seq_num.wrapping_sub(1); // seq_num is client_isn + 1

        let mss_idx = (cookie & 0x07) as u8;
        let time_bits_received = (cookie >> 3) & 0x1F;

        let current_tick = crate::task::current_tick();
        let current_timestamp = (current_tick / 64000) as u32;

        for i in 0..2 {
            let timestamp = current_timestamp.wrapping_sub(i);
            if (timestamp & 0x1F) != time_bits_received {
                continue;
            }

            let mut data = [0u8; 40];
            let local_v6 = local.as_ipv6();
            let remote_v6 = remote.as_ipv6();
            data[0..16].copy_from_slice(&local_v6);
            data[16..18].copy_from_slice(&local.port().to_be_bytes());
            data[18..34].copy_from_slice(&remote_v6);
            data[34..36].copy_from_slice(&remote.port().to_be_bytes());
            data[36..40].copy_from_slice(&timestamp.to_be_bytes());

            let hash = hmac_sha256(&self.syncookie_secret, &data);
            let hash_val = u32::from_be_bytes([hash[0], hash[1], hash[2], 0]);

            // Verify with client ISN
            let expected_mixed = hash_val.wrapping_add(client_isn) & 0xFFFFFF00;

            if (cookie & 0xFFFFFF00) == expected_mixed {
                let mss = match mss_idx {
                    0 => local.default_mss(),
                    1 => 1300,
                    2 => 1440,
                    3 => {
                        if local.is_ipv6() {
                            1440
                        } else {
                            1460
                        }
                    }
                    _ => {
                        if local.is_ipv6() {
                            1440
                        } else {
                            1460
                        }
                    }
                };
                return Some(mss);
            }
        }
        None
    }

    /// Start listening on a local address
    pub fn listen(&mut self, local_addr: EndpointAddr) {
        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.enter_listen();
        self.listeners
            .insert(local_addr, Arc::new(PoisonLock::new(tcb)));
    }

    /// Bind to a specific port
    pub fn bind(
        &mut self,
        addr: EndpointAddr,
        token: Option<u64>,
    ) -> Result<TcpListener, TcpError> {
        self.bind_in(default_runtime(), addr, token)
    }

    pub fn bind_in(
        &mut self,
        runtime: NetRuntimeHandle,
        addr: EndpointAddr,
        token: Option<u64>,
    ) -> Result<TcpListener, TcpError> {
        let port = addr.port();

        // Security: Check for privileged ports (< 1024)
        if port < 1024 {
            let caller = crate::task::context::current_subject().domain.as_u64();
            let mut permitted = false;

            if let Some(t) = token {
                if crate::security::capability::manager().validate_token(
                    caller,
                    t,
                    crate::security::capability::CAP_NET_BIND,
                ) {
                    permitted = true;
                }
            } else {
                if crate::security::capability::manager()
                    .has_capability(caller, crate::security::capability::CAP_NET_BIND)
                {
                    permitted = true;
                }
            }

            if !permitted {
                log::warn!("[NET] TCP: Permission denied for privileged port {}", port);
                return Err(TcpError::PermissionDenied);
            }
        }

        if self.is_port_in_use(port) {
            return Err(TcpError::AddressInUse);
        }

        // If a token was provided and not already validated, validate it now
        if let Some(t) = token {
            // Check if it's at least a valid network token if it wasn't already checked for CAP_NET_BIND
            if port >= 1024 {
                // For now we allow any valid token for non-privileged ports,
                // but we should probably check for a generic NET capability.
                // Let's just increment in-flight for now if it exists.
            }

            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(TcpError::PermissionDenied);
            }
        }

        // Create shared state for backlog and waker
        let backlog = Arc::new(PoisonLock::new(VecDeque::new()));
        let accept_waker = Arc::new(crate::sync::atomic_waker::AtomicWaker::new());

        // Create TCB with this shared state
        let mut tcb = TcpControlBlock::new(addr);
        tcb.enter_listen();
        tcb.set_listener_waiters(backlog.clone(), accept_waker.clone(), runtime);

        // Wrap in Arc<PoisonLock>
        let tcb_arc = Arc::new(PoisonLock::new(tcb));

        self.listeners.insert(addr, tcb_arc);

        Ok(TcpListener {
            local_addr: addr,
            backlog,
            accept_waker,
            runtime,
        })
    }

    /// Check if a port is already in use by a listener or active connection
    pub fn is_port_in_use(&self, port: u16) -> bool {
        // Check listeners
        if self.listeners.keys().any(|addr| addr.port() == port) {
            return true;
        }
        // Check active connections
        if self
            .connections
            .keys()
            .any(|(local, _)| local.port() == port)
        {
            return true;
        }
        false
    }

    /// Allocate a unique ephemeral port using source port randomization
    pub fn allocate_ephemeral_port(&self, _local: &EndpointAddr, _remote: &EndpointAddr) -> u16 {
        // Use cryptographically secure random number to determine start port
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        let seed = u16::from_be_bytes([random_bytes[0], random_bytes[1]]);

        // Ephemeral port range (RFC 6056 / IANA)
        const EPHEMERAL_START: u16 = 49152;
        const EPHEMERAL_END: u16 = 65535;
        const RANGE_SIZE: u16 = EPHEMERAL_END - EPHEMERAL_START + 1;

        let start_port = EPHEMERAL_START + (seed % RANGE_SIZE);

        for i in 0..RANGE_SIZE {
            let port = EPHEMERAL_START
                + ((start_port
                    .wrapping_sub(EPHEMERAL_START)
                    .wrapping_add(i as u16))
                    % RANGE_SIZE);

            if !self.is_port_in_use(port) {
                return port;
            }
        }
        0 // Exhausted
    }

    /// Initiate a connection to a remote address
    pub fn connect(
        &mut self,
        local_addr: EndpointAddr,
        remote_addr: EndpointAddr,
    ) -> Result<TcpStream, TcpError> {
        self.connect_in(default_runtime(), local_addr, remote_addr)
    }

    pub fn connect_in(
        &mut self,
        runtime: NetRuntimeHandle,
        local_addr: EndpointAddr,
        remote_addr: EndpointAddr,
    ) -> Result<TcpStream, TcpError> {
        if self.connections.len() >= Self::DEFAULT_MAX_CONNECTIONS {
            return Err(TcpError::BufferFull);
        }

        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.set_remote_addr(remote_addr);
        tcb.enter_syn_sent();
        tcb.regenerate_isn();

        let tcb_arc = Arc::new(PoisonLock::new(tcb));

        self.connections
            .insert((local_addr, remote_addr), tcb_arc.clone());
        // Note: Caller should send SYN packet after this (handled by stack wrapper or here?)
        // Better if caller does it, or we return an action.
        // But connect() is synchronous state setup.

        Ok(TcpStream {
            tcb: tcb_arc,
            runtime,
        })
    }

    /// Test-only helper to seed an existing connection.
    #[cfg(any(test, feature = "full_mm_tests", feature = "qemu-test-export"))]
    pub fn insert_test_connection(
        &mut self,
        local_addr: EndpointAddr,
        remote_addr: EndpointAddr,
        tcb: Arc<PoisonLock<TcpControlBlock>>,
    ) {
        self.connections.insert((local_addr, remote_addr), tcb);
    }

    /// Process an incoming TCP segment
    pub fn process(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        current_time: u64,
    ) -> TcpProcessResult {
        if data.len() < TcpHeader::MIN_HEADER_LEN {
            return TcpProcessResult::None;
        }

        // Read header fields directly from bytes to avoid packed struct alignment issues
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
        let flags = (data_offset_flags as u8) as u16;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        if header_len < TcpHeader::MIN_HEADER_LEN || header_len > data.len() {
            return TcpProcessResult::None;
        }

        // Verify checksum
        if !verify_tcp_checksum(data, src_ip.octets(), dst_ip.octets()) {
            log::warn!("[TCP] Checksum verification failed from {}", src_ip);
            return TcpProcessResult::None;
        }

        // Convert to internal address types
        let remote_addr = EndpointAddr::new(src_ip.octets(), src_port);

        let local_addr = EndpointAddr::new(dst_ip.octets(), dst_port);

        // Extract payload
        let payload = if data.len() > header_len {
            &data[header_len..]
        } else {
            &[]
        };

        // Try to find existing connection
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                return self.process_segment(
                    &tcb_lock,
                    &mut *tcb,
                    seq_num,
                    ack_num,
                    flags,
                    window,
                    header_len,
                    payload,
                    None,
                    current_time,
                );
            }
        }

        // Check if this is an ACK completing a SYN Cookie handshake
        // RFC 793/9293: The 3rd ACK of a 3-way handshake may also contain data.
        if (flags & (TcpHeader::FLAG_ACK | TcpHeader::FLAG_SYN | TcpHeader::FLAG_RST))
            == TcpHeader::FLAG_ACK
        {
            if let Some(mss) = self.verify_syncookie(local_addr, remote_addr, ack_num, seq_num) {
                log::info!(
                    "[TCP] SYN Cookie verified for {}, creating connection",
                    remote_addr
                );

                let mut tcb = TcpControlBlock::new(local_addr);
                tcb.set_remote_addr(remote_addr);

                if let Some(listener_lock) = self.listeners.get(&local_addr) {
                    if let Ok(listener) = listener_lock.lock() {
                        tcb.inherit_listener_waiters(&listener);
                    }
                }

                tcb.set_rcv_nxt(seq_num); // We expect this seq_num (client ISN + 1)
                tcb.set_snd_una(ack_num.wrapping_sub(1));
                tcb.set_snd_nxt(ack_num);
                tcb.set_rcv_wnd(65535);
                tcb.set_mss(mss);
                tcb.enter_established();
                let tcb_arc = Arc::new(PoisonLock::new(tcb));
                self.connections
                    .insert((local_addr, remote_addr), tcb_arc.clone());

                let accepted = if let Ok(tcb_guard) = tcb_arc.lock() {
                    Self::notify_backlog(&tcb_guard, &tcb_arc)
                } else {
                    false
                };

                if !accepted {
                    self.connections.remove(&(local_addr, remote_addr));
                    return TcpProcessResult::SendPacket {
                        local: local_addr,
                        remote: remote_addr,
                        seq: ack_num,
                        ack: 0,
                        flags: TcpHeader::FLAG_RST,
                        window: 0,
                        payload: Vec::new(),
                        options: Vec::new(),
                    };
                }

                // Process this ACK segment in the new TCB
                if let Ok(mut tcb_guard) = tcb_arc.lock() {
                    return self.process_segment(
                        &tcb_arc,
                        &mut *tcb_guard,
                        seq_num,
                        ack_num,
                        flags,
                        window,
                        header_len,
                        payload,
                        None,
                        current_time,
                    );
                }
            }
        }

        // Check if this is for a listening socket
        let options = if header_len > 20 {
            Some(&data[20..header_len])
        } else {
            None
        };
        if let Some(result) = self.handle_incoming_syn(
            local_addr,
            remote_addr,
            seq_num,
            ack_num,
            flags,
            window,
            options,
        ) {
            return result;
        }

        // No matching connection or listener - RFC 9293 Section 3.10.7.1 (CLOSED state)
        if flags & TcpHeader::FLAG_RST == 0 {
            if flags & TcpHeader::FLAG_ACK != 0 {
                // <SEQ=SEG.ACK><CTL=RST>
                return TcpProcessResult::SendPacket {
                    local: local_addr,
                    remote: remote_addr,
                    seq: ack_num,
                    ack: 0,
                    flags: TcpHeader::FLAG_RST,
                    window: 0,
                    payload: Vec::new(),
                    options: Vec::new(),
                };
            } else {
                // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                let mut seg_len = payload.len() as u32;
                if flags & TcpHeader::FLAG_SYN != 0 {
                    seg_len += 1;
                }
                if flags & TcpHeader::FLAG_FIN != 0 {
                    seg_len += 1;
                }
                let ack = seq_num.wrapping_add(seg_len);
                return TcpProcessResult::SendPacket {
                    local: local_addr,
                    remote: remote_addr,
                    seq: 0,
                    ack,
                    flags: TcpHeader::FLAG_RST | TcpHeader::FLAG_ACK,
                    window: 0,
                    payload: Vec::new(),
                    options: Vec::new(),
                };
            }
        }

        TcpProcessResult::None
    }

    /// IPv6 variant of `process` — accepts IPv6 source/destination and uses `EndpointAddr::V6` keys.
    pub fn process_v6(
        &mut self,
        data: &[u8],
        src_ip: crate::net::l3::ipv6::Ipv6Address,
        dst_ip: crate::net::l3::ipv6::Ipv6Address,
        current_time: u64,
    ) -> TcpProcessResult {
        if data.len() < TcpHeader::MIN_HEADER_LEN {
            return TcpProcessResult::None;
        }

        // Read header fields directly from bytes to avoid packed struct alignment issues
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
        let flags = (data_offset_flags as u8) as u16;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        if header_len < TcpHeader::MIN_HEADER_LEN || header_len > data.len() {
            return TcpProcessResult::None;
        }

        // Verify checksum
        if !verify_tcp_checksum_v6(data, src_ip, dst_ip) {
            log::warn!("[TCP] Checksum verification failed from {}", src_ip);
            return TcpProcessResult::None;
        }

        // Convert to internal address types (EndpointAddr::V6)
        let remote_addr = EndpointAddr::new_v6(src_ip.octets(), src_port);
        let local_addr = EndpointAddr::new_v6(dst_ip.octets(), dst_port);

        // Extract payload
        let payload = if data.len() > header_len {
            &data[header_len..]
        } else {
            &[]
        };

        // Try to find existing connection
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                return self.process_segment(
                    &tcb_lock,
                    &mut *tcb,
                    seq_num,
                    ack_num,
                    flags,
                    window,
                    header_len,
                    payload,
                    None,
                    current_time,
                );
            }
        }

        // Check if this is an ACK completing a SYN Cookie handshake
        // RFC 793/9293: The 3rd ACK of a 3-way handshake may also contain data.
        if (flags & (TcpHeader::FLAG_ACK | TcpHeader::FLAG_SYN | TcpHeader::FLAG_RST))
            == TcpHeader::FLAG_ACK
        {
            if let Some(mss) = self.verify_syncookie(local_addr, remote_addr, ack_num, seq_num) {
                log::info!(
                    "[TCP] SYN Cookie verified for {}, creating connection",
                    remote_addr
                );

                let mut tcb = TcpControlBlock::new(local_addr);
                tcb.set_remote_addr(remote_addr);

                if let Some(listener_lock) = self.listeners.get(&local_addr) {
                    if let Ok(listener) = listener_lock.lock() {
                        tcb.inherit_listener_waiters(&listener);
                    }
                }

                tcb.set_rcv_nxt(seq_num); // We expect this seq_num (client ISN + 1)
                tcb.set_snd_una(ack_num.wrapping_sub(1));
                tcb.set_snd_nxt(ack_num);
                tcb.set_rcv_wnd(65535);
                tcb.set_mss(mss);
                tcb.enter_established();
                let tcb_arc = Arc::new(PoisonLock::new(tcb));
                self.connections
                    .insert((local_addr, remote_addr), tcb_arc.clone());

                let accepted = if let Ok(tcb_guard) = tcb_arc.lock() {
                    Self::notify_backlog(&tcb_guard, &tcb_arc)
                } else {
                    false
                };

                if !accepted {
                    self.connections.remove(&(local_addr, remote_addr));
                    return TcpProcessResult::SendPacket {
                        local: local_addr,
                        remote: remote_addr,
                        seq: ack_num,
                        ack: 0,
                        flags: TcpHeader::FLAG_RST,
                        window: 0,
                        payload: Vec::new(),
                        options: Vec::new(),
                    };
                }

                // Process this ACK segment in the new TCB
                if let Ok(mut tcb_guard) = tcb_arc.lock() {
                    return self.process_segment(
                        &tcb_arc,
                        &mut *tcb_guard,
                        seq_num,
                        ack_num,
                        flags,
                        window,
                        header_len,
                        payload,
                        None,
                        current_time,
                    );
                }
            }
        }

        // Check if this is for a listening socket
        let options = if header_len > 20 {
            Some(&data[20..header_len])
        } else {
            None
        };
        if let Some(result) = self.handle_incoming_syn(
            local_addr,
            remote_addr,
            seq_num,
            ack_num,
            flags,
            window,
            options,
        ) {
            return result;
        }

        // No matching connection or listener - RFC 9293 Section 3.10.7.1 (CLOSED state)
        if flags & TcpHeader::FLAG_RST == 0 {
            if flags & TcpHeader::FLAG_ACK != 0 {
                // <SEQ=SEG.ACK><CTL=RST>
                return TcpProcessResult::SendPacket {
                    local: local_addr,
                    remote: remote_addr,
                    seq: ack_num,
                    ack: 0,
                    flags: TcpHeader::FLAG_RST,
                    window: 0,
                    payload: Vec::new(),
                    options: Vec::new(),
                };
            } else {
                // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                let mut seg_len = payload.len() as u32;
                if flags & TcpHeader::FLAG_SYN != 0 {
                    seg_len += 1;
                }
                if flags & TcpHeader::FLAG_FIN != 0 {
                    seg_len += 1;
                }
                let ack = seq_num.wrapping_add(seg_len);
                return TcpProcessResult::SendPacket {
                    local: local_addr,
                    remote: remote_addr,
                    seq: 0,
                    ack,
                    flags: TcpHeader::FLAG_RST | TcpHeader::FLAG_ACK,
                    window: 0,
                    payload: Vec::new(),
                    options: Vec::new(),
                };
            }
        }

        TcpProcessResult::None
    }

    pub(super) fn handle_incoming_syn(
        &mut self,
        local_addr: EndpointAddr,
        remote_addr: EndpointAddr,
        seq_num: u32,
        ack_num: u32,
        flags: u16,
        _window: u16,
        options_data: Option<&[u8]>,
    ) -> Option<TcpProcessResult> {
        let listener_addr = if self.listeners.contains_key(&local_addr) {
            local_addr
        } else {
            let port = local_addr.port();

            // Prefer IPv4 wildcard when the packet address is IPv4-mapped.
            if local_addr.as_ipv4().is_some() {
                let wildcard_v4 = EndpointAddr::new([0, 0, 0, 0], port);
                if self.listeners.contains_key(&wildcard_v4) {
                    wildcard_v4
                } else {
                    let wildcard_v6 = EndpointAddr::new_v6([0u8; 16], port);
                    if self.listeners.contains_key(&wildcard_v6) {
                        wildcard_v6
                    } else {
                        return None;
                    }
                }
            } else {
                let wildcard_v6 = EndpointAddr::new_v6([0u8; 16], port);
                if self.listeners.contains_key(&wildcard_v6) {
                    wildcard_v6
                } else {
                    return None;
                }
            }
        };

        let listener_lock = self.listeners.get(&listener_addr)?;
        let listener = listener_lock.lock().ok()?;
        if !listener.is_listen() {
            return None;
        }

        // RFC 9293 Section 3.10.7.3 (The LISTEN State)

        // First, check for an RST:
        // "An incoming RST should be ignored. Return."
        if flags & TcpHeader::FLAG_RST != 0 {
            return Some(TcpProcessResult::None);
        }

        // Second, check for an ACK:
        // "Any acknowledgment is bad if it arrives on a connection still in the LISTEN state.
        // An acceptable reset segment should be formed for any arriving ACK-bearing segment."
        if flags & TcpHeader::FLAG_ACK != 0 {
            return Some(TcpProcessResult::SendPacket {
                local: local_addr,
                remote: remote_addr,
                seq: ack_num,
                ack: 0,
                flags: TcpHeader::FLAG_RST,
                window: 0,
                payload: Vec::new(),
                options: Vec::new(),
            });
        }

        // Third, check for a SYN:
        if flags & TcpHeader::FLAG_SYN == 0 {
            // "Any other segments or control bits should be ignored. Return."
            return Some(TcpProcessResult::None);
        }

        // Check total connection limit (SYN flood protection)
        if self.connections.len() >= Self::DEFAULT_MAX_CONNECTIONS {
            return None;
        }

        // Check semi-open connection limit. If reached, use SYN Cookies.
        if self.semi_open_count >= Self::MAX_SEMI_OPEN_CONNECTIONS {
            let mut mss_idx = 3; // default 1460
            if let Some(data) = options_data {
                use crate::net::l4::endpoint::window_scale::TcpOptionParser;
                let mut parser = TcpOptionParser::new(data);
                if let Some(mss) = parser.find_mss() {
                    mss_idx = match mss {
                        0..=536 => 0,
                        537..=1300 => 1,
                        1301..=1440 => 2,
                        _ => 3,
                    };
                }
            }

            // Generate SYN Cookie
            let cookie = self.generate_syncookie(local_addr, remote_addr, seq_num, mss_idx);

            // Build fixed MSS option for SYN Cookie response
            let mss_val: u16 = match mss_idx {
                0 => local_addr.default_mss(),
                1 => 1300,
                2 => 1440,
                3 => {
                    if local_addr.is_ipv6() {
                        1440
                    } else {
                        1460
                    }
                }
                _ => {
                    if local_addr.is_ipv6() {
                        1440
                    } else {
                        1460
                    }
                }
            };
            let mut cookie_opts = Vec::with_capacity(4);
            cookie_opts.push(2); // MSS
            cookie_opts.push(4);
            cookie_opts.extend_from_slice(&mss_val.to_be_bytes());

            return Some(TcpProcessResult::SendPacket {
                local: local_addr,
                remote: remote_addr,
                seq: cookie,
                ack: seq_num.wrapping_add(1),
                flags: TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
                window: 65535,
                payload: Vec::new(),
                options: cookie_opts,
            });
        }

        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.set_remote_addr(remote_addr);
        tcb.regenerate_isn();
        tcb.set_rcv_nxt(seq_num.wrapping_add(1));
        tcb.set_rcv_wnd(65535);

        // Parse options for the initial TCB (SynReceived state)
        let mut peer_mss_val = None;
        if let Some(data) = options_data {
            use crate::net::l4::endpoint::window_scale::TcpOptionParser;
            let mut parser = TcpOptionParser::new(data);

            if let Some(peer_mss) = parser.find_mss() {
                peer_mss_val = Some(peer_mss);
            }
            if let Some(peer_wscale) = parser.find_window_scale() {
                tcb.set_peer_wscale(peer_wscale.min(14));
            }
            if parser.find_sack_permitted() {
                tcb.set_sack_enabled(true);
            }
            if let Some((ts_val, _ts_ecr)) = parser.find_timestamps() {
                tcb.set_timestamps_enabled(true);
                tcb.update_timestamps(ts_val);
            }
        }

        // RFC 1122 Section 4.2.2.6: If an MSS option is not received,
        // a default MSS based on the address family is used.
        tcb.set_mss(peer_mss_val.unwrap_or(local_addr.default_mss()));

        tcb.enter_syn_received();

        let isn = generate_initial_seq(local_addr, Some(remote_addr));
        tcb.set_snd_nxt(isn);
        tcb.set_snd_una(isn);

        let flags = TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK;
        let opts = tcb.build_options(flags);

        let syn_ack = TcpProcessResult::SendPacket {
            local: local_addr,
            remote: remote_addr,
            seq: tcb.snd_nxt(),
            ack: tcb.rcv_nxt(),
            flags,
            window: 65535,
            payload: Vec::new(),
            options: opts,
        };

        drop(listener);
        self.connections
            .insert((local_addr, remote_addr), Arc::new(PoisonLock::new(tcb)));
        self.semi_open_count += 1;
        Some(syn_ack)
    }

    /// Process an incoming TCP segment using a PacketRef (zero-copy path)
    pub fn process_with_packet(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        packet: PacketRef,
        current_time: u64,
    ) -> TcpProcessResult {
        // Short-circuit to the connection-specific fast-path that can enqueue
        // a zero-copy PacketRef view for payload when possible. For non-connection
        // packets we delegate back to the standard `process()` implementation.
        if data.len() < TcpHeader::MIN_HEADER_LEN {
            return TcpProcessResult::None;
        }

        // Read header fields directly from bytes to avoid packed struct alignment issues
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
        let flags = (data_offset_flags as u8) as u16;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        if header_len < TcpHeader::MIN_HEADER_LEN || header_len > data.len() {
            return TcpProcessResult::None;
        }

        // Verify checksum
        if !verify_tcp_checksum(data, src_ip.octets(), dst_ip.octets()) {
            log::warn!(
                "[TCP] Checksum verification failed from {} (zero-copy path)",
                src_ip
            );
            return TcpProcessResult::None;
        }

        // Convert to internal address types
        let remote_addr = EndpointAddr::new(src_ip.octets(), src_port);

        let local_addr = EndpointAddr::new(dst_ip.octets(), dst_port);

        // Extract payload
        let payload = if data.len() > header_len {
            &data[header_len..]
        } else {
            &[]
        };

        // Try to find existing connection and use the packet for zero-copy enqueue
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                return self.process_segment(
                    &tcb_lock,
                    &mut *tcb,
                    seq_num,
                    ack_num,
                    flags,
                    window,
                    header_len,
                    payload,
                    Some(packet),
                    current_time,
                );
            }
        }

        // Not an existing connection - fall back to normal processing (listener/SYN handling)
        self.process(data, src_ip, dst_ip, current_time)
    }

    /// IPv6 variant of `process_with_packet` to support zero-copy receive for native IPv6.
    pub fn process_with_packet_v6(
        &mut self,
        data: &[u8],
        src_ip: crate::net::l3::ipv6::Ipv6Address,
        dst_ip: crate::net::l3::ipv6::Ipv6Address,
        packet: PacketRef,
        current_time: u64,
    ) -> TcpProcessResult {
        if data.len() < TcpHeader::MIN_HEADER_LEN {
            return TcpProcessResult::None;
        }

        // Read header fields directly from bytes to avoid packed struct alignment issues
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
        let flags = (data_offset_flags as u8) as u16;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        if header_len < TcpHeader::MIN_HEADER_LEN || header_len > data.len() {
            return TcpProcessResult::None;
        }

        // Verify checksum
        if !verify_tcp_checksum_v6(data, src_ip, dst_ip) {
            log::warn!(
                "[TCP] Checksum verification failed from {} (zero-copy v6 path)",
                src_ip
            );
            return TcpProcessResult::None;
        }

        // Convert to internal address types
        let remote_addr = EndpointAddr::new_v6(src_ip.octets(), src_port);
        let local_addr = EndpointAddr::new_v6(dst_ip.octets(), dst_port);

        // Extract payload
        let payload = if data.len() > header_len {
            &data[header_len..]
        } else {
            &[]
        };

        // Try to find existing connection and use the packet for zero-copy enqueue
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                return self.process_segment(
                    &tcb_lock,
                    &mut *tcb,
                    seq_num,
                    ack_num,
                    flags,
                    window,
                    header_len,
                    payload,
                    Some(packet),
                    current_time,
                );
            }
        }

        // Not an existing connection - fall back to normal processing (listener/SYN handling)
        self.process_v6(data, src_ip, dst_ip, current_time)
    }

    /// Create an ACK packet result from current TCB state
    pub(super) fn make_ack_result(tcb: &mut TcpControlBlock) -> TcpProcessResult {
        let Some(remote) = tcb.remote_addr() else {
            return TcpProcessResult::None;
        };
        let flags = TcpHeader::FLAG_ACK;
        let opts = tcb.build_options(flags);
        TcpProcessResult::SendPacket {
            local: tcb.local_addr(),
            remote,
            seq: tcb.snd_nxt(),
            ack: tcb.rcv_nxt(),
            flags,
            window: tcb.rcv_wnd(),
            payload: Vec::new(),
            options: opts,
        }
    }

    /// Create an RST|ACK packet result from current TCB state
    pub(super) fn make_rst_ack_result(tcb: &mut TcpControlBlock) -> TcpProcessResult {
        let Some(remote) = tcb.remote_addr() else {
            return TcpProcessResult::None;
        };
        let flags = TcpHeader::FLAG_RST | TcpHeader::FLAG_ACK;
        let opts = tcb.build_options(flags);
        TcpProcessResult::SendPacket {
            local: tcb.local_addr(),
            remote,
            seq: tcb.snd_nxt(),
            ack: tcb.rcv_nxt(),
            flags,
            window: tcb.rcv_wnd(),
            payload: Vec::new(),
            options: opts,
        }
    }

    /// Check if an incoming segment is acceptable according to RFC 793 / 9293 Step 1
    pub(crate) fn is_acceptable_sequence(
        tcb: &TcpControlBlock,
        seq_num: u32,
        seg_len: usize,
    ) -> bool {
        let rcv_nxt = tcb.rcv_nxt();
        let rcv_wnd = tcb.get_effective_rcv_wnd();

        // RFC 1122: If the window is shrunk, we must still accept segments within
        // the previous window (tracked by rcv_wnd_max_adv).
        let current_rcv_end = rcv_nxt.wrapping_add(rcv_wnd);
        let max_rcv_end = tcb.options.rcv_wnd_max_adv;
        let rcv_end = if Self::seq_after(max_rcv_end, current_rcv_end) {
            max_rcv_end
        } else {
            current_rcv_end
        };

        if seg_len == 0 {
            if rcv_wnd == 0 && current_rcv_end == rcv_end {
                seq_num == rcv_nxt
            } else {
                // rcv_nxt <= seq_num < rcv_end
                let diff = seq_num.wrapping_sub(rcv_nxt);
                let wnd_diff = rcv_end.wrapping_sub(rcv_nxt);
                diff < wnd_diff
            }
        } else {
            if rcv_wnd == 0 && current_rcv_end == rcv_end {
                // RFC 1122 Section 4.2.2.17: "The receiver MUST accept a zero-window
                // probe containing a single octet of new data."
                seg_len == 1 && seq_num == rcv_nxt
            } else {
                // Overlap exists if NOT (Entirely before OR Entirely after)
                // Entirely before: SEG.SEQ + SEG.LEN <= RCV.NXT
                // Entirely after: SEG.SEQ >= RCV.END

                let seg_end = seq_num.wrapping_add(seg_len as u32);

                // (seg_end <= rcv_nxt)
                let entirely_before = (seg_end.wrapping_sub(rcv_nxt) as i32) <= 0;
                // (seq_num >= rcv_end)
                let entirely_after = (seq_num.wrapping_sub(rcv_end) as i32) >= 0;

                !entirely_before && !entirely_after
            }
        }
    }
    /// Process a TCP segment for an existing connection
    pub(super) fn process_segment(
        &mut self,
        tcb_arc: &Arc<PoisonLock<TcpControlBlock>>,
        tcb: &mut TcpControlBlock,
        seq_num: u32,
        ack_num: u32,
        flags: u16,
        window: u16,
        header_len: usize,
        payload: &[u8],
        packet_opt: Option<PacketRef>,
        current_time: u64,
    ) -> TcpProcessResult {
        let rst = flags & TcpHeader::FLAG_RST != 0;
        let syn = flags & TcpHeader::FLAG_SYN != 0;
        let ack = flags & TcpHeader::FLAG_ACK != 0;
        let fin = flags & TcpHeader::FLAG_FIN != 0;
        let _psh = flags & TcpHeader::FLAG_PSH != 0;

        // RFC 793 Step 1: Check sequence number acceptability
        // SEG.LEN includes SYN and FIN bits (RFC 793 Section 3.1)
        let mut seg_len = payload.len();
        if syn {
            seg_len += 1;
        }
        if fin {
            seg_len += 1;
        }

        if tcb.state() != TcpState::SynSent && !Self::is_acceptable_sequence(tcb, seq_num, seg_len)
        {
            // If the segment is not acceptable and RST is not set, send an ACK
            if !rst {
                return Self::make_ack_result(tcb);
            }
            return TcpProcessResult::None;
        }

        // Parse options (MSS / TS / SACK)
        let mut ts_val: Option<u32> = None;
        let mut ts_ecr: Option<u32> = None;
        let mut sack_blocks: Option<alloc::vec::Vec<(u32, u32)>> = None;

        if header_len > 20 {
            if let Some(pkt) = &packet_opt {
                if pkt.len() >= header_len {
                    use crate::net::l4::endpoint::window_scale::TcpOptionParser;
                    let mut parser = TcpOptionParser::new(&pkt.data()[20..header_len]);
                    if let Some((v, e)) = parser.find_timestamps() {
                        ts_val = Some(v);
                        ts_ecr = Some(e);
                    }
                    sack_blocks = parser.find_sack_blocks();
                }
            }
        }

        // Security (RFC 7323): PAWS (Protection Against Wrapped Sequences)
        if let Some(v) = ts_val {
            if tcb.check_paws(v, current_time) {
                // Old duplicate segment - send ACK and drop (RFC 7323 Section 5.2)
                if !rst {
                    log::warn!(
                        "[TCP] PAWS drop: seq={}, ts_val={}, ts_recent={}",
                        seq_num,
                        v,
                        tcb.options.ts_recent
                    );
                    return Self::make_ack_result(tcb);
                }
                return TcpProcessResult::None;
            }
            // RFC 7323 RTT measurement from Timestamps
            if let Some(ecr) = ts_ecr {
                if let Some(rtt_sample) = tcb.measure_rtt_from_ts(ecr, current_time as u32) {
                    tcb.update_rto(rtt_sample);
                }
            }
            // Update TS.Recent and prepare TS.EchoReply
            tcb.process_ts_option(v, ts_ecr.unwrap_or(0), current_time, seq_num);
        }

        // Process SACK blocks if present
        if let Some(blocks) = sack_blocks {
            tcb.process_sack_option(&blocks);
        }

        // Security (RFC 5961): RST sequence number validation
        if rst {
            let is_acceptable = if tcb.state() == TcpState::SynSent {
                // RFC 9293 Section 3.10.7.3 (SYN-SENT STATE):
                // If ACK bit is set, RST is valid if it acknowledges the SYN.
                // If ACK bit is not set, RST is valid if its sequence number is in the window.
                if ack {
                    ack_num == tcb.snd_una().wrapping_add(1)
                } else {
                    // In SYN-SENT, we accept any RST as we don't have a known rcv_nxt yet.
                    true
                }
            } else {
                seq_num == tcb.rcv_nxt()
            };

            if is_acceptable {
                // Exact match: accept RST and close
                let local = tcb.local_addr();
                if let Some(remote) = tcb.remote_addr() {
                    if matches!(tcb.state(), TcpState::SynSent | TcpState::SynReceived) {
                        self.semi_open_count = self.semi_open_count.saturating_sub(1);
                    }
                    tcb.close_and_wake();
                    self.connections.remove(&(local, remote));
                }
                return TcpProcessResult::None;
            } else if tcb.state() != TcpState::SynSent
                && (seq_num.wrapping_sub(tcb.rcv_nxt()) as i32) >= 0
                && (seq_num.wrapping_sub(tcb.rcv_nxt().wrapping_add(tcb.get_effective_rcv_wnd()))
                    as i32)
                    < 0
            {
                // RFC 5961: Within window but not exact match: send challenge ACK
                return Self::make_ack_result(tcb);
            } else {
                // Outside window or invalid in SYN-SENT: ignore
                return TcpProcessResult::None;
            }
        }

        // Security (RFC 5961): SYN validation for established connections
        if syn && tcb.state() != TcpState::SynSent {
            // Unexpected SYN on existing connection - send challenge ACK
            return Self::make_ack_result(tcb);
        }

        // RFC 793: Fifth step, check the ACK field
        if ack {
            if tcb.state() == TcpState::SynReceived {
                if Self::seq_after(ack_num, tcb.snd_nxt()) {
                    // RFC 9293 Section 3.10.7.4: SYN-RECEIVED STATE
                    // "If SEG.ACK > SND.NXT, send a reset <SEQ=SEG.ACK><CTL=RST> and return."
                    log::warn!(
                        "[TCP] SYN-RECEIVED: ACK {} in the future (SND.NXT={}), sending RST",
                        ack_num,
                        tcb.snd_nxt()
                    );
                    return TcpProcessResult::SendPacket {
                        local: tcb.local_addr(),
                        remote: tcb
                            .remote_addr()
                            .unwrap_or(EndpointAddr::new([0, 0, 0, 0], 0)),
                        seq: ack_num,
                        ack: 0,
                        flags: TcpHeader::FLAG_RST,
                        window: 0,
                        payload: Vec::new(),
                        options: Vec::new(),
                    };
                }
            }

            // RFC 793 / 9293: Update send window if acceptable
            if tcb.should_update_window(seq_num, ack_num, window) {
                tcb.set_snd_wnd(window, seq_num, ack_num);
            }
        }

        match tcb.state() {
            TcpState::Closed | TcpState::Listen | TcpState::CloseWait => {
                // Closed: ignore; Listen: handled in main process(); CloseWait: handled by close()
                TcpProcessResult::None
            }
            TcpState::SynSent => {
                // SYN-ACKのTCPオプションを解析（TSopt / SACK-Permitted / MSS / WSCALE検出）
                let options = if header_len > 20 && packet_opt.is_some() {
                    let pkt = packet_opt.as_ref().unwrap();
                    if pkt.len() >= header_len {
                        Some(&pkt.data()[20..header_len])
                    } else {
                        None
                    }
                } else {
                    None
                };
                Self::handle_syn_sent_segment(
                    tcb,
                    syn,
                    ack,
                    seq_num,
                    ack_num,
                    options,
                    current_time,
                )
            }
            TcpState::SynReceived => {
                // ACK (completing 3-way handshake) or data segment
                self.handle_syn_received_segment(
                    tcb,
                    tcb_arc,
                    ack,
                    ack_num,
                    seq_num,
                    header_len,
                    payload,
                    packet_opt,
                    None,
                    flags,
                    window,
                    current_time,
                )
            }
            TcpState::Established => Self::handle_established_segment(
                tcb,
                ack,
                ack_num,
                fin,
                seq_num,
                payload,
                header_len,
                packet_opt,
                flags,
                window,
                current_time,
            ),
            TcpState::FinWait1 => {
                Self::handle_fin_wait1_segment(tcb, ack, ack_num, fin, current_time)
            }
            TcpState::FinWait2 => Self::handle_fin_wait2_segment(tcb, fin, current_time),
            TcpState::Closing => Self::handle_closing_segment(tcb, ack, ack_num, current_time),
            TcpState::LastAck => Self::handle_last_ack_segment(tcb, ack, ack_num),
            TcpState::TimeWait => Self::handle_time_wait_segment(tcb, current_time),
        }
    }

    /// Handle segment in SYN-SENT state
    pub(super) fn handle_syn_sent_segment(
        tcb: &mut TcpControlBlock,
        syn: bool,
        ack: bool,
        seq_num: u32,
        ack_num: u32,
        options_data: Option<&[u8]>,
        current_time: u64,
    ) -> TcpProcessResult {
        // Parse options (MSS / WSCALE / SACK / TS) if present in any SYN segment
        let mut peer_mss_val = None;
        if syn {
            if let Some(data) = options_data {
                use crate::net::l4::endpoint::window_scale::TcpOptionParser;
                let mut parser = TcpOptionParser::new(data);

                if let Some(peer_mss) = parser.find_mss() {
                    peer_mss_val = Some(peer_mss);
                }

                if let Some(peer_wscale) = parser.find_window_scale() {
                    tcb.set_peer_wscale(peer_wscale.min(14));
                }

                if parser.find_sack_permitted() {
                    tcb.set_sack_enabled(true);
                }

                if let Some((ts_val, _ts_ecr)) = parser.find_timestamps() {
                    tcb.set_timestamps_enabled(true);
                    tcb.update_timestamps(ts_val);
                }
            }
        }

        // RFC 9293 Section 3.10.7.3: First, check the ACK bit
        if ack {
            // ISS = snd_una. Ack must be between ISS and snd_nxt.
            // Note: In SYN-SENT, snd_nxt should be ISS + 1 after sending SYN.
            if ack_num <= tcb.snd_una() || ack_num > tcb.snd_nxt() {
                log::warn!(
                    "[TCP] SYN-SENT: Invalid ACK {} (ISS={}, SND.NXT={}), sending RST",
                    ack_num,
                    tcb.snd_una(),
                    tcb.snd_nxt()
                );
                return TcpProcessResult::SendPacket {
                    local: tcb.local_addr(),
                    remote: tcb
                        .remote_addr()
                        .unwrap_or(EndpointAddr::new([0, 0, 0, 0], 0)),
                    seq: ack_num,
                    ack: 0,
                    flags: TcpHeader::FLAG_RST,
                    window: 0,
                    payload: Vec::new(),
                    options: Vec::new(),
                };
            }
        }

        // Waiting for SYN-ACK
        // Accept ACK that acknowledges the initial SYN (snd_una + 1)
        if syn && ack {
            // Both SYN and ACK are set and ACK is acceptable (checked above)

            // Apply MSS (defaulting to appropriate value as per RFC 1122 if not provided)
            tcb.set_mss(peer_mss_val.unwrap_or(tcb.local_addr().default_mss()));

            tcb.set_snd_una(ack_num);
            // Remove SYN from retransmit queue and update RTO
            tcb.ack_segments(ack_num, current_time);

            // snd_nxt is already isn + 1, so this is correct.
            tcb.set_rcv_nxt(seq_num.wrapping_add(1));
            tcb.enter_established();
            // Wake connect waker
            tcb.wake_connect_waiter();
            // Send ACK
            Self::make_ack_result(tcb)
        } else if syn && !ack {
            // Simultaneous open
            // Apply MSS even in simultaneous open
            tcb.set_mss(peer_mss_val.unwrap_or(tcb.local_addr().default_mss()));

            tcb.set_rcv_nxt(seq_num.wrapping_add(1));
            tcb.enter_syn_received();
            // Send SYN-ACK
            let Some(remote) = tcb.remote_addr() else {
                return TcpProcessResult::None;
            };
            let flags = TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK;
            let opts = tcb.build_options(flags);
            TcpProcessResult::SendPacket {
                local: tcb.local_addr(),
                remote,
                seq: tcb.snd_una(), // Use ISS for SYN-ACK in simultaneous open
                ack: tcb.rcv_nxt(),
                flags,
                window: tcb.rcv_wnd(),
                payload: Vec::new(),
                options: opts,
            }
        } else {
            TcpProcessResult::None
        }
    }

    /// Handle segment in SYN-RECEIVED state
    pub(super) fn handle_syn_received_segment(
        &mut self,
        tcb: &mut TcpControlBlock,
        tcb_arc: &Arc<PoisonLock<TcpControlBlock>>,
        ack: bool,
        ack_num: u32,
        seq_num: u32,
        header_len: usize,
        payload: &[u8],
        packet_opt: Option<PacketRef>,
        _options_data: Option<&[u8]>,
        flags: u16,
        window: u16,
        current_time: u64,
    ) -> TcpProcessResult {
        // ACK acknowledging our SYN (snd_una + 1)
        if ack && ack_num == tcb.snd_una().wrapping_add(1) {
            // RFC 7323 / 1122: Options like Window Scale, MSS, and SACK-Permitted
            // MUST only be processed in SYN segments. The 3rd ACK of a 3-way handshake
            // is not a SYN segment, so any such options here MUST be ignored.
            // Timestamps and SACK blocks are already handled in the caller (process_segment).

            tcb.set_snd_una(ack_num);
            tcb.set_snd_nxt(ack_num);
            tcb.enter_established();
            self.semi_open_count = self.semi_open_count.saturating_sub(1);

            // Push to backlog and wake accept waker
            if !Self::notify_backlog(tcb, tcb_arc) {
                // Backlog full: close and send RST
                let local = tcb.local_addr();
                let remote = tcb
                    .remote_addr()
                    .unwrap_or(EndpointAddr::new([0, 0, 0, 0], 0));
                tcb.close_and_wake();
                self.connections.remove(&(local, remote));
                return TcpProcessResult::SendPacket {
                    local,
                    remote,
                    seq: ack_num,
                    ack: 0,
                    flags: TcpHeader::FLAG_RST,
                    window: 0,
                    payload: Vec::new(),
                    options: Vec::new(),
                };
            }

            tcb.wake_connect_waiter();

            // Some peers send ACK + first data segment (or FIN) immediately after SYN-ACK.
            // Process that payload/FIN instead of dropping it at state transition.
            let fin = flags & TcpHeader::FLAG_FIN != 0;
            if !payload.is_empty() || fin {
                return Self::handle_established_segment(
                    tcb,
                    ack,
                    ack_num,
                    fin,
                    seq_num,
                    payload,
                    header_len,
                    packet_opt,
                    flags,
                    window,
                    current_time,
                );
            }
        } else if ack {
            // RFC 9293 Section 3.10.7.4: SYN-RECEIVED STATE
            // "If the segment acknowledgment is not acceptable, form a reset segment,
            // <SEQ=SEG.ACK><CTL=RST> and send it."
            log::warn!(
                "[TCP] SYN-RECEIVED: Invalid ACK {} (expected {}), sending RST",
                ack_num,
                tcb.snd_una().wrapping_add(1)
            );
            return TcpProcessResult::SendPacket {
                local: tcb.local_addr(),
                remote: tcb
                    .remote_addr()
                    .unwrap_or(EndpointAddr::new([0, 0, 0, 0], 0)),
                seq: ack_num,
                ack: 0,
                flags: TcpHeader::FLAG_RST,
                window: 0,
                payload: Vec::new(),
                options: Vec::new(),
            };
        }
        TcpProcessResult::None
    }

    /// Push newly established connection to listener backlog and wake accept waker
    pub(super) fn notify_backlog(
        tcb: &TcpControlBlock,
        tcb_arc: &Arc<PoisonLock<TcpControlBlock>>,
    ) -> bool {
        tcb.push_backlog_connection_and_wake(tcb_arc)
    }

    /// Handle segment in ESTABLISHED state
    pub(super) fn handle_established_segment(
        tcb: &mut TcpControlBlock,
        ack: bool,
        ack_num: u32,
        fin: bool,
        seq_num: u32,
        payload: &[u8],
        header_len: usize,
        packet_opt: Option<PacketRef>,
        flags: u16,
        window: u16,
        current_time: u64,
    ) -> TcpProcessResult {
        let payload_len = payload.len();

        // Step 5: Process ACK (updates snd_una)
        let ack_result = Self::handle_established_ack(
            tcb,
            ack,
            ack_num,
            payload_len,
            flags,
            window,
            current_time,
        );

        // Step 7/8: Process Data/FIN (updates rcv_nxt)
        let data_result = if payload_len > 0 || fin {
            Self::handle_established_data(
                tcb,
                seq_num,
                payload,
                header_len,
                packet_opt,
                payload_len,
                fin,
                current_time,
            )
        } else {
            TcpProcessResult::None
        };

        // Decide which result to return. If ack_result is special (e.g. Fast Retransmit),
        // return it with the updated rcv_nxt (since handle_established_data updated it).
        match ack_result {
            TcpProcessResult::SendPacket {
                local,
                remote,
                seq,
                ack: _,
                flags,
                window,
                payload,
                options,
            } => {
                // Return the ack_result packet but with the LATEST ack number
                TcpProcessResult::SendPacket {
                    local,
                    remote,
                    seq,
                    ack: tcb.rcv_nxt(), // Use the updated rcv_nxt
                    flags,
                    window,
                    payload,
                    options,
                }
            }
            TcpProcessResult::None => data_result,
        }
    }

    /// Process ACK in ESTABLISHED state (new ACK or duplicate ACK)
    pub(super) fn handle_established_ack(
        tcb: &mut TcpControlBlock,
        ack: bool,
        ack_num: u32,
        payload_len: usize,
        flags: u16,
        window: u16,
        current_time: u64,
    ) -> TcpProcessResult {
        // Security: RFC 793 validation - only accept ACKs for data actually sent
        if ack
            && Self::seq_after(ack_num, tcb.snd_una())
            && !Self::seq_after(ack_num, tcb.snd_nxt())
        {
            // New ACK - calculate bytes acknowledged
            let bytes_acked = ack_num.wrapping_sub(tcb.snd_una());
            tcb.set_last_ack(ack_num);
            tcb.set_snd_una(ack_num);

            // Remove acknowledged segments from retransmit queue and update RTO (RFC 6298)
            tcb.ack_segments(ack_num, current_time);

            // Congestion control: update cwnd on new ACK
            let is_partial_ack = tcb.on_new_ack(bytes_acked);

            tcb.set_last_snd_wnd(window);
            tcb.wake_write_waiter();

            if is_partial_ack {
                // RFC 6582: Immediate retransmit of the first unacknowledged segment on partial ACK
                if let Some((seq, flags, payload)) =
                    tcb.clone_oldest_unacked_packet_for_retransmit()
                {
                    if let Some(remote) = tcb.remote_addr() {
                        let opts = tcb.build_options(flags);
                        return TcpProcessResult::SendPacket {
                            local: tcb.local_addr(),
                            remote,
                            seq,
                            ack: tcb.rcv_nxt(),
                            flags,
                            window: tcb.rcv_wnd(),
                            payload,
                            options: opts,
                        };
                    }
                }
            }
            TcpProcessResult::None
        } else if ack && ack_num == tcb.snd_una() && tcb.outstanding_bytes() > 0 {
            // Duplicate ACK detection (RFC 5681)
            // An acknowledgment is considered a "duplicate" if:
            // (a) the receiver of the ACK has outstanding data
            // (b) the incoming segment contains no data
            // (c) the SYN and FIN bits are both off
            // (d) the acknowledgment number is equal to the greatest acknowledgment received (snd_una)
            // (e) the advertised window in the incoming segment equals the advertised window in the last segment

            let no_data = payload_len == 0;
            let syn_fin_off = (flags & (TcpHeader::FLAG_SYN | TcpHeader::FLAG_FIN)) == 0;
            let window_unchanged = window == tcb.last_snd_wnd();

            if no_data && syn_fin_off && window_unchanged {
                let res = Self::try_fast_retransmit(tcb);
                tcb.set_last_snd_wnd(window);
                return res;
            }
            tcb.set_last_snd_wnd(window);
            TcpProcessResult::None
        } else if ack && Self::seq_after(ack_num, tcb.snd_nxt()) {
            // RFC 793: SEG.ACK > SND.NXT, send ACK
            tcb.set_last_snd_wnd(window);
            Self::make_ack_result(tcb)
        } else {
            // SEG.ACK <= SND.UNA (Old ACK)
            tcb.set_last_snd_wnd(window);

            // Security: RFC 5961 Section 5.2 (Blind ACK Spoofing Mitigation)
            // An incoming ACK is considered acceptable if SND.UNA - MAX.SND.WND <= SEG.ACK <= SND.NXT
            // If it is too far in the past, we MUST send a challenge ACK.
            if ack {
                let diff = tcb.snd_una().wrapping_sub(ack_num) as i32;
                if diff > (tcb.seq.max_snd_wnd as i32) {
                    // ACK is too far in the past - send challenge ACK
                    log::warn!(
                        "[TCP] RFC 5961: Sending challenge ACK for old ACK {} (SND.UNA={})",
                        ack_num,
                        tcb.snd_una()
                    );
                    return Self::make_ack_result(tcb);
                }
            }
            TcpProcessResult::None
        }
    }

    /// Attempt fast retransmit on duplicate ACK
    pub(super) fn try_fast_retransmit(tcb: &mut TcpControlBlock) -> TcpProcessResult {
        let should_retransmit = tcb.on_dup_ack();
        if should_retransmit {
            // Fast retransmit: immediately resend oldest unacked segment
            if let Some((seq, flags, payload)) = tcb.clone_oldest_unacked_packet_for_retransmit() {
                if let Some(remote) = tcb.remote_addr() {
                    let opts = tcb.build_options(flags);
                    return TcpProcessResult::SendPacket {
                        local: tcb.local_addr(),
                        remote,
                        seq,
                        ack: tcb.rcv_nxt(),
                        flags,
                        window: tcb.rcv_wnd(),
                        payload,
                        options: opts,
                    };
                }
            }
        }
        TcpProcessResult::None
    }

    /// Handle incoming data in ESTABLISHED state
    pub(super) fn handle_established_data(
        tcb: &mut TcpControlBlock,
        seq_num: u32,
        payload: &[u8],
        header_len: usize,
        packet_opt: Option<PacketRef>,
        payload_len: usize,
        fin: bool,
        current_time: u64,
    ) -> TcpProcessResult {
        let rcv_nxt = tcb.rcv_nxt();

        // --- PARTIAL OVERLAP HANDLING ---

        // If the segment starts before rcv_nxt but contains new data after it,
        // we trim the old part so it can be processed as in-order.
        let mut seq_num = seq_num;
        let mut payload = payload;
        let mut payload_len = payload_len;
        let mut packet_opt = packet_opt;

        let diff = rcv_nxt.wrapping_sub(seq_num) as i32;
        if diff > 0 {
            let skip = diff as usize;
            if skip >= payload_len {
                // All payload is old. Only FIN (if any) might be new.
                if fin && skip == payload_len {
                    // FIN starts at rcv_nxt
                    seq_num = rcv_nxt;
                    payload_len = 0;
                    // Note: payload and packet_opt become irrelevant here
                } else {
                    // Entirely old, even including FIN
                    return Self::make_ack_result(tcb);
                }
            } else {
                // Trim prefix
                payload = &payload[skip..];
                payload_len -= skip;
                seq_num = rcv_nxt;
                if let Some(mut pkt) = packet_opt {
                    pkt.advance(skip);
                    packet_opt = Some(pkt);
                }
            }
        }

        if seq_num == rcv_nxt {
            // In-order data
            if payload_len > 0 {
                if !Self::enqueue_inorder_payload(tcb, payload, header_len, packet_opt, payload_len)
                {
                    if tcb.is_closed() {
                        return Self::make_rst_ack_result(tcb);
                    }
                    return Self::make_ack_result(tcb);
                }
                tcb.advance_rcv_nxt(payload_len as u32);
                tcb.record_rx_segment_stats(payload_len);
            }

            // Drain contiguous OOO segments
            let ooo_fin = tcb.drain_ooo_segments();

            // Handle FIN if it is now at the head of the sequence (current or just drained)
            if fin || ooo_fin {
                return Self::handle_established_fin(tcb);
            }

            tcb.wake_read_waiter();
        } else if (seq_num.wrapping_sub(rcv_nxt) as i32) > 0 {
            // Out-of-order data (future) within window
            // Security: Limit global OOO segments to prevent DoS/deadlock
            if GLOBAL_OOO_COUNT.load(Ordering::Relaxed) < GLOBAL_MAX_OOO_SEGMENTS {
                if let Some(packet) = packet_opt {
                    let mut p = packet.clone_ref();
                    p.advance(header_len);
                    p.set_len(payload_len);

                    if tcb.enqueue_ooo_payload(seq_num, p, fin) {
                        let mut sack_end = seq_num.wrapping_add(payload_len as u32);
                        if fin {
                            sack_end = sack_end.wrapping_add(1);
                        }
                        tcb.add_sack_block(seq_num, sack_end);
                    }
                }
            } else {
                log::warn!("[TCP] Global OOO limit reached, dropping segment from future");
            }
        }

        // Both in-order and out-of-order segments require an ACK.
        // For in-order data, we use delayed ACKs to improve efficiency (RFC 1122).
        // Out-of-order data or segments that fill a hole ALWAYS trigger an immediate ACK.

        if (seq_num.wrapping_sub(rcv_nxt) as i32) > 0 {
            // Out-of-order: Immediate ACK
            Self::make_ack_result(tcb)
        } else if tcb.schedule_delayed_ack(current_time) {
            // Second segment or delayed ACK timer expired: Immediate ACK
            Self::make_ack_result(tcb)
        } else {
            // ACK delayed
            TcpProcessResult::None
        }
    }

    /// Enqueue in-order payload to receive buffer, preferring zero-copy
    pub(super) fn enqueue_inorder_payload(
        tcb: &mut TcpControlBlock,
        payload: &[u8],
        header_len: usize,
        packet_opt: Option<PacketRef>,
        payload_len: usize,
    ) -> bool {
        // Security: Check if receive buffer is already full
        if tcb.is_recv_buffer_full() {
            return false;
        }

        let success = if let Some(mut pkt) = packet_opt {
            // Ensure header_len is within packet and adjust view to payload
            if header_len <= pkt.len() && payload_len <= pkt.len() - header_len {
                pkt.advance(header_len);
                pkt.set_len(payload_len);
                tcb.push_recv_packet(pkt);
                true
            } else {
                // View doesn't match expected layout - fallback to copy
                Self::copy_payload_to_recv(tcb, payload, payload_len)
            }
        } else {
            // No PacketRef available - copy into a new PacketRef when possible
            Self::copy_payload_to_recv(tcb, payload, payload_len)
        };

        if success {
            tcb.update_window_from_buffer();
        }
        success
    }

    /// Copy payload into receive buffer (PacketRef優先、失敗時はVecフォールバック)
    pub(super) fn copy_payload_to_recv(
        tcb: &mut TcpControlBlock,
        payload: &[u8],
        payload_len: usize,
    ) -> bool {
        let copy_len = payload_len.min(payload.len());
        let payload = &payload[..copy_len];
        if let Some(mut packet) = crate::net::datapath::mempool::alloc_packet() {
            let data_slice = packet.data_mut();
            if copy_len <= data_slice.len() {
                data_slice[..copy_len].copy_from_slice(payload);
                packet.set_len(copy_len);
                tcb.push_recv_packet(packet);
                tcb.update_window_from_buffer();
                true
            } else {
                // Payload too large for packet - fall back to copied Vec queue
                tcb.enqueue_recv_copy_fallback(payload)
            }
        } else {
            // mempool exhausted - fall back to copied Vec queue
            tcb.enqueue_recv_copy_fallback(payload)
        }
    }

    /// Handle FIN flag in ESTABLISHED state
    pub(super) fn handle_established_fin(tcb: &mut TcpControlBlock) -> TcpProcessResult {
        tcb.advance_rcv_nxt(1);
        tcb.enter_close_wait();
        tcb.wake_read_waiter();
        Self::make_ack_result(tcb)
    }

    /// Handle segment in FIN-WAIT-1 state
    pub(super) fn handle_fin_wait1_segment(
        tcb: &mut TcpControlBlock,
        ack: bool,
        ack_num: u32,
        fin: bool,
        current_time: u64,
    ) -> TcpProcessResult {
        // We sent FIN, waiting for ACK
        if ack && ack_num == tcb.snd_nxt() {
            tcb.set_snd_una(ack_num);
            if fin {
                // Simultaneous close
                tcb.advance_rcv_nxt(1);
                tcb.enter_time_wait(current_time);
                Self::make_ack_result(tcb)
            } else {
                tcb.enter_fin_wait2();
                TcpProcessResult::None
            }
        } else if fin {
            // FIN before ACK
            tcb.advance_rcv_nxt(1);
            tcb.enter_closing();
            Self::make_ack_result(tcb)
        } else {
            TcpProcessResult::None
        }
    }
}

impl Default for TcpProcessor {
    fn default() -> Self {
        Self::new()
    }
}
