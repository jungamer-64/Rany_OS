use super::*;


mod state_handlers;
impl TcpProcessor {
    /// Default maximum number of concurrent TCP connections
    pub const DEFAULT_MAX_CONNECTIONS: usize = 512;

    /// Create a new TCP processor
    pub fn new() -> Self {
        TcpProcessor {
            connections: BTreeMap::new(),
            listeners: BTreeMap::new(),
        }
    }

    /// Start listening on a local address
    pub fn listen(&mut self, local_addr: SocketAddr) {
        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.enter_listen();
        self.listeners.insert(local_addr, Arc::new(PoisonLock::new(tcb)));
    }
    
    /// Bind to a specific port
    pub fn bind(&mut self, addr: SocketAddr) -> Result<TcpListener, TcpError> {
        if self.listeners.contains_key(&addr) || 
           self.connections.keys().any(|(local, _)| local == &addr) {
            return Err(TcpError::AddressInUse);
        }
        
        // Create shared state for backlog and waker
        let backlog = Arc::new(PoisonLock::new(VecDeque::new()));
        let accept_waker = Arc::new(crate::sync::atomic_waker::AtomicWaker::new());

        // Create TCB with this shared state
        let mut tcb = TcpControlBlock::new(addr);
        tcb.enter_listen();
        tcb.set_listener_waiters(backlog.clone(), accept_waker.clone());
        
        // Wrap in Arc<PoisonLock>
        let tcb_arc = Arc::new(PoisonLock::new(tcb));
        
        self.listeners.insert(addr, tcb_arc);
        
        Ok(TcpListener {
            local_addr: addr,
            backlog,
            accept_waker,
        })
    }

    /// Initiate a connection to a remote address
    pub fn connect(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<TcpStream, TcpError> {
        if self.connections.len() >= Self::DEFAULT_MAX_CONNECTIONS {
            return Err(TcpError::BufferFull);
        }

        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.set_remote_addr(remote_addr);
        tcb.enter_syn_sent();
        let random_bytes = crate::net::tls::crypto::generate_random();
        let isn = u32::from_le_bytes([random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3]]);
        tcb.set_snd_nxt(isn);
        tcb.set_snd_una(isn);

        let tcb_arc = Arc::new(PoisonLock::new(tcb));

        self.connections.insert(
            (local_addr, remote_addr),
            tcb_arc.clone(),
        );
        // Note: Caller should send SYN packet after this (handled by stack wrapper or here?)
        // Better if caller does it, or we return an action.
        // But connect() is synchronous state setup.
        
        Ok(TcpStream { tcb: tcb_arc })
    }

    /// Test-only helper to seed an existing connection.
    #[cfg(any(test, feature = "full_mm_tests", feature = "qemu-test-export"))]
    pub fn insert_test_connection(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        tcb: Arc<PoisonLock<TcpControlBlock>>,
    ) {
        self.connections.insert((local_addr, remote_addr), tcb);
    }



    /// Process an incoming TCP segment
    pub fn process(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, current_time: u64) -> TcpProcessResult {
        if data.len() < TcpHeader::MIN_HEADER_LEN {
            return TcpProcessResult::None;
        }

        // Read header fields directly from bytes to avoid packed struct alignment issues
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
        let flags = data_offset_flags & 0x003F;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        if header_len < TcpHeader::MIN_HEADER_LEN || header_len > data.len() {
            return TcpProcessResult::None;
        }

        // Convert to internal address types
        let remote_addr = SocketAddr::new(
            Ipv4Addr::new(
                src_ip.as_bytes()[0],
                src_ip.as_bytes()[1],
                src_ip.as_bytes()[2],
                src_ip.as_bytes()[3],
            ),
            src_port,
        );

        let local_addr = SocketAddr::new(
            Ipv4Addr::new(
                dst_ip.as_bytes()[0],
                dst_ip.as_bytes()[1],
                dst_ip.as_bytes()[2],
                dst_ip.as_bytes()[3],
            ),
            dst_port,
        );

        // Extract payload
        let payload = if data.len() > header_len {
            &data[header_len..]
        } else {
            &[]
        };

        // Try to find existing connection
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                return self.process_segment(&tcb_lock, &mut *tcb, seq_num, ack_num, flags, window, header_len, payload, None, current_time);
            }
        }

        // Check if this is for a listening socket
        if let Some(result) = self.handle_incoming_syn(local_addr, remote_addr, seq_num, flags, window) {
            return result;
        }

        // No matching connection or listener - ignore or send RST
        TcpProcessResult::None
    }

    /// IPv6 variant of `process` — accepts IPv6 source/destination and uses `SocketAddr::V6` keys.
    pub fn process_v6(
        &mut self,
        data: &[u8],
        src_ip: crate::net::ipv6::Ipv6Address,
        dst_ip: crate::net::ipv6::Ipv6Address,
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
        let flags = data_offset_flags & 0x003F;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        if header_len < TcpHeader::MIN_HEADER_LEN || header_len > data.len() {
            return TcpProcessResult::None;
        }

        // Convert to internal address types (SocketAddr::V6)
        let remote_addr = SocketAddr::new_v6(src_ip, src_port);
        let local_addr = SocketAddr::new_v6(dst_ip, dst_port);

        // Extract payload
        let payload = if data.len() > header_len {
            &data[header_len..]
        } else {
            &[]
        };

        // Try to find existing connection
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                return self.process_segment(&tcb_lock, &mut *tcb, seq_num, ack_num, flags, window, header_len, payload, None, current_time);
            }
        }

        // Check if this is for a listening socket
        if let Some(result) = self.handle_incoming_syn(local_addr, remote_addr, seq_num, flags, window) {
            return result;
        }

        // No matching connection or listener - ignore or send RST
        TcpProcessResult::None
    }

    pub(super) fn handle_incoming_syn(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        seq_num: u32,
        flags: u16,
        window: u16,
    ) -> Option<TcpProcessResult> {
        let listener_addr = if self.listeners.contains_key(&local_addr) {
            local_addr
        } else {
            let port = local_addr.port();

            // Prefer IPv4 wildcard when the packet address is IPv4-mapped.
            if local_addr.as_ipv4().is_some() {
                let wildcard_v4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED, port);
                if self.listeners.contains_key(&wildcard_v4) {
                    wildcard_v4
                } else {
                    let wildcard_v6 =
                        SocketAddr::new_v6(crate::net::ipv6::Ipv6Address::UNSPECIFIED, port);
                    if self.listeners.contains_key(&wildcard_v6) {
                        wildcard_v6
                    } else {
                        return None;
                    }
                }
            } else {
                let wildcard_v6 =
                    SocketAddr::new_v6(crate::net::ipv6::Ipv6Address::UNSPECIFIED, port);
                if self.listeners.contains_key(&wildcard_v6) {
                    wildcard_v6
                } else {
                    return None;
                }
            }
        };

        let listener_lock = self.listeners.get(&listener_addr)?;
        let listener = listener_lock.lock().ok()?;
        if !listener.is_listen() || flags & TcpHeader::FLAG_SYN == 0 {
            return None;
        }

        // Check total connection limit (SYN flood protection)
        if self.connections.len() >= Self::DEFAULT_MAX_CONNECTIONS {
            return None;
        }

        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.set_remote_addr(remote_addr);
        tcb.set_rcv_nxt(seq_num.wrapping_add(1));
        tcb.set_rcv_wnd(65535);
        tcb.enter_syn_received();

        let random_bytes = crate::net::tls::crypto::generate_random();
        let isn = u32::from_le_bytes([random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3]]);
        tcb.set_snd_nxt(isn);
        tcb.set_snd_una(isn);

        let syn_ack = TcpProcessResult::SendPacket {
            local: local_addr,
            remote: remote_addr,
            seq: tcb.snd_nxt(),
            ack: tcb.rcv_nxt(),
            flags: TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
            window: 65535,
            payload: Vec::new(),
        };

        drop(listener);
        self.connections.insert(
            (local_addr, remote_addr),
            Arc::new(PoisonLock::new(tcb)),
        );
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
        let flags = data_offset_flags & 0x003F;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        if header_len < TcpHeader::MIN_HEADER_LEN || header_len > data.len() {
            return TcpProcessResult::None;
        }

        // Convert to internal address types
        let remote_addr = SocketAddr::new(
            Ipv4Addr::new(
                src_ip.as_bytes()[0],
                src_ip.as_bytes()[1],
                src_ip.as_bytes()[2],
                src_ip.as_bytes()[3],
            ),
            src_port,
        );

        let local_addr = SocketAddr::new(
            Ipv4Addr::new(
                dst_ip.as_bytes()[0],
                dst_ip.as_bytes()[1],
                dst_ip.as_bytes()[2],
                dst_ip.as_bytes()[3],
            ),
            dst_port,
        );

        // Extract payload
        let payload = if data.len() > header_len { &data[header_len..] } else { &[] };

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
        src_ip: crate::net::ipv6::Ipv6Address,
        dst_ip: crate::net::ipv6::Ipv6Address,
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
        let flags = data_offset_flags & 0x003F;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let header_len = ((data_offset_flags >> 12) & 0x0F) as usize * 4;

        if header_len < TcpHeader::MIN_HEADER_LEN || header_len > data.len() {
            return TcpProcessResult::None;
        }

        // Convert to internal address types
        let remote_addr = SocketAddr::new_v6(src_ip, src_port);
        let local_addr = SocketAddr::new_v6(dst_ip, dst_port);

        // Extract payload
        let payload = if data.len() > header_len { &data[header_len..] } else { &[] };

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
    pub(super) fn make_ack_result(tcb: &TcpControlBlock) -> TcpProcessResult {
        let Some(remote) = tcb.remote_addr() else {
            return TcpProcessResult::None;
        };
        TcpProcessResult::SendPacket {
            local: tcb.local_addr(),
            remote,
            seq: tcb.snd_nxt(),
            ack: tcb.rcv_nxt(),
            flags: TcpHeader::FLAG_ACK,
            window: tcb.rcv_wnd(),
            payload: Vec::new(),
        }
    }

    /// Create an RST|ACK packet result from current TCB state
    pub(super) fn make_rst_ack_result(tcb: &TcpControlBlock) -> TcpProcessResult {
        let Some(remote) = tcb.remote_addr() else {
            return TcpProcessResult::None;
        };
        TcpProcessResult::SendPacket {
            local: tcb.local_addr(),
            remote,
            seq: tcb.snd_nxt(),
            ack: tcb.rcv_nxt(),
            flags: TcpHeader::FLAG_RST | TcpHeader::FLAG_ACK,
            window: tcb.rcv_wnd(),
            payload: Vec::new(),
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

        // Security (RFC 5961): RST sequence number validation
        if rst {
            if seq_num == tcb.rcv_nxt() {
                // Exact match: accept RST and close
                let local = tcb.local_addr();
                if let Some(remote) = tcb.remote_addr() {
                    tcb.close_and_wake();
                    self.connections.remove(&(local, remote));
                }
                return TcpProcessResult::None;
            } else if (seq_num.wrapping_sub(tcb.rcv_nxt()) as i32) >= 0
                && (seq_num.wrapping_sub(tcb.rcv_nxt().wrapping_add(tcb.rcv_wnd() as u32)) as i32) < 0
            {
                // Within window but not exact match: send challenge ACK
                return Self::make_ack_result(tcb);
            } else {
                // Outside window: ignore
                return TcpProcessResult::None;
            }
        }

        // Security (RFC 5961): SYN validation for established connections
        if syn && tcb.state() != TcpState::SynSent {
            // Unexpected SYN on existing connection - send challenge ACK
            return Self::make_ack_result(tcb);
        }

        // Update send window
        if ack {
            tcb.set_snd_wnd(window);
        }

        match tcb.state() {
            TcpState::Closed | TcpState::Listen | TcpState::CloseWait => {
                // Closed: ignore; Listen: handled in main process(); CloseWait: handled by close()
                TcpProcessResult::None
            }
            TcpState::SynSent => Self::handle_syn_sent_segment(tcb, syn, ack, seq_num, ack_num),
            TcpState::SynReceived => Self::handle_syn_received_segment(
                tcb,
                tcb_arc,
                ack,
                ack_num,
                seq_num,
                header_len,
                payload,
                packet_opt,
            ),
            TcpState::Established => {
                Self::handle_established_segment(tcb, ack, ack_num, fin, seq_num, payload, header_len, packet_opt)
            }
            TcpState::FinWait1 => Self::handle_fin_wait1_segment(tcb, ack, ack_num, fin, current_time),
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
    ) -> TcpProcessResult {
        // Waiting for SYN-ACK
        // Accept ACK that acknowledges the initial SYN (snd_una + 1)
        if syn && ack && ack_num == tcb.snd_una().wrapping_add(1) {
            tcb.set_snd_una(ack_num);
            tcb.set_snd_nxt(ack_num);
            tcb.set_rcv_nxt(seq_num.wrapping_add(1));
            tcb.enter_established();
            // Wake connect waker
            tcb.wake_connect_waiter();
            // Send ACK
            Self::make_ack_result(tcb)
        } else if syn && !ack {
            // Simultaneous open
            tcb.set_rcv_nxt(seq_num.wrapping_add(1));
            tcb.enter_syn_received();
            // Send SYN-ACK
            let Some(remote) = tcb.remote_addr() else {
                return TcpProcessResult::None;
            };
            TcpProcessResult::SendPacket {
                local: tcb.local_addr(),
                remote,
                seq: tcb.snd_nxt(),
                ack: tcb.rcv_nxt(),
                flags: TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
                window: tcb.rcv_wnd(),
                payload: Vec::new(),
            }
        } else {
            TcpProcessResult::None
        }
    }

    /// Handle segment in SYN-RECEIVED state
    pub(super) fn handle_syn_received_segment(
        tcb: &mut TcpControlBlock,
        tcb_arc: &Arc<PoisonLock<TcpControlBlock>>,
        ack: bool,
        ack_num: u32,
        seq_num: u32,
        header_len: usize,
        payload: &[u8],
        packet_opt: Option<PacketRef>,
    ) -> TcpProcessResult {
        // ACK acknowledging our SYN (snd_una + 1)
        if ack && ack_num == tcb.snd_una().wrapping_add(1) {
            tcb.set_snd_una(ack_num);
            tcb.set_snd_nxt(ack_num);
            tcb.enter_established();

            // Push to backlog and wake accept waker
            Self::notify_backlog(tcb, tcb_arc);

            tcb.wake_connect_waiter();

            // Some peers send ACK + first data segment immediately after SYN-ACK.
            // Process that payload instead of dropping it at state transition.
            if !payload.is_empty() {
                return Self::handle_established_segment(
                    tcb,
                    ack,
                    ack_num,
                    false,
                    seq_num,
                    payload,
                    header_len,
                    packet_opt,
                );
            }
        }
        TcpProcessResult::None
    }

    /// Push newly established connection to listener backlog and wake accept waker
    pub(super) fn notify_backlog(
        tcb: &TcpControlBlock,
        tcb_arc: &Arc<PoisonLock<TcpControlBlock>>,
    ) {
        tcb.push_backlog_connection_and_wake(tcb_arc);
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
    ) -> TcpProcessResult {
        let payload_len = payload.len();
        let mut result = Self::handle_established_ack(tcb, ack, ack_num);

        if payload_len > 0 {
            result = Self::handle_established_data(tcb, seq_num, payload, header_len, packet_opt, payload_len);
            if tcb.is_closed() {
                return result;
            }
        }

        if fin {
            result = Self::handle_established_fin(tcb);
        }

        result
    }

    /// Process ACK in ESTABLISHED state (new ACK or duplicate ACK)
    pub(super) fn handle_established_ack(
        tcb: &mut TcpControlBlock,
        ack: bool,
        ack_num: u32,
    ) -> TcpProcessResult {
        if ack && Self::seq_after(ack_num, tcb.snd_una()) {
            // New ACK - calculate bytes acknowledged
            let bytes_acked = ack_num.wrapping_sub(tcb.snd_una());
            tcb.set_last_ack(ack_num);
            tcb.set_snd_una(ack_num);

            // Remove acknowledged segments from retransmit queue
            tcb.ack_segments(ack_num);

            // Congestion control: update cwnd on new ACK
            tcb.on_new_ack(bytes_acked);

            tcb.wake_write_waiter();
            TcpProcessResult::None
        } else if ack && ack_num == tcb.snd_una() && tcb.outstanding_bytes() > 0 {
            // Duplicate ACK - same ack_num but we have outstanding data
            Self::try_fast_retransmit(tcb)
        } else {
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
                    return TcpProcessResult::SendPacket {
                        local: tcb.local_addr(),
                        remote,
                        seq,
                        ack: tcb.rcv_nxt(),
                        flags,
                        window: tcb.rcv_wnd(),
                        payload,
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
    ) -> TcpProcessResult {
        if seq_num == tcb.rcv_nxt() {
            // In-order data
            if !Self::enqueue_inorder_payload(tcb, payload, header_len, packet_opt, payload_len) {
                // 受信フォールバック上限超過時は fail-close して RST を返す。
                if tcb.is_closed() {
                    return Self::make_rst_ack_result(tcb);
                }
                // ドロップ/未格納の場合はシーケンス番号を進めず、既存のACKを返す
                return Self::make_ack_result(tcb);
            }

            // Update stats
            tcb.advance_rcv_nxt(payload_len as u32);
            tcb.record_rx_segment_stats(payload_len);

            tcb.wake_read_waiter();
        }
        // Both in-order and out-of-order: send ACK for expected seq
        Self::make_ack_result(tcb)
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
        if let Some(mut packet) = crate::net::mempool::alloc_packet() {
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

// ============================================================================
// テスト
// ============================================================================

#[cfg(any(test, feature = "qemu-test-export"))]
#[path = "../../tests.rs"]
pub mod tests;
