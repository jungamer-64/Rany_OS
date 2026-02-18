use super::*;


mod _split_1;
impl TcpProcessor {
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
        tcb.state = TcpState::Listen;
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
        let accept_waker = Arc::new(PoisonLock::new(None));

        // Create TCB with this shared state
        let mut tcb = TcpControlBlock::new(addr);
        tcb.state = TcpState::Listen;
        tcb.backlog = Some(backlog.clone());
        tcb.accept_waker = Some(accept_waker.clone());
        
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
        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.remote_addr = Some(remote_addr);
        tcb.state = TcpState::SynSent;
        // Generate initial sequence number (simplified: use tick count)
        tcb.snd_nxt = crate::task::timer::current_tick() as u32;
        tcb.snd_una = tcb.snd_nxt;

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

        // Handle RST - reset connection immediately
        if flags & TcpHeader::FLAG_RST != 0 {
            self.connections.remove(&(local_addr, remote_addr));
            return TcpProcessResult::None;
        }

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
        let listener_lock = self.listeners.get(&local_addr)?;
        let listener = listener_lock.lock().ok()?;
        if listener.state != TcpState::Listen || flags & TcpHeader::FLAG_SYN == 0 {
            return None;
        }

        let mut tcb = TcpControlBlock::new(local_addr);
        tcb.remote_addr = Some(remote_addr);
        tcb.state = TcpState::SynReceived;
        tcb.rcv_nxt = seq_num.wrapping_add(1);
        tcb.snd_nxt = crate::task::timer::current_tick() as u32;
        tcb.snd_una = tcb.snd_nxt;
        tcb.snd_wnd = window;
        tcb.backlog = listener.backlog.clone();
        tcb.accept_waker = listener.accept_waker.clone();

        let syn_ack = TcpProcessResult::SendPacket {
            local: local_addr,
            remote: remote_addr,
            seq: tcb.snd_nxt,
            ack: tcb.rcv_nxt,
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

        // Handle RST - reset connection immediately
        if flags & TcpHeader::FLAG_RST != 0 {
            self.connections.remove(&(local_addr, remote_addr));
            return TcpProcessResult::None;
        }

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

    /// Create an ACK packet result from current TCB state
    pub(super) fn make_ack_result(tcb: &TcpControlBlock) -> TcpProcessResult {
        TcpProcessResult::SendPacket {
            local: tcb.local_addr,
            remote: tcb.remote_addr.unwrap(),
            seq: tcb.snd_nxt,
            ack: tcb.rcv_nxt,
            flags: TcpHeader::FLAG_ACK,
            window: tcb.rcv_wnd,
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
        let syn = flags & TcpHeader::FLAG_SYN != 0;
        let ack = flags & TcpHeader::FLAG_ACK != 0;
        let fin = flags & TcpHeader::FLAG_FIN != 0;
        let _psh = flags & TcpHeader::FLAG_PSH != 0;

        // Update send window
        if ack {
            tcb.snd_wnd = window;
        }

        match tcb.state {
            TcpState::Closed | TcpState::Listen | TcpState::CloseWait => {
                // Closed: ignore; Listen: handled in main process(); CloseWait: handled by close()
                TcpProcessResult::None
            }
            TcpState::SynSent => Self::handle_syn_sent_segment(tcb, syn, ack, seq_num, ack_num),
            TcpState::SynReceived => Self::handle_syn_received_segment(tcb, tcb_arc, ack, ack_num),
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
        if syn && ack && ack_num == tcb.snd_una.wrapping_add(1) {
            tcb.snd_una = ack_num;
            tcb.snd_nxt = ack_num;
            tcb.rcv_nxt = seq_num.wrapping_add(1);
            tcb.state = TcpState::Established;
            // Wake connect waker
            if let Some(waker) = tcb.connect_waker.take() {
                waker.wake();
            }
            // Send ACK
            Self::make_ack_result(tcb)
        } else if syn && !ack {
            // Simultaneous open
            tcb.rcv_nxt = seq_num.wrapping_add(1);
            tcb.state = TcpState::SynReceived;
            // Send SYN-ACK
            TcpProcessResult::SendPacket {
                local: tcb.local_addr,
                remote: tcb.remote_addr.unwrap(),
                seq: tcb.snd_nxt,
                ack: tcb.rcv_nxt,
                flags: TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK,
                window: tcb.rcv_wnd,
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
    ) -> TcpProcessResult {
        // ACK acknowledging our SYN (snd_una + 1)
        if ack && ack_num == tcb.snd_una.wrapping_add(1) {
            tcb.snd_una = ack_num;
            tcb.snd_nxt = ack_num;
            tcb.state = TcpState::Established;

            // Push to backlog and wake accept waker
            Self::notify_backlog(tcb, tcb_arc);

            if let Some(waker) = tcb.connect_waker.take() {
                waker.wake();
            }
        }
        TcpProcessResult::None
    }

    /// Push newly established connection to listener backlog and wake accept waker
    pub(super) fn notify_backlog(
        tcb: &TcpControlBlock,
        tcb_arc: &Arc<PoisonLock<TcpControlBlock>>,
    ) {
        if let Some(backlog_lock) = &tcb.backlog {
            if let Ok(mut backlog) = backlog_lock.lock() {
                backlog.push_back(TcpStream { tcb: tcb_arc.clone() });

                if let Some(waker_lock) = &tcb.accept_waker {
                    if let Ok(mut waker_opt) = waker_lock.lock() {
                        if let Some(waker) = waker_opt.take() {
                            waker.wake();
                        }
                    }
                }
            }
        }
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
        if ack && Self::seq_after(ack_num, tcb.snd_una) {
            // New ACK - calculate bytes acknowledged
            let bytes_acked = ack_num.wrapping_sub(tcb.snd_una);
            tcb.last_ack = ack_num;
            tcb.snd_una = ack_num;

            // Remove acknowledged segments from retransmit queue
            tcb.ack_segments(ack_num);

            // Congestion control: update cwnd on new ACK
            tcb.on_new_ack(bytes_acked);

            if let Some(waker) = tcb.write_waker.take() {
                waker.wake();
            }
            TcpProcessResult::None
        } else if ack && ack_num == tcb.snd_una && tcb.outstanding_bytes > 0 {
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
            if let Some(oldest) = tcb.unacked_segments.front() {
                if let Some(remote) = tcb.remote_addr {
                    return TcpProcessResult::SendPacket {
                        local: tcb.local_addr,
                        remote,
                        seq: oldest.seq,
                        ack: tcb.rcv_nxt,
                        flags: oldest.flags,
                        window: tcb.rcv_wnd,
                        payload: oldest.data.clone(),
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
        if seq_num == tcb.rcv_nxt {
            // In-order data - Update stats
            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);
            tcb.stats.bytes_received += payload_len as u64;
            tcb.stats.packets_received += 1;

            Self::enqueue_inorder_payload(tcb, payload, header_len, packet_opt, payload_len);

            if let Some(waker) = tcb.read_waker.take() {
                waker.wake();
            }
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
    ) {
        if let Some(mut pkt) = packet_opt {
            // Ensure header_len is within packet and adjust view to payload
            if header_len <= pkt.len() && payload_len <= pkt.len() - header_len {
                pkt.advance(header_len);
                pkt.set_len(payload_len);
                tcb.recv_buffer.push_back(pkt);
            } else {
                // View doesn't match expected layout - fallback to copy
                Self::copy_payload_to_recv(tcb, payload, payload_len);
            }
        } else {
            // No PacketRef available - copy into a new PacketRef when possible
            Self::copy_payload_to_recv(tcb, payload, payload_len);
        }
    }

    /// Copy payload into receive buffer (mempool PacketRef or Vec fallback)
    pub(super) fn copy_payload_to_recv(
        tcb: &mut TcpControlBlock,
        payload: &[u8],
        payload_len: usize,
    ) {
        if let Some(mut packet) = super::mempool::alloc_packet() {
            let data_slice = packet.data_mut();
            if payload_len <= data_slice.len() {
                data_slice[..payload_len].copy_from_slice(payload);
                packet.set_len(payload_len);
                tcb.recv_buffer.push_back(packet);
            } else {
                // Payload too large for packet, use Vec fallback
                tcb.recv_queue.push_back(payload.to_vec());
            }
        } else {
            // mempool exhausted - fallback to copy
            tcb.recv_queue.push_back(payload.to_vec());
        }
    }

    /// Handle FIN flag in ESTABLISHED state
    pub(super) fn handle_established_fin(tcb: &mut TcpControlBlock) -> TcpProcessResult {
        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
        tcb.state = TcpState::CloseWait;
        if let Some(waker) = tcb.read_waker.take() {
            waker.wake();
        }
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
        if ack && ack_num == tcb.snd_nxt {
            tcb.snd_una = ack_num;
            if fin {
                // Simultaneous close
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                tcb.state = TcpState::TimeWait;
                tcb.time_wait_entered = current_time;
                Self::make_ack_result(tcb)
            } else {
                tcb.state = TcpState::FinWait2;
                TcpProcessResult::None
            }
        } else if fin {
            // FIN before ACK
            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
            tcb.state = TcpState::Closing;
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

#[cfg(test)]
#[path = "../../tests.rs"]
mod tests;
