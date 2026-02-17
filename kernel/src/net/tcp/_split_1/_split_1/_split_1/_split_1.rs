use super::*;

impl TcpProcessor {

    /// Handle segment in FIN-WAIT-2 state
    fn handle_fin_wait2_segment(
        tcb: &mut TcpControlBlock,
        fin: bool,
        current_time: u64,
    ) -> TcpProcessResult {
        // Waiting for peer's FIN
        if fin {
            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
            tcb.state = TcpState::TimeWait;
            tcb.time_wait_entered = current_time;
            Self::make_ack_result(tcb)
        } else {
            TcpProcessResult::None
        }
    }

    /// Handle segment in CLOSING state
    fn handle_closing_segment(
        tcb: &mut TcpControlBlock,
        ack: bool,
        ack_num: u32,
        current_time: u64,
    ) -> TcpProcessResult {
        // Waiting for ACK of our FIN
        if ack && ack_num == tcb.snd_nxt {
            tcb.snd_una = ack_num;
            tcb.state = TcpState::TimeWait;
            tcb.time_wait_entered = current_time;
        }
        TcpProcessResult::None
    }

    /// Handle segment in LAST-ACK state
    fn handle_last_ack_segment(
        tcb: &mut TcpControlBlock,
        ack: bool,
        ack_num: u32,
    ) -> TcpProcessResult {
        // Waiting for ACK of our FIN
        if ack && ack_num == tcb.snd_nxt {
            tcb.snd_una = ack_num;
            tcb.state = TcpState::Closed;
        }
        TcpProcessResult::None
    }

    /// Handle segment in TIME-WAIT state
    fn handle_time_wait_segment(
        tcb: &mut TcpControlBlock,
        current_time: u64,
    ) -> TcpProcessResult {
        // RFC 793: Wait for 2*MSL (Maximum Segment Lifetime) then move to Closed
        // MSL = 120 seconds, 2*MSL = 240 seconds = 240_000_000 microseconds
        const TWO_MSL_US: u64 = 240_000_000;
        if current_time.saturating_sub(tcb.time_wait_entered) >= TWO_MSL_US {
            tcb.state = TcpState::Closed;
        }
        TcpProcessResult::None
    }

    /// Check if seq1 is after seq2 (handling wrap-around)
    fn seq_after(seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) > 0
    }

    /// Close a connection (initiate active close)
    pub fn close(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) {
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)) {
            if let Ok(mut tcb) = tcb_lock.lock() {
                match tcb.state {
                    TcpState::Established => {
                        let seq = tcb.snd_nxt;
                        let ack = tcb.rcv_nxt;
                        tcb.state = TcpState::FinWait1;
                        // Send FIN+ACK
                        send_fin_packet(local_addr, remote_addr, seq, ack);
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1); // FIN consumes 1 seq
                    }
                    TcpState::CloseWait => {
                        let seq = tcb.snd_nxt;
                        let ack = tcb.rcv_nxt;
                        tcb.state = TcpState::LastAck;
                        // Send FIN+ACK
                        send_fin_packet(local_addr, remote_addr, seq, ack);
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1); // FIN consumes 1 seq
                    }
                    _ => {}
                }
            }
        }
    }

    /// Remove closed and expired TIME_WAIT connections
    pub fn cleanup_closed(&mut self) {
        const TWO_MSL_US: u64 = 240_000_000;
        self.connections.retain(|_, tcb_lock| {
            if let Ok(tcb) = tcb_lock.lock() {
                match tcb.state {
                    TcpState::Closed => false,
                    TcpState::TimeWait => {
                        // Keep if 2MSL has not yet passed
                        // Use last_activity_time as fallback if time_wait_entered is 0
                        let entered = if tcb.time_wait_entered > 0 {
                            tcb.time_wait_entered
                        } else {
                            tcb.last_activity_time
                        };
                        let elapsed = tcb.last_activity_time
                            .max(entered)
                            .saturating_sub(entered);
                        elapsed < TWO_MSL_US
                    }
                    _ => true,
                }
            } else {
                // If lock is poisoned, remove the connection
                false
            }
        });
    }

    /// Check for retransmission timeouts and generate retransmit packets
    /// Returns a vector of `TcpProcessResult::SendPacket` items for timed-out segments.
    pub fn check_retransmissions(&mut self, current_time: u64) -> Vec<TcpProcessResult> {
        let mut results: Vec<TcpProcessResult> = Vec::new();

        for (_key, tcb_arc) in self.connections.iter() {
            if let Ok(mut tcb) = tcb_arc.lock() {
                if tcb.check_retransmit_timeout(current_time) {
                    // Scope the mutable borrow of oldest segment
                    let packet_data = if let Some(oldest) = tcb.unacked_segments.front_mut() {
                        // Update retransmit metadata
                        oldest.sent_time = current_time;
                        oldest.retransmit_count = oldest.retransmit_count.saturating_add(1);
                        // Extract data needed for packet creation
                        Some((oldest.seq, oldest.data.clone()))
                    } else {
                        None
                    };

                    if let Some((seq, payload)) = packet_data {
                        tcb.backoff_rto();
                        tcb.retransmit_count = tcb.retransmit_count.saturating_add(1);
                        
                        // RFC 5681: On RTO, go back to slow start
                        tcb.on_loss();

                        // Build a packet resend (PSH+ACK)
                        if let Some(remote) = tcb.remote_addr {
                            results.push(TcpProcessResult::SendPacket {
                                local: tcb.local_addr,
                                remote,
                                seq,
                                ack: tcb.rcv_nxt,
                                flags: TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK,
                                window: tcb.rcv_wnd,
                                payload,
                            });
                        }
                    }
                }
            }
        }

        results
    }

    /// Process TCP keepalive timers and generate keepalive probes
    /// Returns packets to send for keepalive probes
    pub fn process_keepalives(&mut self, current_time: u64) -> Vec<TcpProcessResult> {
        let mut results = Vec::new();
        let mut dead_connections = Vec::new();

        for (key, tcb_lock) in self.connections.iter() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                match tcb.check_keepalive(current_time) {
                    Some(true) => {
                        // Send keepalive probe: ACK with seq = snd_una - 1
                        if let Some(remote) = tcb.remote_addr {
                            results.push(TcpProcessResult::SendPacket {
                                local: tcb.local_addr,
                                remote,
                                seq: tcb.snd_una.wrapping_sub(1),
                                ack: tcb.rcv_nxt,
                                flags: TcpHeader::FLAG_ACK,
                                window: tcb.rcv_wnd,
                                payload: Vec::new(),
                            });
                        }
                    }
                    Some(false) => {
                        // Connection dead - too many probes without response
                        dead_connections.push(*key);
                    }
                    None => {
                        // No action needed
                    }
                }
            }
        }

        // Mark dead connections as closed
        for key in dead_connections {
            if let Some(tcb_lock) = self.connections.get(&key) {
                if let Ok(mut tcb) = tcb_lock.lock() {
                    tcb.state = TcpState::Closed;
                }
            }
        }

        results
    }

    /// Mark that a retransmit for a given (local, remote, seq) has been sent.
    /// Updates the corresponding unacked segment's sent_time and retransmit counters
    /// and applies RTO backoff.
    pub fn mark_retransmit_sent(&mut self, local: SocketAddr, remote: SocketAddr, seq: u32, current_time: u64) {
        if let Some(tcb_lock) = self.connections.get(&(local, remote)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                if let Some(seg) = tcb.unacked_segments.iter_mut().find(|s| s.seq == seq) {
                    seg.sent_time = current_time;
                    seg.retransmit_count = seg.retransmit_count.saturating_add(1);
                    tcb.backoff_rto();
                    tcb.retransmit_count = tcb.retransmit_count.saturating_add(1);
                    tcb.last_retransmit_time = current_time;
                }
            }
        }
    }

    /// Record that a TCP segment was actually sent on the wire for a connection.
    /// This updates TCB state (snd_nxt) and queues the data for potential retransmit.
    pub fn record_sent_packet(&mut self, local: SocketAddr, remote: SocketAddr, seq: u32, flags: u16, payload: &[u8], current_time: u64) {
        if let Some(tcb_lock) = self.connections.get(&(local, remote)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                // Determine how many sequence numbers are consumed
                let mut consumed: u32 = payload.len() as u32;
                if flags & TcpHeader::FLAG_SYN != 0 {
                    consumed = consumed.saturating_add(1);
                }
                if flags & TcpHeader::FLAG_FIN != 0 {
                    consumed = consumed.saturating_add(1);
                }

                if consumed > 0 {
                    // Queue for retransmission
                    tcb.queue_unacked(seq, payload.to_vec(), current_time, flags);
                    tcb.last_retransmit_time = current_time;
                    // Advance snd_nxt to reflect the bytes consumed
                    tcb.snd_nxt = seq.wrapping_add(consumed);
                }
            }
        }
    }
}
