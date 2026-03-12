use super::*;
use alloc::vec;

impl TcpProcessor {
    /// Handle segment in FIN-WAIT-2 state
    pub(super) fn handle_fin_wait2_segment(
        tcb: &mut TcpControlBlock,
        fin: bool,
        current_time: u64,
    ) -> TcpProcessResult {
        // Waiting for peer's FIN
        if fin {
            tcb.advance_rcv_nxt(1);
            tcb.enter_time_wait(current_time);
            Self::make_ack_result(tcb)
        } else {
            TcpProcessResult::None
        }
    }

    /// Handle segment in CLOSING state
    pub(super) fn handle_closing_segment(
        tcb: &mut TcpControlBlock,
        ack: bool,
        ack_num: u32,
        current_time: u64,
    ) -> TcpProcessResult {
        // Waiting for ACK of our FIN
        if ack && ack_num == tcb.snd_nxt() {
            tcb.set_snd_una(ack_num);
            tcb.enter_time_wait(current_time);
        }
        TcpProcessResult::None
    }

    /// Handle segment in LAST-ACK state
    pub(super) fn handle_last_ack_segment(
        tcb: &mut TcpControlBlock,
        ack: bool,
        ack_num: u32,
    ) -> TcpProcessResult {
        // Waiting for ACK of our FIN
        if ack && ack_num == tcb.snd_nxt() {
            tcb.set_snd_una(ack_num);
            tcb.close_and_wake();
        }
        TcpProcessResult::None
    }

    /// Handle segment in TIME-WAIT state
    pub(super) fn handle_time_wait_segment(
        tcb: &mut TcpControlBlock,
        current_time: u64,
    ) -> TcpProcessResult {
        // RFC 793 / 9293: Wait for 2*MSL (Maximum Segment Lifetime) then move to Closed
        // MSL = 120 seconds, 2*MSL = 240 seconds = 240,000 milliseconds
        const TWO_MSL_MS: u64 = 240_000;
        if current_time.saturating_sub(tcb.time_wait_entered_at()) >= TWO_MSL_MS {
            tcb.close_and_wake();
            return TcpProcessResult::None;
        }

        // RFC 9293 Section 3.10.7.4: "Any segment received in the TIME-WAIT state MUST be acknowledged.
        // This re-acknowledges the peer's FIN and restarts the 2MSL timer."
        tcb.enter_time_wait(current_time);
        Self::make_ack_result(tcb)
    }

    /// Check if seq1 is after seq2 (handling wrap-around)
    pub(crate) fn seq_after(seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) > 0
    }

    /// Close a connection (initiate active close)
    pub fn close(&mut self, local_addr: EndpointAddr, remote_addr: EndpointAddr) {
        if let Some(tcb_lock) = self.connections.get(&(local_addr, remote_addr)) {
            if let Ok(mut tcb) = tcb_lock.lock() {
                match tcb.state() {
                    TcpState::Established => {
                        let seq = tcb.snd_nxt();
                        let ack = tcb.rcv_nxt();
                        tcb.begin_active_close();
                        // Send FIN+ACK
                        send_fin_packet(local_addr, remote_addr, seq, ack);
                        tcb.advance_snd_nxt(1); // FIN consumes 1 seq
                    }
                    TcpState::CloseWait => {
                        let seq = tcb.snd_nxt();
                        let ack = tcb.rcv_nxt();
                        tcb.begin_passive_close_reply();
                        // Send FIN+ACK
                        send_fin_packet(local_addr, remote_addr, seq, ack);
                        tcb.advance_snd_nxt(1); // FIN consumes 1 seq
                    }
                    _ => {}
                }
            }
        }
    }

    /// Remove closed and expired connections
    pub fn cleanup_closed(&mut self) {
        // Standard TCP timeouts in milliseconds (matching current_tick())
        const TWO_MSL_MS: u64 = 240_000;
        const HANDSHAKE_TIMEOUT_MS: u64 = 20_000; // 20 seconds for handshake (DoS protection)
        let current_time = crate::task::current_tick();
        let mut semi_open_removed = 0;

        self.connections.retain(|_, tcb_lock| {
            match tcb_lock.lock() {
                Ok(tcb) => {
                    let (should_remove, is_semi_open) = match tcb.state() {
                        TcpState::Closed => (true, false),
                        TcpState::TimeWait => {
                            // Keep if 2MSL has not yet passed
                            let entered = tcb.time_wait_entered_or_last_activity();
                            let elapsed = current_time.saturating_sub(entered);
                            (!(elapsed < TWO_MSL_MS), false)
                        }
                        TcpState::SynSent | TcpState::SynReceived => {
                            // Remove stale handshakes (DoS protection)
                            let elapsed = current_time.saturating_sub(tcb.created_at());
                            (!(elapsed < HANDSHAKE_TIMEOUT_MS), true)
                        }
                        _ => (false, false),
                    };
                    if should_remove && is_semi_open {
                        semi_open_removed += 1;
                    }
                    !should_remove
                }
                Err(_) => {
                    // If lock is poisoned, remove the connection.
                    // We can't safely know if it was semi-open, but we assume it might have been
                    // if the counter is non-zero to avoid permanent DoS.
                    // However, we don't have enough info here. For safety, we just remove it.
                    false
                }
            }
        });

        self.semi_open_count = self.semi_open_count.saturating_sub(semi_open_removed);
    }

    /// Check for retransmission timeouts and generate retransmit packets
    /// Returns a vector of `TcpProcessResult::SendPacket` items for timed-out segments.
    pub fn check_retransmissions(&mut self, current_time: u64) -> Vec<TcpProcessResult> {
        let mut results: Vec<TcpProcessResult> = Vec::new();
        let mut timed_out_connections = Vec::new();

        for (key, tcb_arc) in self.connections.iter() {
            if let Ok(mut tcb) = tcb_arc.lock() {
                // 1. Check for delayed ACK timeout (RFC 1122)
                if tcb.check_delayed_ack_timeout(current_time) {
                    tcb.clear_delayed_ack();
                    results.push(TcpProcessor::make_ack_result(&mut *tcb));
                }

                // 2. Check for retransmission timeout
                if tcb.check_retransmit_timeout(current_time) {
                    // RFC 1122: Check if maximum retransmission threshold reached
                    // Standard TCP typically uses 15, but for this OS we use 10.
                    if tcb.timers.retransmit_count >= 10 {
                        log::info!(
                            "[TCP] Connection timed out after {} retransmissions",
                            tcb.timers.retransmit_count
                        );
                        timed_out_connections.push(*key);
                        continue;
                    }

                    // Scope the mutable borrow of oldest segment
                    let packet_data = tcb.touch_oldest_unacked_for_retransmit(current_time);

                    if let Some((seq, payload)) = packet_data {
                        tcb.backoff_rto();

                        // RFC 5681: On RTO, go back to slow start
                        tcb.on_loss();

                        // Build a packet resend (PSH+ACK)
                        if let Some(remote) = tcb.remote_addr() {
                            let flags = TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK;
                            let opts = tcb.build_options(flags);
                            results.push(TcpProcessResult::SendPacket {
                                local: tcb.local_addr(),
                                remote,
                                seq,
                                ack: tcb.rcv_nxt(),
                                flags,
                                window: tcb.rcv_wnd(),
                                payload,
                                options: opts,
                            });
                        }
                    }
                }
            }
        }

        // Close and remove connections that reached retransmit limit
        for key in timed_out_connections {
            if let Some(tcb_lock) = self.connections.remove(&key) {
                if let Ok(mut tcb) = tcb_lock.lock() {
                    tcb.close_and_wake();
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
                        if let Some(remote) = tcb.remote_addr() {
                            let flags = TcpHeader::FLAG_ACK;
                            let opts = tcb.build_options(flags);
                            results.push(TcpProcessResult::SendPacket {
                                local: tcb.local_addr(),
                                remote,
                                seq: tcb.snd_una().wrapping_sub(1),
                                ack: tcb.rcv_nxt(),
                                flags,
                                window: tcb.rcv_wnd(),
                                payload: Vec::new(),
                                options: opts,
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
                    tcb.close_and_wake();
                }
            }
        }

        results
    }

    /// Process zero-window probes for connections with peer window = 0
    /// Returns packets to send (ACK probes with seq = snd_nxt)
    pub fn process_zero_window_probes(&mut self, current_time: u64) -> Vec<TcpProcessResult> {
        let mut results = Vec::new();

        for (_key, tcb_lock) in self.connections.iter() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                // RFC 1122: If we have outstanding data, that data acts as a zero-window probe
                // via regular retransmissions. We only need to trigger an explicit 1-byte probe
                // if the send window is zero, we have data to send, and nothing is currently
                // in flight (outstanding_bytes == 0).
                if tcb.tx.outstanding_bytes > 0 {
                    continue;
                }

                match tcb.check_zero_window_probe(current_time) {
                    Some(true) => {
                        // Send zero-window probe: 1 byte of new data at seq = snd_nxt (RFC 1122)
                        if let Some(remote) = tcb.remote_addr() {
                            // Dequeue the first packet from send buffer to extract 1 byte
                            if let Some(packet) = tcb.dequeue_send_packet() {
                                let data = packet.data();
                                if data.is_empty() {
                                    // This shouldn't happen as send_buffer_bytes > 0
                                    tcb.requeue_send_packet_front(packet);
                                    continue;
                                }

                                let probe_byte = data[0];
                                let seq = tcb.snd_nxt();

                                // RFC 1122: ZWP should be 1 byte of new data.
                                // We treat it as a normal data segment for retransmission purposes.
                                let flags = TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK;
                                let opts = tcb.build_options(flags);
                                let payload = vec![probe_byte];

                                // Advance sequence number and queue for retransmission
                                // Now outstanding_bytes will be > 0, and the retransmission timer
                                // will handle further attempts for this specific byte until ACKed.
                                tcb.queue_unacked(seq, payload.clone(), current_time, flags);
                                tcb.advance_snd_nxt(1);

                                // Put the rest of the packet back to the front of the send buffer
                                let mut remaining_packet = packet;
                                remaining_packet.advance(1);
                                if remaining_packet.len() > 0 {
                                    tcb.requeue_send_packet_front(remaining_packet);
                                }

                                results.push(TcpProcessResult::SendPacket {
                                    local: tcb.local_addr(),
                                    remote,
                                    seq,
                                    ack: tcb.rcv_nxt(),
                                    flags,
                                    window: tcb.rcv_wnd(),
                                    payload,
                                    options: opts,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        results
    }

    /// Mark that a retransmit for a given (local, remote, seq) has been sent.
    /// Updates the corresponding unacked segment's sent_time and retransmit counters
    /// and applies RTO backoff.
    pub fn mark_retransmit_sent(
        &mut self,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq: u32,
        current_time: u64,
    ) {
        if let Some(tcb_lock) = self.connections.get(&(local, remote)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                if tcb.touch_unacked_segment_for_retransmit(seq, current_time) {
                    tcb.backoff_rto();
                    tcb.bump_retransmit_count_counter();
                    tcb.set_last_retransmit_time(current_time);
                }
            }
        }
    }

    /// Record that a TCP segment was actually sent on the wire for a connection.
    /// This updates TCB state (snd_nxt) and queues the data for potential retransmit.
    pub fn record_sent_packet(
        &mut self,
        local: EndpointAddr,
        remote: EndpointAddr,
        seq: u32,
        flags: u16,
        payload: &[u8],
        current_time: u64,
    ) {
        if let Some(tcb_lock) = self.connections.get(&(local, remote)).cloned() {
            if let Ok(mut tcb) = tcb_lock.lock() {
                // Clear any pending delayed ACK since we are now sending an ACK (possibly with data)
                tcb.clear_delayed_ack();

                // Determine how many sequence numbers are consumed.
                let consumed = TcpControlBlock::seq_space_len_for_len_flags(payload.len(), flags);

                if consumed > 0 {
                    // Queue for retransmission
                    tcb.queue_unacked(seq, payload.to_vec(), current_time, flags);
                    tcb.set_last_retransmit_time(current_time);
                    // Advance snd_nxt to reflect the bytes consumed
                    tcb.set_snd_nxt(seq.wrapping_add(consumed));
                }
            }
        }
    }
}
