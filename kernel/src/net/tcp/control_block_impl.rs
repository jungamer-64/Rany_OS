use super::*;


impl TcpControlBlock {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            remote_addr: None,
            state: TcpState::Closed,
            snd_nxt: 0,
            snd_una: 0,
            snd_wnd: 65535,
            rcv_nxt: 0,
            rcv_wnd: 65535,
            send_buffer: VecDeque::new(),
            send_buffer_bytes: 0,
            outstanding_bytes: 0,
            recv_buffer: VecDeque::new(),
            recv_queue: VecDeque::new(),
            cwnd: 10 * 1460, // 初期値: 10 MSS (RFC 6928)
            ssthresh: 65535,
            mss: 1460, // Ethernet MTU - IP/TCP headers
            dup_ack_count: 0,
            last_ack: 0,
            in_recovery: false,
            nagle_enabled: true, // Nagle's algorithm on by default
            read_waker: None,
            write_waker: None,
            connect_waker: None,
            backlog: None,
            accept_waker: None,
            stats: TcpStats::default(),
            // Retransmission Timer (RFC 6298 defaults)
            srtt: None,
            rttvar: None,
            rto: 1_000_000, // Initial RTO = 1 second (in microseconds)
            last_retransmit_time: 0,
            retransmit_count: 0,
            unacked_segments: VecDeque::new(),
            // TCP Keepalive (defaults: 2 hours idle, 75s interval, 9 probes)
            keepalive_enabled: false,
            keepalive_idle: 7_200_000_000,    // 2 hours in microseconds
            keepalive_interval: 75_000_000,   // 75 seconds in microseconds
            keepalive_count: 9,
            keepalive_probes_sent: 0,
            last_activity_time: 0,
            time_wait_entered: 0,
            // Window Scaling (RFC 7323) - default scale factor 7 = 128KB max window
            snd_wscale: 7,
            rcv_wscale: 0, // Set when peer SYN received
            wscale_enabled: false, // Negotiated during handshake
            rcv_wnd_scaled: 65535 << 7, // Initial scaled window
            // Timestamps (RFC 7323) - disabled by default, negotiated in SYN
            ts_enabled: false,
            ts_val: 0,
            ts_ecr: 0,
            ts_recent: 0,
            ts_recent_age: 0,
            // SACK (RFC 2018) - disabled by default
            sack_enabled: false,
            sack_blocks: [(0, 0); 4],
            sack_block_count: 0,
            sack_scoreboard: alloc::vec::Vec::new(),
        }
    }

    /// 受信データがあるか
    pub fn has_data(&self) -> bool {
        !self.recv_buffer.is_empty() || !self.recv_queue.is_empty()
    }

    /// 送信可能か（バイト単位で判定、受信ウィンドウとの最小値を使用）
    pub fn can_send(&self) -> bool {
        if self.state != TcpState::Established {
            return false;
        }
        let available = core::cmp::min(self.cwnd, self.snd_wnd as u32);
        // Consider both in-flight (outstanding) and queued bytes
        let total_outstanding = self.outstanding_bytes.saturating_add(self.send_buffer_bytes);
        total_outstanding < available
    }

    /// Update RTO based on RTT measurement (RFC 6298)
    /// 
    /// Called when an ACK is received for a segment that was not retransmitted.
    pub fn update_rto(&mut self, rtt_sample: u64) {
        const ALPHA: u64 = 8;  // 1/8
        const BETA: u64 = 4;   // 1/4
        const MIN_RTO: u64 = 200_000;    // 200ms in microseconds
        const MAX_RTO: u64 = 60_000_000; // 60 seconds in microseconds

        if let (Some(srtt), Some(rttvar)) = (self.srtt, self.rttvar) {
            // Subsequent measurements
            let diff = if rtt_sample > srtt {
                rtt_sample - srtt
            } else {
                srtt - rtt_sample
            };
            self.rttvar = Some(rttvar - rttvar / BETA + diff / BETA);
            self.srtt = Some(srtt - srtt / ALPHA + rtt_sample / ALPHA);
        } else {
            // First measurement
            self.srtt = Some(rtt_sample);
            self.rttvar = Some(rtt_sample / 2);
        }

        // RTO = SRTT + max(G, 4 * RTTVAR) where G is clock granularity
        let srtt = self.srtt.unwrap_or(rtt_sample);
        let rttvar = self.rttvar.unwrap_or(rtt_sample / 2);
        self.rto = (srtt + 4 * rttvar).clamp(MIN_RTO, MAX_RTO);
    }

    /// Backoff RTO on retransmission timeout
    pub fn backoff_rto(&mut self) {
        const MAX_RTO: u64 = 60_000_000; // 60 seconds
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.retransmit_count += 1;
    }

    /// Queue a segment for potential retransmission (stores flags too)
    pub fn queue_unacked(&mut self, seq: u32, data: Vec<u8>, current_time: u64, flags: u16) {
        // Count sequence-space bytes consumed by this segment for outstanding accounting
        let mut added: u32 = data.len() as u32;
        if flags & TcpHeader::FLAG_SYN != 0 {
            added = added.saturating_add(1);
        }
        if flags & TcpHeader::FLAG_FIN != 0 {
            added = added.saturating_add(1);
        }

        self.outstanding_bytes = self.outstanding_bytes.saturating_add(added);
        self.unacked_segments.push_back(UnackedSegment {
            seq,
            data,
            sent_time: current_time,
            retransmit_count: 0,
            flags,
        });
    }

    /// Remove acknowledged segments from retransmission queue
    pub fn ack_segments(&mut self, ack_num: u32) {
        // Compute total bytes before (include SYN/FIN sequence-space)
        let before: u32 = self.unacked_segments.iter().map(|s| {
            let mut cnt = s.data.len() as u32;
            if s.flags & TcpHeader::FLAG_SYN != 0 { cnt = cnt.saturating_add(1); }
            if s.flags & TcpHeader::FLAG_FIN != 0 { cnt = cnt.saturating_add(1); }
            cnt
        }).sum();

        // Remove all segments with seq + len <= ack_num
        self.unacked_segments.retain(|seg| {
            let mut end_seq = seg.seq.wrapping_add(seg.data.len() as u32);
            if seg.flags & TcpHeader::FLAG_SYN != 0 { end_seq = end_seq.wrapping_add(1); }
            if seg.flags & TcpHeader::FLAG_FIN != 0 { end_seq = end_seq.wrapping_add(1); }
            // Keep if segment is after ack_num (not yet acknowledged)
            TcpProcessor::seq_after(end_seq, ack_num)
        });

        // Compute removed bytes and adjust outstanding_bytes
        let after: u32 = self.unacked_segments.iter().map(|s| {
            let mut cnt = s.data.len() as u32;
            if s.flags & TcpHeader::FLAG_SYN != 0 { cnt = cnt.saturating_add(1); }
            if s.flags & TcpHeader::FLAG_FIN != 0 { cnt = cnt.saturating_add(1); }
            cnt
        }).sum();
        let removed = before.saturating_sub(after);
        self.outstanding_bytes = self.outstanding_bytes.saturating_sub(removed);

        // Reset retransmit count on successful ACK
        if self.unacked_segments.is_empty() {
            self.retransmit_count = 0;
        }
    }

    /// Check if retransmission timeout has occurred
    pub fn check_retransmit_timeout(&self, current_time: u64) -> bool {
        if self.unacked_segments.is_empty() {
            return false;
        }
        
        // Check if oldest unacked segment has timed out
        if let Some(oldest) = self.unacked_segments.front() {
            let elapsed = current_time.saturating_sub(oldest.sent_time);
            return elapsed >= self.rto;
        }
        false
    }

    // ========================================================================
    // Congestion Control (RFC 5681)
    // ========================================================================

    /// Called when a new (non-duplicate) ACK is received
    ///
    /// Implements:
    /// - Slow Start (cwnd < ssthresh): cwnd += mss
    /// - Congestion Avoidance (cwnd >= ssthresh): cwnd += mss*mss/cwnd
    pub fn on_new_ack(&mut self, bytes_acked: u32) {
        let mss = self.mss as u32;
        
        // Exit fast recovery on new ACK
        if self.in_recovery {
            self.in_recovery = false;
            self.cwnd = self.ssthresh;
        }
        
        // Reset dup ACK counter
        self.dup_ack_count = 0;
        
        if self.cwnd < self.ssthresh {
            // Slow Start: exponential growth
            // Increase cwnd by mss for each ACK (roughly doubles per RTT)
            self.cwnd = self.cwnd.saturating_add(mss);
        } else {
            // Congestion Avoidance: linear growth (AIMD - Additive Increase)
            // cwnd += mss * mss / cwnd (approximately +1 MSS per RTT)
            let increment = (mss as u64 * mss as u64 / self.cwnd as u64).max(1) as u32;
            self.cwnd = self.cwnd.saturating_add(increment);
        }
    }

    /// Called when a duplicate ACK is received
    ///
    /// Returns true if fast retransmit should be triggered (3rd dup ACK)
    pub fn on_dup_ack(&mut self) -> bool {
        self.dup_ack_count = self.dup_ack_count.saturating_add(1);
        
        if self.dup_ack_count == 3 && !self.in_recovery {
            // Fast Retransmit + Fast Recovery (RFC 5681)
            self.enter_fast_recovery();
            return true; // Trigger fast retransmit
        }
        
        if self.in_recovery && self.dup_ack_count > 3 {
            // Inflate cwnd during fast recovery
            self.cwnd = self.cwnd.saturating_add(self.mss as u32);
        }
        
        false
    }

    /// Enter Fast Recovery mode (RFC 5681 Section 3.2)
    pub(super) fn enter_fast_recovery(&mut self) {
        let mss = self.mss as u32;
        
        // ssthresh = max(FlightSize / 2, 2*MSS)
        self.ssthresh = (self.outstanding_bytes / 2).max(2 * mss);
        
        // cwnd = ssthresh + 3*MSS (for the 3 dup ACKs)
        self.cwnd = self.ssthresh.saturating_add(3 * mss);
        
        self.in_recovery = true;
    }

    /// Called when a loss is detected (RTO timeout)
    ///
    /// More severe than fast retransmit - go back to slow start
    pub fn on_loss(&mut self) {
        let mss = self.mss as u32;
        
        // ssthresh = max(cwnd / 2, 2*MSS)
        self.ssthresh = (self.cwnd / 2).max(2 * mss);
        
        // cwnd = 1 MSS (slow start)
        self.cwnd = mss;
        
        // Exit recovery if in it
        self.in_recovery = false;
        self.dup_ack_count = 0;
    }

    /// Check if sending should be delayed (Nagle's algorithm)
    ///
    /// Nagle's algorithm: If there is unacknowledged data AND data to send
    /// is less than MSS, delay sending until either:
    /// 1. All data is acknowledged (outstanding_bytes == 0)
    /// 2. Enough data to fill MSS
    ///
    /// This reduces small packet overhead on interactive connections.
    pub fn should_delay_send(&self, data_len: usize) -> bool {
        if !self.nagle_enabled {
            return false;
        }
        
        // If data fills an MSS, send immediately
        if data_len >= self.mss as usize {
            return false;
        }
        
        // If no outstanding data, send immediately
        if self.outstanding_bytes == 0 {
            return false;
        }
        
        // Small packet with outstanding data: delay
        true
    }

    /// Disable Nagle's algorithm (like TCP_NODELAY socket option)
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nagle_enabled = !nodelay;
    }

    // ========================================================================
    // TCP Keepalive
    // ========================================================================

    /// Enable/disable keepalive with custom parameters
    pub fn set_keepalive(&mut self, enabled: bool, idle_us: Option<u64>, interval_us: Option<u64>, count: Option<u8>) {
        self.keepalive_enabled = enabled;
        if let Some(idle) = idle_us {
            self.keepalive_idle = idle;
        }
        if let Some(interval) = interval_us {
            self.keepalive_interval = interval;
        }
        if let Some(c) = count {
            self.keepalive_count = c;
        }
    }

    /// Record activity on the connection (resets keepalive timer)
    pub fn on_activity(&mut self, current_time: u64) {
        self.last_activity_time = current_time;
        self.keepalive_probes_sent = 0;
    }

    /// Check if keepalive probe should be sent
    /// 
    /// Returns:
    /// - None: No action needed
    /// - Some(true): Send keepalive probe
    /// - Some(false): Connection dead (too many probes failed)
    pub fn check_keepalive(&mut self, current_time: u64) -> Option<bool> {
        if !self.keepalive_enabled {
            return None;
        }
        
        if self.state != TcpState::Established {
            return None;
        }
        
        let elapsed = current_time.saturating_sub(self.last_activity_time);
        
        if self.keepalive_probes_sent == 0 {
            // First probe after idle time
            if elapsed >= self.keepalive_idle {
                self.keepalive_probes_sent = 1;
                return Some(true);
            }
        } else {
            // Subsequent probes at interval
            let probe_time = self.keepalive_idle + 
                (self.keepalive_probes_sent as u64 - 1) * self.keepalive_interval;
            
            if elapsed >= probe_time + self.keepalive_interval {
                if self.keepalive_probes_sent >= self.keepalive_count {
                    // Too many probes - connection is dead
                    return Some(false);
                }
                self.keepalive_probes_sent += 1;
                return Some(true);
            }
        }
        
        None
    }

    /// Reset keepalive state (call when ACK received)
    pub fn reset_keepalive(&mut self) {
        self.keepalive_probes_sent = 0;
    }

    // ========================================================================
    // TCP Window Scaling (RFC 7323)
    // ========================================================================

    /// Get effective send window (peer's window scaled)
    pub fn get_effective_snd_wnd(&self) -> u32 {
        if self.wscale_enabled {
            (self.snd_wnd as u32) << self.rcv_wscale
        } else {
            self.snd_wnd as u32
        }
    }

    /// Get effective receive window (our window scaled)
    pub fn get_effective_rcv_wnd(&self) -> u32 {
        self.rcv_wnd_scaled
    }

    /// Set peer's window scale factor (from SYN/SYN-ACK option)
    pub fn set_peer_wscale(&mut self, scale: u8) {
        // RFC 7323: scale factor must be <= 14
        self.rcv_wscale = scale.min(14);
        self.wscale_enabled = true;
    }

    /// Calculate optimal window scale factor based on buffer size
    /// Returns scale factor (0-14) for the given max window size
    pub fn calculate_wscale(max_window: u32) -> u8 {
        if max_window <= 65535 {
            return 0;
        }
        for scale in 1..=14u8 {
            if (65535u32 << scale) >= max_window {
                return scale;
            }
        }
        14 // Maximum scale factor
    }

    /// Update our advertised receive window
    pub fn update_rcv_wnd(&mut self, available_buffer: u32) {
        self.rcv_wnd_scaled = available_buffer;
        // Calculate the 16-bit window field (scaled down)
        if self.wscale_enabled {
            self.rcv_wnd = (available_buffer >> self.snd_wscale).min(65535) as u16;
        } else {
            self.rcv_wnd = available_buffer.min(65535) as u16;
        }
    }

    // ========================================================================
    // TCP Timestamps (RFC 7323)
    // ========================================================================

    /// Get current timestamp value for outgoing segment
    pub fn get_ts_val(&mut self) -> u32 {
        self.ts_val = self.ts_val.wrapping_add(1);
        self.ts_val
    }

    /// Process incoming timestamp option
    /// 
    /// Updates ts_recent for PAWS and prepares ts_ecr for reply
    pub fn process_ts_option(&mut self, ts_val: u32, ts_ecr: u32, current_time: u64, seq_num: u32) {
        // Only update ts_recent if segment is in sequence
        if seq_num == self.rcv_nxt || self.ts_recent == 0 {
            self.ts_recent = ts_val;
            self.ts_recent_age = current_time;
        }
        
        // Echo back the received timestamp
        self.ts_ecr = ts_val;
    }

    /// Check PAWS (Protection Against Wrapped Sequences)
    /// 
    /// Returns true if segment should be rejected (old duplicate)
    pub fn check_paws(&self, ts_val: u32, current_time: u64) -> bool {
        if !self.ts_enabled || self.ts_recent == 0 {
            return false;
        }
        
        // RFC 7323: If ts_recent is less than 24 days old and 
        // incoming ts_val < ts_recent, reject segment
        const PAWS_IDLE_LIMIT: u64 = 24 * 24 * 60 * 60 * 1_000_000; // 24 days in microseconds
        
        let age = current_time.saturating_sub(self.ts_recent_age);
        if age < PAWS_IDLE_LIMIT {
            // Compare timestamps (handling wrap-around)
            let diff = ts_val.wrapping_sub(self.ts_recent) as i32;
            if diff < 0 {
                return true; // Old duplicate - reject
            }
        }
        
        false
    }

    /// Measure RTT from timestamp echo
    /// 
    /// Returns RTT in microseconds if measurement is valid
    pub fn measure_rtt_from_ts(&self, ts_ecr: u32, current_ts: u32) -> Option<u64> {
        if !self.ts_enabled || ts_ecr == 0 {
            return None;
        }
        
        // RTT = current_ts - ts_ecr (in timestamp units)
        // Assuming 1ms per tick (common convention)
        let rtt_ticks = current_ts.wrapping_sub(ts_ecr);
        Some(rtt_ticks as u64 * 1000) // Convert to microseconds
    }

    /// Enable timestamps (call when negotiated in SYN)
    pub fn enable_timestamps(&mut self, initial_ts: u32) {
        self.ts_enabled = true;
        self.ts_val = initial_ts;
    }

    // ========================================================================
    // TCP SACK (RFC 2018)
    // ========================================================================

    /// Enable SACK (call when negotiated in SYN)
    pub fn enable_sack(&mut self) {
        self.sack_enabled = true;
    }

    /// Add a SACK block for out-of-order segment received
    /// 
    /// Called when we receive data out of order to build SACK option
    pub fn add_sack_block(&mut self, left: u32, right: u32) {
        if !self.sack_enabled {
            return;
        }
        
        // Insert new block, maintaining most recent first
        // Shift existing blocks down
        for i in (1..4).rev() {
            self.sack_blocks[i] = self.sack_blocks[i - 1];
        }
        self.sack_blocks[0] = (left, right);
        self.sack_block_count = (self.sack_block_count + 1).min(4);
    }

    /// Process SACK option received from peer
    /// 
    /// Updates scoreboard to mark segments as selectively acknowledged
    pub fn process_sack_option(&mut self, blocks: &[(u32, u32)]) {
        for &(left, right) in blocks {
            // Merge or add to scoreboard
            let mut merged = false;
            for (l, r) in self.sack_scoreboard.iter_mut() {
                // Check for overlap or adjacency
                if Self::seq_in_range(left, *l, *r) || Self::seq_in_range(*l, left, right) ||
                   right == *l || *r == left {
                    *l = core::cmp::min(*l, left);
                    *r = core::cmp::max(*r, right);
                    merged = true;
                    break;
                }
            }
            if !merged {
                self.sack_scoreboard.push((left, right));
            }
        }
    }

    /// Check if a sequence number is within a range (handling wrap-around)
    pub(super) fn seq_in_range(seq: u32, left: u32, right: u32) -> bool {
        let diff_left = seq.wrapping_sub(left) as i32;
        let diff_right = right.wrapping_sub(seq) as i32;
        diff_left >= 0 && diff_right > 0
    }

    /// Check if a segment is marked as SACKed
    pub fn is_sacked(&self, seq: u32, len: u32) -> bool {
        let end = seq.wrapping_add(len);
        for &(left, right) in &self.sack_scoreboard {
            if Self::seq_in_range(seq, left, right) && 
               (Self::seq_in_range(end, left, right) || end == right) {
                return true;
            }
        }
        false
    }

    /// Get next unsacked segment for retransmission
    /// 
    /// Returns Some(seq) of the first segment that needs retransmitting
    pub fn get_next_unsacked(&self) -> Option<u32> {
        for seg in &self.unacked_segments {
            if !self.is_sacked(seg.seq, seg.data.len() as u32) {
                return Some(seg.seq);
            }
        }
        None
    }

    /// Clear SACK scoreboard on new cumulative ACK
    pub fn clear_sacked_below(&mut self, ack: u32) {
        self.sack_scoreboard.retain(|&(left, _)| {
            let diff = left.wrapping_sub(ack) as i32;
            diff >= 0
        });
    }

    /// Get SACK blocks to include in outgoing ACK
    pub fn get_sack_blocks(&self) -> &[(u32, u32)] {
        &self.sack_blocks[..self.sack_block_count as usize]
    }
}
