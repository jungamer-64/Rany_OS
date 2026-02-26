use super::*;


impl TcpControlBlock {
    pub fn new(local_addr: SocketAddr) -> Self {
        let now = crate::task::timer::current_tick();
        
        // Generate a cryptographically secure random Initial Sequence Number (ISN).
        // Using ISN randomization (RFC 6528) is critical to prevent TCP spoofing and hijacking.
        let random_bytes = crate::net::tls::generate_random();
        let isn = u32::from_le_bytes([random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3]]);

        Self {
            endpoints: TcpEndpointMeta::new(local_addr),
            state: TcpState::Closed,
            seq: TcpSeqState::new(isn),
            tx: TcpTxState::new(),
            rx: TcpRxState::new(),
            congestion: TcpCongestionState::new(),
            options: TcpOptionsState::new(),
            timers: TcpTimerState::new(),
            waiters: TcpAsyncWaiters::default(),
            stats: TcpStats::default(),
            created_at: now,
        }
    }

    /// 接続作成時刻を取得
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// 受信データがあるか
    pub fn has_data(&self) -> bool {
        !self.rx.recv_buffer.is_empty()
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoints.local_addr
    }

    #[inline]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.endpoints.remote_addr
    }

    #[inline]
    pub fn set_remote_addr(&mut self, remote: SocketAddr) {
        self.endpoints.remote_addr = Some(remote);
    }

    #[inline]
    pub fn clear_remote_addr(&mut self) {
        self.endpoints.remote_addr = None;
    }

    #[inline]
    fn set_state(&mut self, next: TcpState) {
        self.state = next;
    }

    #[inline]
    pub fn state(&self) -> TcpState {
        self.state
    }

    #[inline]
    pub fn set_rcv_nxt(&mut self, next: u32) {
        self.seq.rcv_nxt = next;
    }

    #[inline]
    pub fn snd_nxt(&self) -> u32 {
        self.seq.snd_nxt
    }

    #[inline]
    pub fn snd_una(&self) -> u32 {
        self.seq.snd_una
    }

    #[inline]
    pub fn snd_wnd(&self) -> u16 {
        self.seq.snd_wnd
    }

    #[inline]
    pub fn rcv_nxt(&self) -> u32 {
        self.seq.rcv_nxt
    }

    #[inline]
    pub fn rcv_wnd(&self) -> u16 {
        self.seq.rcv_wnd
    }

    #[inline]
    pub fn set_snd_nxt(&mut self, next: u32) {
        self.seq.snd_nxt = next;
    }

    #[inline]
    pub fn set_snd_una(&mut self, next: u32) {
        self.seq.snd_una = next;
    }

    #[inline]
    pub fn set_snd_wnd(&mut self, wnd: u16) {
        self.seq.snd_wnd = wnd;
    }

    #[inline]
    pub fn set_rcv_wnd(&mut self, wnd: u16) {
        self.seq.rcv_wnd = wnd;
    }

    #[inline]
    pub fn advance_snd_nxt(&mut self, by: u32) {
        self.seq.snd_nxt = self.seq.snd_nxt.wrapping_add(by);
    }

    #[inline]
    pub fn advance_rcv_nxt(&mut self, by: u32) {
        self.seq.rcv_nxt = self.seq.rcv_nxt.wrapping_add(by);
    }

    #[inline]
    pub fn send_capacity_bytes(&self) -> usize {
        core::cmp::min(self.congestion.cwnd, self.seq.snd_wnd as u32)
            .saturating_sub(self.tx.outstanding_bytes.saturating_add(self.tx.send_buffer_bytes))
            as usize
    }

    #[inline]
    pub fn outstanding_bytes(&self) -> u32 {
        self.tx.outstanding_bytes
    }

    #[inline]
    pub fn enqueue_send_packet(&mut self, packet: PacketRef) {
        self.tx.send_buffer_bytes = self.tx.send_buffer_bytes.saturating_add(packet.len() as u32);
        self.tx.send_buffer.push_back(packet);
    }

    #[inline]
    pub fn send_buffer_bytes(&self) -> u32 {
        self.tx.send_buffer_bytes
    }

    #[inline]
    pub fn send_buffer_is_empty(&self) -> bool {
        self.tx.send_buffer.is_empty()
    }

    #[inline]
    pub fn dequeue_send_packet(&mut self) -> Option<PacketRef> {
        let packet = self.tx.send_buffer.pop_front()?;
        self.tx.send_buffer_bytes = self.tx.send_buffer_bytes.saturating_sub(packet.len() as u32);
        Some(packet)
    }

    #[inline]
    pub fn requeue_send_packet_front(&mut self, packet: PacketRef) {
        self.tx.send_buffer_bytes = self.tx.send_buffer_bytes.saturating_add(packet.len() as u32);
        self.tx.send_buffer.push_front(packet);
    }

    #[inline]
    pub fn recv_buffer_is_empty(&self) -> bool {
        self.rx.recv_buffer.is_empty()
    }

    #[inline]
    pub fn recv_buffer_front_data(&self) -> Option<&[u8]> {
        self.rx.recv_buffer.front().map(|pkt| pkt.data())
    }

    #[inline]
    pub fn pop_recv_packet(&mut self) -> Option<PacketRef> {
        let packet = self.rx.recv_buffer.pop_front()?;
        self.rx.recv_buffer_bytes = self.rx.recv_buffer_bytes.saturating_sub(packet.len());
        Some(packet)
    }

    #[inline]
    pub fn push_recv_packet_front(&mut self, packet: PacketRef) {
        self.rx.recv_buffer_bytes = self.rx.recv_buffer_bytes.saturating_add(packet.len());
        self.rx.recv_buffer.push_front(packet);
    }

    #[inline]
    pub fn push_recv_packet(&mut self, packet: PacketRef) {
        self.rx.recv_buffer_bytes = self.rx.recv_buffer_bytes.saturating_add(packet.len());
        self.rx.recv_buffer.push_back(packet);
    }

    #[inline]
    pub fn recv_buffer_bytes(&self) -> usize {
        self.rx.recv_buffer_bytes
    }

    #[inline]
    pub fn recv_buffer_limit_bytes(&self) -> usize {
        self.rx.recv_buffer_limit_bytes
    }

    #[inline]
    pub fn recv_buffer_available_bytes(&self) -> usize {
        self.rx.recv_buffer_limit_bytes.saturating_sub(self.rx.recv_buffer_bytes)
    }

    #[inline]
    pub fn is_recv_buffer_full(&self) -> bool {
        self.rx.recv_buffer_bytes >= self.rx.recv_buffer_limit_bytes
    }

    #[inline]
    pub fn pop_recv_copy_fallback_front(&mut self) -> Option<Vec<u8>> {
        let queued = self.rx.recv_queue.pop_front()?;
        self.rx.recv_queue_bytes = self.rx.recv_queue_bytes.saturating_sub(queued.len());
        Some(queued)
    }

    #[inline]
    pub fn push_recv_copy_fallback_front(&mut self, queued: Vec<u8>) {
        self.rx.recv_queue_bytes = self.rx.recv_queue_bytes.saturating_add(queued.len());
        self.rx.recv_queue.push_front(queued);
    }

    #[inline]
    pub fn recv_copy_fallback_len(&self) -> usize {
        self.rx.recv_queue.len()
    }

    #[inline]
    pub fn recv_copy_fallback_bytes(&self) -> usize {
        self.rx.recv_queue_bytes
    }

    #[inline]
    pub fn recv_copy_fallback_is_empty(&self) -> bool {
        self.rx.recv_queue.is_empty()
    }

    #[inline]
    pub fn recv_copy_fallback_front_data(&self) -> Option<&[u8]> {
        self.rx.recv_queue.front().map(|v| v.as_slice())
    }

    #[inline]
    pub fn set_recv_copy_fallback_limit_bytes(&mut self, limit: usize) {
        self.rx.recv_queue_limit_bytes = limit;
    }

    #[inline]
    fn push_recv_copy_fallback_back_unchecked(&mut self, queued: Vec<u8>) {
        self.rx.recv_queue_bytes = self.rx.recv_queue_bytes.saturating_add(queued.len());
        self.rx.recv_queue.push_back(queued);
    }

    #[inline]
    pub fn stats_snapshot(&self) -> TcpStats {
        self.stats.clone()
    }

    #[inline]
    pub fn record_tx_enqueued_stats(&mut self, len: usize) {
        self.stats.record_tx_enqueued(len);
    }

    #[inline]
    pub fn record_rx_segment_stats(&mut self, len: usize) {
        self.stats.record_rx_segment(len);
    }

    #[inline]
    pub fn record_rx_delivered_stats(&mut self, len: usize) {
        self.stats.record_rx_delivered(len);
    }

    #[inline]
    pub fn enter_listen(&mut self) {
        self.set_state(TcpState::Listen);
    }

    #[inline]
    pub fn enter_syn_sent(&mut self) {
        self.set_state(TcpState::SynSent);
    }

    #[inline]
    pub fn enter_syn_received(&mut self) {
        self.set_state(TcpState::SynReceived);
    }

    #[inline]
    pub fn enter_established(&mut self) {
        self.set_state(TcpState::Established);
    }

    #[inline]
    pub fn enter_close_wait(&mut self) {
        self.set_state(TcpState::CloseWait);
    }

    #[inline]
    pub fn enter_fin_wait2(&mut self) {
        self.set_state(TcpState::FinWait2);
    }

    #[inline]
    pub fn enter_closing(&mut self) {
        self.set_state(TcpState::Closing);
    }

    #[inline]
    pub fn begin_active_close(&mut self) {
        self.set_state(TcpState::FinWait1);
    }

    #[inline]
    pub fn begin_passive_close_reply(&mut self) {
        self.set_state(TcpState::LastAck);
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.state == TcpState::Closed
    }

    #[inline]
    pub fn is_established(&self) -> bool {
        self.state == TcpState::Established
    }

    #[inline]
    pub fn is_connecting(&self) -> bool {
        matches!(self.state, TcpState::SynSent | TcpState::SynReceived)
    }

    #[inline]
    pub fn is_listen(&self) -> bool {
        self.state == TcpState::Listen
    }

    #[inline]
    pub fn wake_io_waiters(&self) {
        self.waiters.read_waker.wake();
        self.waiters.write_waker.wake();
        self.waiters.connect_waker.wake();
    }

    #[inline]
    pub fn register_read_waker(&self, waker: &core::task::Waker) {
        self.waiters.read_waker.register(waker);
    }

    #[inline]
    pub fn register_write_waker(&self, waker: &core::task::Waker) {
        self.waiters.write_waker.register(waker);
    }

    #[inline]
    pub fn register_connect_waker(&self, waker: &core::task::Waker) {
        self.waiters.connect_waker.register(waker);
    }

    #[inline]
    pub fn wake_read_waiter(&self) {
        self.waiters.read_waker.wake();
    }

    #[inline]
    pub fn wake_write_waiter(&self) {
        self.waiters.write_waker.wake();
    }

    #[inline]
    pub fn wake_connect_waiter(&self) {
        self.waiters.connect_waker.wake();
    }

    #[inline]
    pub fn set_listener_waiters(
        &mut self,
        backlog: Arc<PoisonLock<VecDeque<TcpStream>>>,
        accept_waker: Arc<crate::sync::atomic_waker::AtomicWaker>,
    ) {
        self.waiters.backlog = Some(backlog);
        self.waiters.accept_waker = Some(accept_waker);
    }

    #[inline]
    pub fn inherit_listener_waiters(&mut self, listener: &TcpControlBlock) {
        self.waiters.backlog = listener.waiters.backlog.clone();
        self.waiters.accept_waker = listener.waiters.accept_waker.clone();
    }

    #[inline]
    pub fn push_backlog_connection_and_wake(
        &self,
        tcb_arc: &Arc<PoisonLock<TcpControlBlock>>,
    ) {
        if let Some(backlog_lock) = &self.waiters.backlog {
            if let Ok(mut backlog) = backlog_lock.lock() {
                backlog.push_back(TcpStream { tcb: tcb_arc.clone() });
                if let Some(accept_waker) = &self.waiters.accept_waker {
                    accept_waker.wake();
                }
            }
        }
    }

    #[inline]
    pub fn close_and_wake(&mut self) {
        self.state = TcpState::Closed;
        self.wake_io_waiters();
    }

    #[inline]
    pub fn enter_time_wait(&mut self, current_time: u64) {
        self.state = TcpState::TimeWait;
        self.timers.time_wait_entered = current_time;
    }

    #[inline]
    pub fn time_wait_entered_at(&self) -> u64 {
        self.timers.time_wait_entered
    }

    #[inline]
    pub fn last_activity_time(&self) -> u64 {
        self.timers.last_activity_time
    }

    #[inline]
    pub fn time_wait_entered_or_last_activity(&self) -> u64 {
        if self.timers.time_wait_entered > 0 {
            self.timers.time_wait_entered
        } else {
            self.timers.last_activity_time
        }
    }

    #[inline]
    pub fn set_last_ack(&mut self, ack_num: u32) {
        self.congestion.last_ack = ack_num;
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    #[inline]
    pub fn set_cwnd_for_test(&mut self, cwnd: u32) {
        self.congestion.cwnd = cwnd;
    }

    #[inline]
    pub fn set_last_retransmit_time(&mut self, current_time: u64) {
        self.timers.last_retransmit_time = current_time;
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    #[inline]
    pub fn set_rto_for_test(&mut self, rto_us: u64) {
        self.timers.rto = rto_us;
    }

    #[inline]
    pub fn bump_retransmit_count_counter(&mut self) {
        self.timers.retransmit_count = self.timers.retransmit_count.saturating_add(1);
    }

    #[inline]
    pub fn oldest_unacked_seq(&self) -> Option<u32> {
        self.timers.unacked_segments.front().map(|seg| seg.seq)
    }

    #[inline]
    pub fn clone_oldest_unacked_packet_for_retransmit(&self) -> Option<(u32, u16, Vec<u8>)> {
        let oldest = self.timers.unacked_segments.front()?;
        Some((oldest.seq, oldest.flags, oldest.data.clone()))
    }

    #[inline]
    pub fn touch_oldest_unacked_for_retransmit(&mut self, current_time: u64) -> Option<(u32, Vec<u8>)> {
        let oldest = self.timers.unacked_segments.front_mut()?;
        oldest.sent_time = current_time;
        oldest.retransmit_count = oldest.retransmit_count.saturating_add(1);
        Some((oldest.seq, oldest.data.clone()))
    }

    #[inline]
    pub fn touch_unacked_segment_for_retransmit(&mut self, seq: u32, current_time: u64) -> bool {
        if let Some(seg) = self.find_unacked_segment_mut_by_seq(seq) {
            seg.sent_time = current_time;
            seg.retransmit_count = seg.retransmit_count.saturating_add(1);
            return true;
        }
        false
    }

    #[inline]
    fn find_unacked_segment_mut_by_seq(&mut self, seq: u32) -> Option<&mut UnackedSegment> {
        self.timers.unacked_segments.iter_mut().find(|s| s.seq == seq)
    }

    #[inline]
    fn push_unacked_segment(&mut self, seq: u32, data: Vec<u8>, current_time: u64, flags: u16) {
        self.timers.unacked_segments.push_back(UnackedSegment {
            seq,
            data,
            sent_time: current_time,
            retransmit_count: 0,
            flags,
        });
    }

    #[inline]
    fn retain_unacked_after_ack_and_count_removed(&mut self, ack_num: u32) -> u32 {
        let mut removed = 0u32;
        let mut old_queue = core::mem::take(&mut self.timers.unacked_segments);
        let mut kept = VecDeque::with_capacity(old_queue.len());

        while let Some(mut seg) = old_queue.pop_front() {
            let end_seq = Self::unacked_end_seq(&seg);

            // Fully acknowledged: drop segment entirely.
            if !TcpProcessor::seq_after(end_seq, ack_num) {
                removed = removed.saturating_add(Self::unacked_seq_space_len(&seg));
                continue;
            }

            // Partially acknowledged: trim prefix from the retransmit queue entry.
            if TcpProcessor::seq_after(ack_num, seg.seq) {
                removed = removed.saturating_add(Self::trim_unacked_segment_prefix_to_ack(
                    &mut seg, ack_num,
                ));
            }

            kept.push_back(seg);
        }

        self.timers.unacked_segments = kept;
        removed
    }

    #[inline]
    fn unacked_queue_is_empty(&self) -> bool {
        self.timers.unacked_segments.is_empty()
    }

    #[inline]
    fn oldest_unacked_elapsed(&self, current_time: u64) -> Option<u64> {
        let oldest = self.timers.unacked_segments.front()?;
        Some(current_time.saturating_sub(oldest.sent_time))
    }

    #[inline]
    fn trim_unacked_segment_prefix_to_ack(seg: &mut UnackedSegment, ack_num: u32) -> u32 {
        let mut acked = ack_num.wrapping_sub(seg.seq);
        if acked == 0 {
            return 0;
        }

        let original_seq = seg.seq;
        // Keep sent_time/retransmit_count as-is: the remaining suffix was sent at the same time
        // and should still participate in timeout/backoff accounting as the oldest outstanding data.
        seg.seq = ack_num;

        if (seg.flags & TcpHeader::FLAG_SYN) != 0 && acked > 0 {
            seg.flags &= !TcpHeader::FLAG_SYN;
            acked -= 1;
        }

        let payload_trim = core::cmp::min(acked as usize, seg.data.len());
        if payload_trim > 0 {
            seg.data.drain(..payload_trim);
            acked -= payload_trim as u32;
        }

        if (seg.flags & TcpHeader::FLAG_FIN) != 0 && acked > 0 {
            seg.flags &= !TcpHeader::FLAG_FIN;
            acked -= 1;
        }

        debug_assert_eq!(acked, 0, "partial ACK trim exceeded segment sequence-space");
        ack_num.wrapping_sub(original_seq)
    }

    /// OOMによるパケットドロップを記録する
    pub fn record_oom_drop(&mut self, payload: &[u8]) -> bool {
        self.stats.record_oom_drop(payload.len());
        
        log::warn!("[TCP] OOM: dropped {} bytes of payload", payload.len());
        
        // パケットをドロップするがコネクションは維持する (= RSTを送らない) ため、
        // 呼び出し元が正常として処理を続行できるよう true を返す
        true
    }

    /// Copy fallback queue に受信 payload を積む（mempool 枯渇/容量不足時）
    ///
    /// 返り値:
    /// - `true`: フォールバック投入成功（接続継続）
    /// - `false`: 上限超過のため fail-close（`state = Closed` 済み）
    pub fn enqueue_recv_copy_fallback(&mut self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return true;
        }

        let new_total = self.rx.recv_queue_bytes.saturating_add(payload.len());
        if new_total > self.rx.recv_queue_limit_bytes {
            log::warn!(
                "[TCP] recv copy fallback queue overflow: {} + {} > {} (closing)",
                self.rx.recv_queue_bytes,
                payload.len(),
                self.rx.recv_queue_limit_bytes
            );
            self.close_and_wake();
            return false;
        }

        // WARNING: this path allocates on the global heap.  In kernel/embedded
        // builds the allocator may be extremely scarce; enabling the copy-fallback
        // behaviour (non-zero limit) in production is therefore unsafe and can
        // lead to OOM kills or heap exhaustion.  We disable the fallback by
        // default (see `TCP_RECV_COPY_FALLBACK_LIMIT_BYTES`) and the only
        // remaining callers are tests which explicitly set a limit.  If the
        // fallback must be re-enabled in future consider using a fixed-size
        // scratch buffer or a dedicated pool rather than `Vec::to_vec()`.
        self.push_recv_copy_fallback_back_unchecked(payload.to_vec());
        self.stats
            .record_recv_copy_fallback(payload.len(), self.rx.recv_queue_bytes);
        true
    }

    /// 送信可能か（バイト単位で判定、受信ウィンドウとの最小値を使用）
    pub fn can_send(&self) -> bool {
        if !self.is_established() {
            return false;
        }
        self.send_capacity_bytes() > 0
    }

    /// Update RTO based on RTT measurement (RFC 6298)
    /// 
    /// Called when an ACK is received for a segment that was not retransmitted.
    pub fn update_rto(&mut self, rtt_sample: u64) {
        const ALPHA: u64 = 8;  // 1/8
        const BETA: u64 = 4;   // 1/4
        const MIN_RTO: u64 = 200_000;    // 200ms in microseconds
        const MAX_RTO: u64 = 60_000_000; // 60 seconds in microseconds

        if let (Some(srtt), Some(rttvar)) = (self.timers.srtt, self.timers.rttvar) {
            // Subsequent measurements.  Compute with β=1/4 and α=1/8 using
            // shift operations to avoid repeated integer-division rounding.
            let diff = if rtt_sample > srtt {
                rtt_sample - srtt
            } else {
                srtt - rtt_sample
            };
            // rttvar = (3/4)*rttvar + (1/4)*diff
            self.timers.rttvar = Some(rttvar - (rttvar >> 2) + (diff >> 2));
            // srtt = (7/8)*srtt + (1/8)*rtt_sample
            self.timers.srtt = Some(srtt - (srtt >> 3) + (rtt_sample >> 3));
        } else {
            // First measurement
            self.timers.srtt = Some(rtt_sample);
            self.timers.rttvar = Some(rtt_sample >> 1);
        }

        // RTO = SRTT + max(G, 4 * RTTVAR) where G is clock granularity
        let srtt = self.timers.srtt.unwrap_or(rtt_sample);
        let rttvar = self.timers.rttvar.unwrap_or(rtt_sample / 2);
        self.timers.rto = (srtt + 4 * rttvar).clamp(MIN_RTO, MAX_RTO);
    }

    /// Backoff RTO on retransmission timeout
    pub fn backoff_rto(&mut self) {
        const MAX_RTO: u64 = 60_000_000; // 60 seconds
        self.timers.rto = (self.timers.rto * 2).min(MAX_RTO);
        self.timers.retransmit_count += 1;
    }

    #[inline]
    pub(crate) fn seq_space_len_for_len_flags(data_len: usize, flags: u16) -> u32 {
        let mut len = data_len as u32;
        if flags & TcpHeader::FLAG_SYN != 0 {
            len = len.saturating_add(1);
        }
        if flags & TcpHeader::FLAG_FIN != 0 {
            len = len.saturating_add(1);
        }
        len
    }

    #[inline]
    fn unacked_seq_space_len(seg: &UnackedSegment) -> u32 {
        Self::seq_space_len_for_len_flags(seg.data.len(), seg.flags)
    }

    #[inline]
    fn unacked_end_seq(seg: &UnackedSegment) -> u32 {
        seg.seq.wrapping_add(Self::unacked_seq_space_len(seg))
    }

    /// Queue a segment for potential retransmission (stores flags too)
    pub fn queue_unacked(&mut self, seq: u32, data: Vec<u8>, current_time: u64, flags: u16) {
        // Count sequence-space bytes consumed by this segment for outstanding accounting
        let added = Self::seq_space_len_for_len_flags(data.len(), flags);

        self.tx.outstanding_bytes = self.tx.outstanding_bytes.saturating_add(added);
        self.push_unacked_segment(seq, data, current_time, flags);
    }

    /// Remove acknowledged segments from retransmission queue
    pub fn ack_segments(&mut self, ack_num: u32) {
        // Remove all segments with seq + len <= ack_num and count removed sequence-space bytes.
        let removed = self.retain_unacked_after_ack_and_count_removed(ack_num);
        self.tx.outstanding_bytes = self.tx.outstanding_bytes.saturating_sub(removed);

        // Reset retransmit count on successful ACK
        if self.unacked_queue_is_empty() {
            self.timers.retransmit_count = 0;
        }
    }

    /// Check if retransmission timeout has occurred
    pub fn check_retransmit_timeout(&self, current_time: u64) -> bool {
        match self.oldest_unacked_elapsed(current_time) {
            Some(elapsed) => elapsed >= self.timers.rto,
            None => false,
        }
    }

    // ========================================================================
    // Congestion Control (RFC 5681)
    // ========================================================================

    /// Called when a new (non-duplicate) ACK is received
    ///
    /// Implements:
    /// - Slow Start (cwnd < ssthresh): cwnd += mss
    /// - Congestion Avoidance (cwnd >= ssthresh): cwnd += mss*mss/cwnd
    pub fn on_new_ack(&mut self, _bytes_acked: u32) {
        let mss = self.congestion.mss as u32;
        
        // Exit fast recovery on new ACK
        if self.congestion.in_recovery {
            self.congestion.in_recovery = false;
            self.congestion.cwnd = self.congestion.ssthresh;
        }
        
        // Reset dup ACK counter
        self.congestion.dup_ack_count = 0;
        
        if self.congestion.cwnd < self.congestion.ssthresh {
            // Slow Start: exponential growth
            // Increase cwnd by mss for each ACK (roughly doubles per RTT)
            self.congestion.cwnd = self.congestion.cwnd.saturating_add(mss);
        } else {
            // Congestion Avoidance: linear growth (AIMD - Additive Increase)
            // cwnd += mss * mss / cwnd (approximately +1 MSS per RTT)
            let increment = (mss as u64 * mss as u64 / self.congestion.cwnd as u64).max(1) as u32;
            self.congestion.cwnd = self.congestion.cwnd.saturating_add(increment);
        }
    }

    /// Called when a duplicate ACK is received
    ///
    /// Returns true if fast retransmit should be triggered (3rd dup ACK)
    pub fn on_dup_ack(&mut self) -> bool {
        self.congestion.dup_ack_count = self.congestion.dup_ack_count.saturating_add(1);
        
        if self.congestion.dup_ack_count == 3 && !self.congestion.in_recovery {
            // Fast Retransmit + Fast Recovery (RFC 5681)
            self.enter_fast_recovery();
            return true; // Trigger fast retransmit
        }
        
        if self.congestion.in_recovery && self.congestion.dup_ack_count > 3 {
            // Inflate cwnd during fast recovery
            self.congestion.cwnd = self.congestion.cwnd.saturating_add(self.congestion.mss as u32);
        }
        
        false
    }

    /// Enter Fast Recovery mode (RFC 5681 Section 3.2)
    pub(super) fn enter_fast_recovery(&mut self) {
        let mss = self.congestion.mss as u32;
        
        // ssthresh = max(FlightSize / 2, 2*MSS)
        self.congestion.ssthresh = (self.tx.outstanding_bytes / 2).max(2 * mss);
        
        // cwnd = ssthresh + 3*MSS (for the 3 dup ACKs)
        self.congestion.cwnd = self.congestion.ssthresh.saturating_add(3 * mss);
        
        self.congestion.in_recovery = true;
    }

    /// Called when a loss is detected (RTO timeout)
    ///
    /// More severe than fast retransmit - go back to slow start
    pub fn on_loss(&mut self) {
        let mss = self.congestion.mss as u32;
        
        // ssthresh = max(cwnd / 2, 2*MSS)
        self.congestion.ssthresh = (self.congestion.cwnd / 2).max(2 * mss);
        
        // cwnd = 1 MSS (slow start)
        self.congestion.cwnd = mss;
        
        // Exit recovery if in it
        self.congestion.in_recovery = false;
        self.congestion.dup_ack_count = 0;
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
        if !self.congestion.nagle_enabled {
            return false;
        }
        
        // If data fills an MSS, send immediately
        if data_len >= self.congestion.mss as usize {
            return false;
        }
        
        // If no outstanding data, send immediately
        if self.tx.outstanding_bytes == 0 {
            return false;
        }
        
        // Small packet with outstanding data: delay
        true
    }

    /// Disable Nagle's algorithm (like TCP_NODELAY socket option)
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.congestion.nagle_enabled = !nodelay;
    }

    // ========================================================================
    // TCP Keepalive
    // ========================================================================

    /// Enable/disable keepalive with custom parameters
    pub fn set_keepalive(&mut self, enabled: bool, idle_us: Option<u64>, interval_us: Option<u64>, count: Option<u8>) {
        self.timers.keepalive_enabled = enabled;
        if let Some(idle) = idle_us {
            self.timers.keepalive_idle = idle;
        }
        if let Some(interval) = interval_us {
            self.timers.keepalive_interval = interval;
        }
        if let Some(c) = count {
            self.timers.keepalive_count = c;
        }
    }

    /// Record activity on the connection (resets keepalive timer)
    pub fn on_activity(&mut self, current_time: u64) {
        self.timers.last_activity_time = current_time;
        self.timers.keepalive_probes_sent = 0;
    }

    /// Check if keepalive probe should be sent
    /// 
    /// Returns:
    /// - None: No action needed
    /// - Some(true): Send keepalive probe
    /// - Some(false): Connection dead (too many probes failed)
    pub fn check_keepalive(&mut self, current_time: u64) -> Option<bool> {
        if !self.timers.keepalive_enabled {
            return None;
        }
        
        if !self.is_established() {
            return None;
        }
        
        let elapsed = current_time.saturating_sub(self.timers.last_activity_time);
        
        if self.timers.keepalive_probes_sent == 0 {
            // First probe after idle time
            if elapsed >= self.timers.keepalive_idle {
                self.timers.keepalive_probes_sent = 1;
                return Some(true);
            }
        } else {
            // Subsequent probes at interval
            let probe_time = self.timers.keepalive_idle + 
                (self.timers.keepalive_probes_sent as u64 - 1) * self.timers.keepalive_interval;
            
            if elapsed >= probe_time + self.timers.keepalive_interval {
                if self.timers.keepalive_probes_sent >= self.timers.keepalive_count {
                    // Too many probes - connection is dead
                    return Some(false);
                }
                self.timers.keepalive_probes_sent += 1;
                return Some(true);
            }
        }
        
        None
    }

    /// Reset keepalive state (call when ACK received)
    pub fn reset_keepalive(&mut self) {
        self.timers.keepalive_probes_sent = 0;
    }

    // ========================================================================
    // Zero-Window Probe (RFC 1122 Section 4.2.2.17)
    // ========================================================================

    /// ゼロウィンドウプローブ間隔 (マイクロ秒): 500ms
    const ZWP_INITIAL_INTERVAL_US: u64 = 500_000;
    /// ゼロウィンドウプローブ最大再試行回数
    const ZWP_MAX_PROBES: u8 = 10;

    /// Check if zero-window probe should be sent.
    ///
    /// Returns:
    /// - Some(true):  Send a probe (peer window is 0 and interval elapsed)
    /// - Some(false): Too many probes — consider connection dead
    /// - None:        No action needed (non-zero window or interval not elapsed)
    pub fn check_zero_window_probe(&mut self, current_time: u64) -> Option<bool> {
        // Only probe in Established state when peer window is 0
        if !self.is_established() {
            return None;
        }
        let effective_wnd = self.get_effective_snd_wnd();
        if effective_wnd > 0 {
            // Window opened — reset probe state
            if self.timers.zwp_probes_sent > 0 {
                self.timers.zwp_probes_sent = 0;
            }
            return None;
        }

        // Peer window is zero
        if self.timers.zwp_probes_sent >= Self::ZWP_MAX_PROBES {
            return Some(false); // Connection dead
        }

        // Exponential backoff: initial * 2^min(probes, 6)
        let backoff = 1u64 << core::cmp::min(self.timers.zwp_probes_sent, 6);
        let interval = Self::ZWP_INITIAL_INTERVAL_US.saturating_mul(backoff);
        let elapsed = current_time.saturating_sub(self.timers.zwp_last_probe_time);

        if elapsed >= interval {
            self.timers.zwp_probes_sent = self.timers.zwp_probes_sent.saturating_add(1);
            self.timers.zwp_last_probe_time = current_time;
            Some(true) // Send probe
        } else {
            None
        }
    }

    // ========================================================================
    // TCP Window Scaling (RFC 7323)
    // ========================================================================

    /// Get effective send window (peer's window scaled)
    pub fn get_effective_snd_wnd(&self) -> u32 {
        if self.options.wscale_enabled {
            (self.seq.snd_wnd as u32) << self.options.rcv_wscale
        } else {
            self.seq.snd_wnd as u32
        }
    }

    /// Get effective receive window (our window scaled)
    pub fn get_effective_rcv_wnd(&self) -> u32 {
        self.options.rcv_wnd_scaled
    }

    /// Set peer's window scale factor (from SYN/SYN-ACK option)
    pub fn set_peer_wscale(&mut self, scale: u8) {
        // RFC 7323: scale factor must be <= 14
        self.options.rcv_wscale = scale.min(14);
        self.options.wscale_enabled = true;
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
        self.options.rcv_wnd_scaled = available_buffer;
        // Calculate the 16-bit window field (scaled down)
        if self.options.wscale_enabled {
            self.seq.rcv_wnd = (available_buffer >> self.options.snd_wscale).min(65535) as u16;
        } else {
            self.seq.rcv_wnd = available_buffer.min(65535) as u16;
        }
    }

    /// 受信バッファの空き容量に基づいて受信ウィンドウを更新する
    pub fn update_window_from_buffer(&mut self) {
        let avail = self.recv_buffer_available_bytes() as u32;
        self.update_rcv_wnd(avail);
    }

    // ========================================================================
    // TCP Timestamps (RFC 7323)
    // ========================================================================

    /// Get current timestamp value for outgoing segment
    pub fn get_ts_val(&mut self) -> u32 {
        self.options.ts_val = self.options.ts_val.wrapping_add(1);
        self.options.ts_val
    }

    /// Process incoming timestamp option
    /// 
    /// Updates ts_recent for PAWS and prepares ts_ecr for reply
    pub fn process_ts_option(&mut self, ts_val: u32, _ts_ecr: u32, current_time: u64, seq_num: u32) {
        // Only update ts_recent if segment is in sequence
        if seq_num == self.seq.rcv_nxt || self.options.ts_recent == 0 {
            self.options.ts_recent = ts_val;
            self.options.ts_recent_age = current_time;
        }
        
        // Echo back the received timestamp
        self.options.ts_ecr = ts_val;
    }

    /// Check PAWS (Protection Against Wrapped Sequences)
    /// 
    /// Returns true if segment should be rejected (old duplicate)
    pub fn check_paws(&self, ts_val: u32, current_time: u64) -> bool {
        if !self.options.ts_enabled || self.options.ts_recent == 0 {
            return false;
        }
        
        // RFC 7323: If ts_recent is less than 24 days old and 
        // incoming ts_val < ts_recent, reject segment
        const PAWS_IDLE_LIMIT: u64 = 24 * 24 * 60 * 60 * 1_000_000; // 24 days in microseconds
        
        let age = current_time.saturating_sub(self.options.ts_recent_age);
        if age < PAWS_IDLE_LIMIT {
            // Compare timestamps (handling wrap-around)
            let diff = ts_val.wrapping_sub(self.options.ts_recent) as i32;
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
        if !self.options.ts_enabled || ts_ecr == 0 {
            return None;
        }
        
        // RTT = current_ts - ts_ecr (in timestamp units)
        // Assuming 1ms per tick (common convention)
        let rtt_ticks = current_ts.wrapping_sub(ts_ecr);
        Some(rtt_ticks as u64 * 1000) // Convert to microseconds
    }

    /// Enable timestamps (call when negotiated in SYN)
    pub fn enable_timestamps(&mut self, initial_ts: u32) {
        self.options.ts_enabled = true;
        self.options.ts_val = initial_ts;
    }

    // ========================================================================
    // TCP SACK (RFC 2018)
    // ========================================================================

    /// Enable SACK (call when negotiated in SYN)
    pub fn enable_sack(&mut self) {
        self.options.sack_enabled = true;
    }

    /// Add a SACK block for out-of-order segment received
    /// 
    /// Called when we receive data out of order to build SACK option
    pub fn add_sack_block(&mut self, left: u32, right: u32) {
        if !self.options.sack_enabled {
            return;
        }
        
        // Insert new block, maintaining most recent first
        // Shift existing blocks down
        for i in (1..4).rev() {
            self.options.sack_blocks[i] = self.options.sack_blocks[i - 1];
        }
        self.options.sack_blocks[0] = (left, right);
        self.options.sack_block_count = (self.options.sack_block_count + 1).min(4);
    }

    /// Process SACK option received from peer
    /// 
    /// Updates scoreboard to mark segments as selectively acknowledged
    pub fn process_sack_option(&mut self, blocks: &[(u32, u32)]) {
        for &(left, right) in blocks {
            // Merge or add to scoreboard
            let mut merged = false;
            for (l, r) in self.options.sack_scoreboard.iter_mut() {
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
                self.options.sack_scoreboard.push((left, right));
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
        for &(left, right) in &self.options.sack_scoreboard {
            if Self::seq_in_range(seq, left, right) && 
               (Self::seq_in_range(end, left, right) || end == right) {
                return true;
            }
        }
        false
    }

    /// Clear SACK scoreboard on new cumulative ACK
    pub fn clear_sacked_below(&mut self, ack: u32) {
        self.options.sack_scoreboard.retain(|&(left, _)| {
            let diff = left.wrapping_sub(ack) as i32;
            diff >= 0
        });
    }

    /// Get SACK blocks to include in outgoing ACK
    pub fn get_sack_blocks(&self) -> &[(u32, u32)] {
        &self.options.sack_blocks[..self.options.sack_block_count as usize]
    }
}
