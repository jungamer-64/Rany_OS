use super::*;
use crate::net::l3::icmp::{IcmpType, DestUnreachCode};


impl TcpControlBlock {
    pub fn new(local_addr: EndpointAddr) -> Self {
        let now = crate::task::timer::current_tick();
        
        // Generate a cryptographically secure random Initial Sequence Number (ISN).
        // Using ISN randomization (RFC 6528) is critical to prevent TCP spoofing and hijacking.
        let isn = generate_initial_seq(local_addr, None);

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

    /// Regenerate ISN once remote address is known (RFC 6528 compliant)
    pub fn regenerate_isn(&mut self) {
        if let Some(remote) = self.endpoints.remote_addr {
            let isn = generate_initial_seq(self.endpoints.local_addr, Some(remote));
            self.seq.snd_nxt = isn;
            self.seq.snd_una = isn;
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
    pub fn local_addr(&self) -> EndpointAddr {
        self.endpoints.local_addr
    }

    #[inline]
    pub fn remote_addr(&self) -> Option<EndpointAddr> {
        self.endpoints.remote_addr
    }

    #[inline]
    pub fn set_remote_addr(&mut self, remote: EndpointAddr) {
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
    pub fn snd_wnd(&self) -> u32 {
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

    /// Enqueue an out-of-order segment
    pub fn enqueue_ooo_payload(&mut self, mut seq: u32, mut packet: PacketRef) -> bool {
        let rcv_nxt = self.seq.rcv_nxt;

        // 1. Acknowledge parts: skip data before rcv_nxt
        let diff = rcv_nxt.wrapping_sub(seq);
        if (diff as i32) > 0 {
            let skip = diff as usize;
            if skip >= packet.len() {
                return false; // Entirely old
            }
            // Trim the packet using PacketRef's built-in advance mechanism
            packet.advance(skip);
            seq = rcv_nxt;
        }

        // Limit per-connection OOO segments
        const MAX_PER_CONN_OOO: usize = 16;
        if self.rx.ooo_queue.len() >= MAX_PER_CONN_OOO {
            // ... (eviction logic)
            let mut furthest_seq: Option<u32> = None;
            for &s in self.rx.ooo_queue.keys() {
                if furthest_seq.is_none() || (s.wrapping_sub(seq) as i32) > (furthest_seq.unwrap().wrapping_sub(seq) as i32) {
                    furthest_seq = Some(s);
                }
            }

            if let Some(f_seq) = furthest_seq {
                if (f_seq.wrapping_sub(seq) as i32) > 0 {
                    if self.rx.ooo_queue.remove(&f_seq).is_some() {
                        GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        // 2. Check for overlaps with existing OOO segments
        // If we already have a segment starting at the same position,
        // keep the longer one.
        if let Some(existing) = self.rx.ooo_queue.get(&seq) {
            if existing.len() >= packet.len() {
                return false; // Existing is better
            }
            // New one is longer, replace it
            self.rx.ooo_queue.remove(&seq);
            GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
        }

        // Security: Check global OOO limit
        if GLOBAL_OOO_COUNT.load(Ordering::Relaxed) >= GLOBAL_MAX_OOO_SEGMENTS {
            return false;
        }

        self.rx.ooo_queue.insert(seq, packet);
        GLOBAL_OOO_COUNT.fetch_add(1, Ordering::Relaxed);
        true
    }
    /// Try to drain contiguous OOO segments into the receive buffer
    pub fn drain_ooo_segments(&mut self) -> u32 {
        // First, prune segments that are now entirely before rcv_nxt
        self.prune_ooo_segments();

        let mut drained_count = 0;
        let mut current_rcv_nxt = self.seq.rcv_nxt;

        while let Some(packet) = self.rx.ooo_queue.remove(&current_rcv_nxt) {
            GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
            let len = packet.len();

            if self.rx.recv_buffer_bytes + len <= self.rx.recv_buffer_limit_bytes {
                self.rx.recv_buffer_bytes += len;
                self.rx.recv_buffer.push_back(packet);
                current_rcv_nxt = current_rcv_nxt.wrapping_add(len as u32);
                drained_count += 1;
            } else {
                self.rx.ooo_queue.insert(current_rcv_nxt, packet);
                GLOBAL_OOO_COUNT.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }

        if drained_count > 0 {
            self.seq.rcv_nxt = current_rcv_nxt;
            self.wake_read_waiter();
        }

        current_rcv_nxt
    }

    /// Remove outdated OOO segments (before rcv_nxt)
    pub fn prune_ooo_segments(&mut self) {
        let rcv_nxt = self.seq.rcv_nxt;
        let outdated: Vec<u32> = self.rx.ooo_queue.keys()
            .filter(|&&seq| (seq.wrapping_sub(rcv_nxt) as i32) < 0)
            .cloned()
            .collect();

        for seq in outdated {
            if self.rx.ooo_queue.remove(&seq).is_some() {
                GLOBAL_OOO_COUNT.fetch_sub(1, Ordering::Relaxed);
            }
        }
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
        let new_wnd = if self.options.wscale_enabled {
            (wnd as u32) << self.options.rcv_wscale
        } else {
            wnd as u32
        };
        self.seq.snd_wnd = new_wnd;
        if new_wnd > self.seq.max_snd_wnd {
            self.seq.max_snd_wnd = new_wnd;
        }
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
        core::cmp::min(self.congestion.cwnd, self.seq.snd_wnd)
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
                // Security: Limit backlog size to prevent SYN flood memory exhaustion
                const TCP_BACKLOG_LIMIT: usize = 128;
                if backlog.len() >= TCP_BACKLOG_LIMIT {
                    log::warn!("[NET] TCP Backlog full - dropping new connection");
                    return;
                }

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

    #[inline]
    pub fn last_snd_wnd(&self) -> u16 {
        self.congestion.last_snd_wnd
    }

    #[inline]
    pub fn set_last_snd_wnd(&mut self, wnd: u16) {
        self.congestion.last_snd_wnd = wnd;
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
        let ts_val = self.get_ts_val(); // Get new timestamp for retransmission
        let oldest = self.timers.unacked_segments.front_mut()?;
        oldest.sent_time = current_time;
        oldest.ts_val = ts_val;
        oldest.retransmit_count = oldest.retransmit_count.saturating_add(1);
        Some((oldest.seq, oldest.data.clone()))
    }

    #[inline]
    pub fn touch_unacked_segment_for_retransmit(&mut self, seq: u32, current_time: u64) -> bool {
        let ts_val = self.get_ts_val(); // Get new timestamp for retransmission
        if let Some(seg) = self.find_unacked_segment_mut_by_seq(seq) {
            seg.sent_time = current_time;
            seg.ts_val = ts_val;
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
        let ts_val = self.options.ts_val; // Use the current timestamp that was placed in the header
        self.timers.unacked_segments.push_back(UnackedSegment {
            seq,
            data,
            sent_time: current_time,
            ts_val,
            retransmit_count: 0,
            flags,
        });
    }

    #[inline]
    fn retain_unacked_after_ack_and_count_removed(&mut self, ack_num: u32, current_time: u64) -> (u32, Option<u64>) {
        let mut removed = 0u32;
        let mut rtt_sample = None;
        let mut old_queue = core::mem::take(&mut self.timers.unacked_segments);
        let mut kept = VecDeque::with_capacity(old_queue.len());

        while let Some(mut seg) = old_queue.pop_front() {
            let end_seq = Self::unacked_end_seq(&seg);

            // Fully acknowledged: drop segment entirely.
            if !TcpProcessor::seq_after(end_seq, ack_num) {
                let seq_len = Self::unacked_seq_space_len(&seg);
                removed = removed.saturating_add(seq_len);

                // Karn's Algorithm: Only take RTT sample if segment was NOT retransmitted.
                if seg.retransmit_count == 0 && rtt_sample.is_none() {
                    rtt_sample = Some(current_time.saturating_sub(seg.sent_time));
                }
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
        (removed, rtt_sample)
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
        seg.seq = ack_num;

        if (seg.flags & 0x02) != 0 && acked > 0 { // SYN
            seg.flags &= !0x02;
            acked -= 1;
        }

        let payload_trim = core::cmp::min(acked as usize, seg.data.len());
        if payload_trim > 0 {
            seg.data.drain(..payload_trim);
            acked -= payload_trim as u32;
        }

        if (seg.flags & 0x01) != 0 && acked > 0 { // FIN
            seg.flags &= !0x01;
            acked -= 1;
        }

        debug_assert_eq!(acked, 0, "partial ACK trim exceeded segment sequence-space");
        ack_num.wrapping_sub(original_seq)
    }

    /// Remove acknowledged segments from retransmission queue
    pub fn ack_segments(&mut self, ack_num: u32, current_time: u64) {
        // Remove all segments with seq + len <= ack_num and count removed sequence-space bytes.
        let (removed, rtt_sample) = self.retain_unacked_after_ack_and_count_removed(ack_num, current_time);
        self.tx.outstanding_bytes = self.tx.outstanding_bytes.saturating_sub(removed);

        if let Some(rtt) = rtt_sample {
            if rtt > 0 {
                self.update_rto(rtt);
            }
        }

        // Reset retransmit count on successful ACK
        if self.unacked_queue_is_empty() {
            self.timers.retransmit_count = 0;
        }
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
            // Security: In production, limit is 0 to disable heap-allocating fallback.
            // We return false here to indicate buffer is full/unavailable, but do NOT 
            // close the connection. This allows the stack to send an ACK with window 0
            // or just drop the segment, following standard TCP flow control.
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
        const MIN_RTO: u64 = 200;    // 200ms
        const MAX_RTO: u64 = 60_000; // 60 seconds in milliseconds

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

        // RTO = SRTT + max(G, 4 * RTTVAR) where G is clock granularity (assume 1ms)
        let srtt = self.timers.srtt.unwrap_or(rtt_sample);
        let rttvar = self.timers.rttvar.unwrap_or(rtt_sample / 2);
        self.timers.rto = (srtt + core::cmp::max(1, 4 * rttvar)).clamp(MIN_RTO, MAX_RTO);
    }

    /// Backoff RTO on retransmission timeout
    pub fn backoff_rto(&mut self) {
        const MAX_RTO: u64 = 60_000; // 60 seconds in milliseconds
        self.timers.rto = (self.timers.rto * 2).min(MAX_RTO);
        self.timers.retransmit_count += 1;
    }

    #[inline]
    pub(crate) fn seq_space_len_for_len_flags(data_len: usize, flags: u16) -> u32 {
        let mut len = data_len as u32;
        if flags & 0x02 != 0 { // SYN
            len = len.saturating_add(1);
        }
        if flags & 0x01 != 0 { // FIN
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

    /// Check if retransmission timeout has occurred
    pub fn check_retransmit_timeout(&self, current_time: u64) -> bool {
        match self.oldest_unacked_elapsed(current_time) {
            Some(elapsed) => elapsed >= self.timers.rto,
            None => false,
        }
    }

    /// Schedule a delayed ACK (RFC 1122)
    ///
    /// Returns true if an immediate ACK should be sent (already had a pending ACK)
    pub fn schedule_delayed_ack(&mut self, current_time: u64) -> bool {
        if self.timers.ack_pending {
            // "An ACK SHOULD be generated for at least every second full-sized segment"
            // We just send it on the second segment of any size for simplicity.
            self.timers.ack_pending = false;
            self.timers.delayed_ack_timer = 0;
            true
        } else {
            self.timers.ack_pending = true;
            self.timers.delayed_ack_timer = current_time;
            false
        }
    }

    /// Check if delayed ACK timeout has occurred (usually 200ms)
    pub fn check_delayed_ack_timeout(&self, current_time: u64) -> bool {
        if self.timers.ack_pending {
            let elapsed = current_time.saturating_sub(self.timers.delayed_ack_timer);
            elapsed >= 200 // 200ms is the standard max delay
        } else {
            false
        }
    }

    /// Clear pending delayed ACK (e.g. because we sent an ACK with data)
    pub fn clear_delayed_ack(&mut self) {
        self.timers.ack_pending = false;
        self.timers.delayed_ack_timer = 0;
    }

    // ========================================================================
    // Congestion Control (RFC 5681)
    // ========================================================================

    /// Called when a new (non-duplicate) ACK is received
    ///
    /// Implements:
    /// - Slow Start (cwnd < ssthresh): cwnd += bytes_acked (up to 1 MSS)
    /// - Congestion Avoidance (cwnd >= ssthresh): cwnd += mss per RTT
    pub fn on_new_ack(&mut self, bytes_acked: u32) {
        let mss = self.congestion.mss as u32;
        
        // Exit fast recovery on new ACK
        if self.congestion.in_recovery {
            self.congestion.in_recovery = false;
            self.congestion.cwnd = self.congestion.ssthresh;
            self.congestion.bytes_acked_in_ca = 0;
        }
        
        // Reset dup ACK counter
        self.congestion.dup_ack_count = 0;
        
        if self.congestion.cwnd < self.congestion.ssthresh {
            // Slow Start: exponential growth
            // RFC 5681: Increase cwnd by at most SMSS bytes for each ACK
            self.congestion.cwnd = self.congestion.cwnd.saturating_add(bytes_acked.min(mss));
        } else if self.congestion.cwnd > 0 {
            // Congestion Avoidance: linear growth (AIMD - Additive Increase)
            // RFC 5681: Increase cwnd by at most 1 MSS per RTT
            self.congestion.bytes_acked_in_ca = self.congestion.bytes_acked_in_ca.saturating_add(bytes_acked);
            if self.congestion.bytes_acked_in_ca >= self.congestion.cwnd {
                self.congestion.bytes_acked_in_ca = self.congestion.bytes_acked_in_ca.saturating_sub(self.congestion.cwnd);
                self.congestion.cwnd = self.congestion.cwnd.saturating_add(mss);
            }
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

        // RFC 5681: ssthresh = max(FlightSize / 2, 2*MSS)
        self.congestion.ssthresh = (self.tx.outstanding_bytes / 2).max(2 * mss);

        // cwnd = 1 MSS (slow start after loss)
        self.congestion.cwnd = mss;
    }

    /// Handle ICMP Source Quench (RFC 1122 Section 4.2.3.9)
    pub fn on_source_quench(&mut self) {
        let mss = self.congestion.mss as u32;

        // Reduce amount of data in flight by reducing congestion window.
        // Similar to Fast Retransmit (RFC 5681).
        self.congestion.ssthresh = (self.tx.outstanding_bytes / 2).max(2 * mss);
        self.congestion.cwnd = self.congestion.ssthresh;
    }

    /// Handle ICMP Error (RFC 1122 Section 4.2.3.9)
    pub fn on_icmp_error(&mut self, icmp_type: IcmpType, code: u8) {
        // RFC 1122: "A TCP SHOULD notify the user of the error, but it SHOULD NOT 
        // close the connection."
        
        // However, for SYN-SENT state, certain errors mean the connection 
        // attempt failed (e.g. Port Unreachable = Connection Refused).
        if self.state == TcpState::SynSent {
            if icmp_type == IcmpType::DestinationUnreachable {
                match DestUnreachCode::from(code) {
                    DestUnreachCode::PortUnreachable => {
                        log::info!("[TCP] Connection refused by remote host (ICMP Port Unreachable)");
                        self.close_and_wake();
                        return;
                    }
                    DestUnreachCode::HostUnreachable | DestUnreachCode::NetworkUnreachable => {
                        // RFC 1122 Section 4.2.3.9: "it SHOULD NOT close the connection."
                        // We just log it and wait for timeout or retry.
                        log::info!("[TCP] Remote host/network unreachable (ICMP); keeping connection open");
                        return;
                    }
                    _ => {}
                }
            }
        }

        // For established connections, we just log it for now.
        // In a more complete implementation, we would store the error to be 
        // returned by the next read/write operation.
        log::info!("[TCP] Received ICMP error (Type {:?}, Code {}) for established connection", icmp_type, code);
    }

    /// Check if sending should be delayed (Nagle's algorithm + Sender SWS avoidance)
    ///
    /// Following RFC 1122 Section 4.2.3.4 (Sender SWS Avoidance) and Section 4.2.3.2 (Nagle's).
    pub fn should_delay_send(&self, data_len: usize) -> bool {
        // --- 1. Maximum-sized segment can be sent ---
        if data_len >= self.congestion.mss as usize {
            return false; // Send immediately
        }

        // --- 2. Sender SWS Avoidance: Window is large enough ---
        // "at least half of the maximum window size seen so far on this connection"
        let sws_threshold = self.seq.max_snd_wnd / 2;
        if self.seq.snd_wnd >= sws_threshold && self.seq.snd_wnd > 0 && data_len > 0 {
            // If the window is large enough to avoid SWS, we can potentially send.
            // But we still need to check Nagle's algorithm.
        } else if self.tx.outstanding_bytes > 0 {
            // SWS avoidance: Window is small and we already have data in flight.
            return true; // Delay
        }

        // --- 3. Nagle's Algorithm ---
        if !self.congestion.nagle_enabled {
            return false; // NODELAY enabled: send immediately
        }

        // If there is unacknowledged data, delay small segments
        if self.tx.outstanding_bytes > 0 {
            return true; // Delay
        }

        false // No outstanding data: send immediately
    }
    /// Disable Nagle's algorithm (like TCP_NODELAY socket option)
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.congestion.nagle_enabled = !nodelay;
    }

    // ========================================================================
    // TCP Keepalive
    // ========================================================================

    /// Enable/disable keepalive with custom parameters (all times in milliseconds)
    pub fn set_keepalive(&mut self, enabled: bool, idle_ms: Option<u64>, interval_ms: Option<u64>, count: Option<u8>) {
        self.timers.keepalive_enabled = enabled;
        if let Some(idle) = idle_ms {
            self.timers.keepalive_idle = idle;
        }
        if let Some(interval) = interval_ms {
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

    /// ゼロウィンドウプローブ間隔 (ミリ秒): 500ms
    const ZWP_INITIAL_INTERVAL_MS: u64 = 500;
    /// ゼロウィンドウプローブ最大再試行回数
    const ZWP_MAX_PROBES: u8 = 10;

    /// Check if zero-window probe should be sent.
    ///
    /// Returns:
    /// - Some(true):  Send a probe (peer window is 0 and interval elapsed)
    /// - None:        No action needed (non-zero window or interval not elapsed)
    pub fn check_zero_window_probe(&mut self, current_time: u64) -> Option<bool> {
        // Only probe in Established state when peer window is 0
        if !self.is_established() {
            return None;
        }
        let effective_wnd = self.get_effective_snd_wnd();
        if effective_wnd > 0 || self.tx.send_buffer_bytes == 0 {
            // Window opened or no data to send — reset probe state
            if self.timers.zwp_probes_sent > 0 {
                self.timers.zwp_probes_sent = 0;
            }
            return None;
        }

        // Peer window is zero. 
        // RFC 1122 Section 4.2.2.17: "A TCP MUST NOT close a connection because the 
        // window is zero and the probe timer has expired."
        // We continue probing indefinitely (or until a very high limit) but with 
        // maximum backoff.

        // Exponential backoff: initial * 2^min(probes, 6)
        let backoff = 1u64 << core::cmp::min(self.timers.zwp_probes_sent, 6);
        let interval = Self::ZWP_INITIAL_INTERVAL_MS.saturating_mul(backoff);
        let elapsed = current_time.saturating_sub(self.timers.zwp_last_probe_time);

        if elapsed >= interval {
            self.timers.zwp_probes_sent = self.timers.zwp_probes_sent.saturating_add(1);
            if self.timers.zwp_probes_sent > 100 {
                 // Prevent overflow, keep it at a high but stable value
                 self.timers.zwp_probes_sent = 100;
            }
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

    /// Set peer's MSS (Maximum Segment Size) from SYN/SYN-ACK option
    #[inline]
    pub fn set_mss(&mut self, mss: u16) {
        self.congestion.mss = mss;
        // Also update initial cwnd if we're still using the default initial window
        if self.congestion.cwnd == 10 * 536 {
            self.congestion.cwnd = 10 * mss as u32;
        }
    }

    #[inline]
    pub fn set_sack_enabled(&mut self, enabled: bool) {
        self.options.sack_enabled = enabled;
    }

    #[inline]
    pub fn set_timestamps_enabled(&mut self, enabled: bool) {
        self.options.ts_enabled = enabled;
    }

    #[inline]
    pub fn update_timestamps(&mut self, ts_val: u32) {
        self.options.ts_recent = ts_val;
        self.options.ts_recent_age = crate::task::timer::current_tick();
    }

    #[inline]
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
        // SWS Avoidance: RFC 1122 Section 4.2.3.3
        // The receiver SHOULD NOT update the window if the update is less than 
        // min(MSS, 1/2*RCV.WND).  Here RCV.WND is the total receive buffer size.
        
        let old_wnd = self.options.rcv_wnd_scaled;
        let mss = self.congestion.mss as u32;
        let total_buffer = self.rx.recv_buffer_limit_bytes as u32;
        
        // If the window is shrinking, we MUST update it immediately to avoid 
        // buffer overflow and maintain correctness.
        if available_buffer < old_wnd {
            self.options.rcv_wnd_scaled = available_buffer;
        } else {
            // Window is growing or staying the same. Apply SWS avoidance.
            let increment = available_buffer - old_wnd;
            let threshold = core::cmp::min(mss, total_buffer / 2);
            
            if increment >= threshold || available_buffer == total_buffer || old_wnd == 0 {
                self.options.rcv_wnd_scaled = available_buffer;
            }
            // Else: Keep old_wnd to avoid Silly Window Syndrome
        }

        // Calculate the 16-bit window field (scaled down)
        if self.options.wscale_enabled {
            self.seq.rcv_wnd = (self.options.rcv_wnd_scaled >> self.options.snd_wscale).min(65535) as u16;
        } else {
            self.seq.rcv_wnd = self.options.rcv_wnd_scaled.min(65535) as u16;
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
    /// Updates ts_recent for PAWS and prepares ts_ecr for reply (RFC 7323 Section 5.3)
    pub fn process_ts_option(&mut self, ts_val: u32, _ts_ecr: u32, current_time: u64, seq_num: u32) {
        // RFC 7323 Section 5.3: Update TS.Recent if:
        // (1) SEG.TSval >= TS.Recent, AND
        // (2) SEG.SEQ <= last.ACK.sent (rcv_nxt)
        // Note: ts_recent == 0 check is for initialization.
        let in_sequence = (seq_num.wrapping_sub(self.seq.rcv_nxt) as i32) <= 0;
        let ts_not_older = (ts_val.wrapping_sub(self.options.ts_recent) as i32) >= 0;

        if (in_sequence && ts_not_older) || self.options.ts_recent == 0 {
            self.options.ts_recent = ts_val;
            self.options.ts_recent_age = current_time;
        }

        // RFC 7323 Section 5.2: The TSval to be sent in the TSecr field 
        // of the NEXT segment is the current value of TS.Recent.
        self.options.ts_ecr = self.options.ts_recent;
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
        const PAWS_IDLE_LIMIT_MS: u64 = 24 * 24 * 60 * 60 * 1_000; // 24 days in milliseconds
        
        let age = current_time.saturating_sub(self.options.ts_recent_age);
        if age < PAWS_IDLE_LIMIT_MS {
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
    /// Returns RTT in milliseconds if measurement is valid
    pub fn measure_rtt_from_ts(&self, ts_ecr: u32, current_ts: u32) -> Option<u64> {
        if !self.options.ts_enabled || ts_ecr == 0 {
            return None;
        }
        
        // RTT = current_ts - ts_ecr (in timestamp units)
        // Assuming 1ms per tick (common convention)
        let rtt_ticks = current_ts.wrapping_sub(ts_ecr);
        Some(rtt_ticks as u64) // Already in milliseconds
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
                // Security: Limit scoreboard size to prevent memory exhaustion (DoS)
                if self.options.sack_scoreboard.len() < 64 {
                    self.options.sack_scoreboard.push((left, right));
                }
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

    /// Build TCP options for an outgoing segment
    pub fn build_options(&mut self, flags: u16) -> Vec<u8> {
        let mut opts = Vec::new();
        let syn = flags & crate::net::l4::tcp::TcpHeader::FLAG_SYN != 0;
        let ack = flags & crate::net::l4::tcp::TcpHeader::FLAG_ACK != 0;

        // MSS (Maximum Segment Size) - Only in SYN
        if syn {
            opts.push(2); // Kind
            opts.push(4); // Length
            let mss = self.congestion.mss.to_be_bytes();
            opts.extend_from_slice(&mss);
        }

        // Window Scale - Only in SYN
        // RFC 7323: To use window scaling, it MUST be sent in the initial SYN.
        // In SYN-ACK, only send it if it was received in the SYN (wscale_enabled).
        if syn && (!ack || self.options.wscale_enabled) {
            opts.push(3); // Kind
            opts.push(3); // Length
            opts.push(self.options.snd_wscale); // Our scale factor
        }

        // SACK Permitted - Only in SYN
        // RFC 2018: Similar negotiation as Window Scale
        if syn && (!ack || self.options.sack_enabled) {
            opts.push(4); // Kind
            opts.push(2); // Length
        }

        // Timestamps (RFC 7323)
        // Only in SYN or if negotiated (ts_enabled)
        if (syn && !ack) || self.options.ts_enabled {
            opts.push(8);  // Kind
            opts.push(10); // Length
            let ts_val = self.get_ts_val().to_be_bytes();
            let ts_ecr = self.options.ts_ecr.to_be_bytes();
            opts.extend_from_slice(&ts_val);
            opts.extend_from_slice(&ts_ecr);
        }

        // SACK Blocks (RFC 2018) - Only in ACKs for out-of-order data
        if !syn && self.options.sack_enabled && self.options.sack_block_count > 0 {
            let count = self.options.sack_block_count as usize;
            opts.push(5); // Kind
            opts.push((2 + count * 8) as u8); // Length
            for i in 0..count {
                let (left, right) = self.options.sack_blocks[i];
                opts.extend_from_slice(&left.to_be_bytes());
                opts.extend_from_slice(&right.to_be_bytes());
            }
        }

        // Padding to 4-byte boundary (RFC 793)
        let remainder = opts.len() % 4;
        if remainder != 0 {
            for _ in 0..(4 - remainder) {
                opts.push(1); // NOP
            }
        }

        opts
    }
}
