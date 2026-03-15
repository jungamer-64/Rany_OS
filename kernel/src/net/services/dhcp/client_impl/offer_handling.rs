use super::*;
use crate::net::runtime::manager::NetIfId;

fn send_dhcpv4_packet_on(
    runtime: crate::net::runtime::NetRuntimeHandle,
    if_id: Option<NetIfId>,
    src_ip: Ipv4Address,
    src_port: u16,
    dst_ip: Ipv4Address,
    dst_port: u16,
    payload: &[u8],
    ttl: u8,
) -> bool {
    match if_id {
        Some(if_id) => crate::net::runtime::stack::enqueue_udp_send_on_with_src_in(
            runtime, if_id, src_ip, src_port, dst_ip, dst_port, payload, ttl,
        ),
        None => crate::net::runtime::stack::enqueue_udp_send_scoped_with_src_in(
            runtime,
            crate::net::types::InterfaceScope::Any,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            payload,
            ttl,
        ),
    }
}

impl DhcpClient {
    /// OFFER 受信時の副作用を適用する
    pub(super) fn apply_offer(&self, lease: DhcpLease, current_tick: u64) -> DhcpResponseResult {
        match self.offered_lease.lock() {
            Ok(mut g) => *g = Some(lease.clone()),
            Err(_) => log::error!(
                "[NET] DHCP Offer lock poisoned (process_response Offer) - skipping storing offer"
            ),
        }

        // Best-effort: ARP probe をイベントキュー経由で送信（デッドロック回避）
        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
            self.runtime,
            crate::net::l4::endpoint::event::NetworkEvent::ArpProbe {
                target_ip: *lease.ip_address.as_bytes(),
            },
        );
        self.offered_probe_at.store(current_tick, Ordering::SeqCst);

        DhcpResponseResult::Offer(lease)
    }

    /// ACK 受信時の副作用を適用する
    pub(super) fn apply_ack(&self, lease: DhcpLease, current_tick: u64) -> DhcpResponseResult {
        match self.lease.lock() {
            Ok(mut g) => *g = Some(lease.clone()),
            Err(_) => log::error!(
                "[NET] DHCP Lease lock poisoned (process_response Ack) - skipping storing lease"
            ),
        }
        // Clear any offer probe state
        self.offered_probe_at.store(0, Ordering::SeqCst);
        match self.state.lock() {
            Ok(mut g) => *g = DhcpState::Bound,
            Err(_) => log::error!(
                "[NET] DHCP State lock poisoned (process_response Ack) - state not updated"
            ),
        }
        self.state_time.store(current_tick, Ordering::SeqCst);
        self.retry_count.store(0, Ordering::SeqCst);

        DhcpResponseResult::Ack(lease)
    }

    /// NAK 受信時の副作用を適用する
    pub(super) fn apply_nak(&self) -> DhcpResponseResult {
        match self.state.lock() {
            Ok(mut g) => *g = DhcpState::Init,
            Err(_) => log::error!(
                "[NET] DHCP State lock poisoned (process_response Nak) - state not updated"
            ),
        }
        match self.offered_lease.lock() {
            Ok(mut g) => *g = None,
            Err(_) => log::error!(
                "[NET] DHCP Offer lock poisoned (process_response Nak) - skipping clear"
            ),
        }
        // Clear any probe timestamp
        self.offered_probe_at.store(0, Ordering::SeqCst);
        DhcpResponseResult::Nak
    }

    /// DHCP応答を処理
    pub fn process_response(
        &self,
        data: &[u8],
        current_tick: u64,
    ) -> Result<DhcpResponseResult, &'static str> {
        let header = self.validate_header(data)?;
        let opts = Self::parse_options(data);
        let msg_type = opts.message_type.ok_or("No message type in response")?;

        if matches!(msg_type, DhcpMessageType::Offer | DhcpMessageType::Ack) {
            let sid = opts.server_id.ok_or("No server identifier in response")?;
            self.validate_offer_ack(msg_type, header, sid)?;
        }

        match msg_type {
            DhcpMessageType::Offer => {
                let lease = Self::build_lease(header, opts, current_tick);
                Ok(self.apply_offer(lease, current_tick))
            }
            DhcpMessageType::Ack => {
                let lease = Self::build_lease(header, opts, current_tick);
                Ok(self.apply_ack(lease, current_tick))
            }
            DhcpMessageType::Nak => Ok(self.apply_nak()),
            _ => Err("Unexpected message type"),
        }
    }

    /// Build DHCPDECLINE packet for a conflicting IP
    pub fn build_decline(
        &self,
        buffer: &mut [u8],
        declined_ip: Ipv4Address,
        server_ip: Option<Ipv4Address>,
        _current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DhcpHeader::SIZE + 64 {
            return Err("Buffer too small");
        }

        let xid = self.xid.load(Ordering::SeqCst);

        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
        buffer[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // Message Type: DECLINE
        buffer[offset] = DhcpOption::MessageType as u8;
        buffer[offset + 1] = 1;
        buffer[offset + 2] = DhcpMessageType::Decline as u8;
        offset += 3;

        // Requested IP (the offending IP)
        buffer[offset] = DhcpOption::RequestedIp as u8;
        buffer[offset + 1] = 4;
        buffer[offset + 2..offset + 6].copy_from_slice(declined_ip.as_bytes());
        offset += 6;

        // Server Identifier (if provided)
        if let Some(sip) = server_ip {
            buffer[offset] = DhcpOption::ServerIdentifier as u8;
            buffer[offset + 1] = 4;
            buffer[offset + 2..offset + 6].copy_from_slice(sip.as_bytes());
            offset += 6;
        }

        // Client identifier
        buffer[offset] = DhcpOption::ClientIdentifier as u8;
        buffer[offset + 1] = 7;
        buffer[offset + 2] = 1; // Ethernet
        buffer[offset + 3..offset + 9].copy_from_slice(self.mac_address.as_bytes());
        offset += 9;

        // End
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        Ok(offset)
    }

    /// Send a DHCPDECLINE (best-effort)
    ///
    /// RFC 2131: DHCPDECLINE は src_ip = 0.0.0.0 で送信する。
    pub fn send_decline(&self, declined_ip: Ipv4Address, server_ip: Option<Ipv4Address>) -> bool {
        self.send_decline_on(None, declined_ip, server_ip)
    }

    pub fn send_decline_on(
        &self,
        if_id: Option<NetIfId>,
        declined_ip: Ipv4Address,
        server_ip: Option<Ipv4Address>,
    ) -> bool {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];
        match self.build_decline(&mut buf, declined_ip, server_ip, 0) {
            Ok(len) => {
                // Record for tests/diagnostics
                self.last_declined
                    .store(declined_ip.to_u32(), Ordering::SeqCst);

                let dst = server_ip.unwrap_or(Ipv4Address::new([255, 255, 255, 255]));
                send_dhcpv4_packet_on(
                    self.runtime,
                    if_id,
                    Ipv4Address::new([0, 0, 0, 0]),
                    DHCP_CLIENT_PORT,
                    dst,
                    DHCP_SERVER_PORT,
                    &buf[..len],
                    64,
                )
            }
            Err(_) => false,
        }
    }

    /// Build DHCPRELEASE packet
    pub fn build_release(
        &self,
        buffer: &mut [u8],
        _current_tick: u64,
    ) -> Result<usize, &'static str> {
        if buffer.len() < DhcpHeader::SIZE + 64 {
            return Err("Buffer too small");
        }

        let xid = self.xid.load(Ordering::SeqCst);

        // Need an active lease
        let lease = match self.lease.lock() {
            Ok(g) => g.clone().ok_or("No active lease")?,
            Err(_) => return Err("Lease lock poisoned"),
        };

        buffer[0..DhcpHeader::SIZE].fill(0);
        buffer[0] = DhcpOperation::Request as u8;
        buffer[1] = 1; // Ethernet
        buffer[2] = 6; // MAC address length
        buffer[3] = 0; // hops
        buffer[4..8].copy_from_slice(&xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
        buffer[10..12].copy_from_slice(&0u16.to_be_bytes()); // flags

        // ciaddr = current IP
        buffer[12..16].copy_from_slice(lease.ip_address.as_bytes());
        buffer[28..34].copy_from_slice(self.mac_address.as_bytes());

        let mut offset = DhcpHeader::SIZE;
        buffer[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        offset += 4;

        // Message Type: RELEASE
        buffer[offset] = DhcpOption::MessageType as u8;
        buffer[offset + 1] = 1;
        buffer[offset + 2] = DhcpMessageType::Release as u8;
        offset += 3;

        // Server Identifier
        buffer[offset] = DhcpOption::ServerIdentifier as u8;
        buffer[offset + 1] = 4;
        buffer[offset + 2..offset + 6].copy_from_slice(lease.server_ip.as_bytes());
        offset += 6;

        // Client identifier
        buffer[offset] = DhcpOption::ClientIdentifier as u8;
        buffer[offset + 1] = 7;
        buffer[offset + 2] = 1; // Ethernet
        buffer[offset + 3..offset + 9].copy_from_slice(self.mac_address.as_bytes());
        offset += 9;

        // End
        buffer[offset] = DhcpOption::End as u8;
        offset += 1;

        Ok(offset)
    }

    /// Send DHCPRELEASE (best-effort)
    pub fn send_release(&self) -> bool {
        self.send_release_on(None)
    }

    pub fn send_release_on(&self, if_id: Option<NetIfId>) -> bool {
        // Acquire lease to get server
        let lease = match self.lease.lock() {
            Ok(g) => g.clone(),
            Err(_) => return false,
        };

        let lease = match lease {
            Some(l) => l,
            None => return false,
        };

        // Record for tests/diagnostics
        self.last_released
            .store(lease.ip_address.to_u32(), Ordering::SeqCst);

        let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];
        match self.build_release(&mut buf, 0) {
            // RFC 2131: RELEASE は取得済みクライアントIPをソースIPとして使用
            Ok(len) => send_dhcpv4_packet_on(
                self.runtime,
                if_id,
                lease.ip_address,
                DHCP_CLIENT_PORT,
                lease.server_ip,
                DHCP_SERVER_PORT,
                &buf[..len],
                64,
            ),
            Err(_) => false,
        }
    }

    /// リースを解放
    pub fn release(&self) {
        let _ = self.release_on(None);
    }

    /// リースを指定インターフェース上で解放
    pub fn release_on(&self, if_id: Option<NetIfId>) -> bool {
        let released = self.send_release_on(if_id);

        match self.state.lock() {
            Ok(mut g) => *g = DhcpState::Init,
            Err(_) => log::error!("[NET] DHCP State lock poisoned (release) - state not updated"),
        }
        match self.lease.lock() {
            Ok(mut g) => *g = None,
            Err(_) => log::error!("[NET] DHCP Lease lock poisoned (release) - skipping clear"),
        }
        match self.offered_lease.lock() {
            Ok(mut g) => *g = None,
            Err(_) => log::error!("[NET] DHCP Offer lock poisoned (release) - skipping clear"),
        }
        // Reset probe timestamp
        self.offered_probe_at.store(0, Ordering::SeqCst);
        released
    }

    /// Send a DHCPDISCOVER packet for the current state machine cycle.
    ///
    /// RFC 2131: DHCPDISCOVER は src_ip = 0.0.0.0 で送信する。
    async fn send_discover_packet(&self, current_tick: u64) -> Result<bool, &'static str> {
        self.send_discover_packet_on(None, current_tick).await
    }

    async fn send_discover_packet_on(
        &self,
        if_id: Option<NetIfId>,
        current_tick: u64,
    ) -> Result<bool, &'static str> {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];
        let len = self.build_discover(&mut buf, current_tick)?;
        Ok(send_dhcpv4_packet_on(
            self.runtime,
            if_id,
            Ipv4Address::new([0, 0, 0, 0]),
            DHCP_CLIENT_PORT,
            Ipv4Address::new([255, 255, 255, 255]),
            DHCP_SERVER_PORT,
            &buf[..len],
            64,
        ))
    }

    /// Resolve DHCPREQUEST destination address from current state.
    fn request_destination_for_state(&self, state: DhcpState) -> Ipv4Address {
        match state {
            DhcpState::Renewing => match self.lease.lock() {
                Ok(lease) => lease
                    .as_ref()
                    .map(|l| l.server_ip)
                    .unwrap_or(Ipv4Address::new([255, 255, 255, 255])),
                Err(_) => Ipv4Address::new([255, 255, 255, 255]),
            },
            DhcpState::Requesting | DhcpState::Rebinding => Ipv4Address::new([255, 255, 255, 255]),
            _ => Ipv4Address::new([255, 255, 255, 255]),
        }
    }

    /// Send a DHCPREQUEST packet for Requesting/Renewing/Rebinding.
    ///
    /// RFC 2131: Renewing 時は取得済みIPをソースIPとして使用し、
    /// それ以外 (Requesting/Rebinding) は src_ip = 0.0.0.0 で送信する。
    async fn send_request_packet(&self, current_tick: u64) -> Result<bool, &'static str> {
        self.send_request_packet_on(None, current_tick).await
    }

    async fn send_request_packet_on(
        &self,
        if_id: Option<NetIfId>,
        current_tick: u64,
    ) -> Result<bool, &'static str> {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_SIZE];
        let len = self.build_request(&mut buf, current_tick)?;
        let state = self.state();
        let dst = self.request_destination_for_state(state);
        let src_ip = if state == DhcpState::Renewing {
            // Renewing: ユニキャストで取得済みIPを使用
            match self.lease.lock() {
                Ok(lease) => lease
                    .as_ref()
                    .map(|l| l.ip_address)
                    .unwrap_or(Ipv4Address::new([0, 0, 0, 0])),
                Err(_) => Ipv4Address::new([0, 0, 0, 0]),
            }
        } else {
            // Requesting/Rebinding: src_ip = 0.0.0.0
            Ipv4Address::new([0, 0, 0, 0])
        };
        Ok(send_dhcpv4_packet_on(
            self.runtime,
            if_id,
            src_ip,
            DHCP_CLIENT_PORT,
            dst,
            DHCP_SERVER_PORT,
            &buf[..len],
            64,
        ))
    }

    /// Drive DHCP state machine and emit outbound packets when state changes
    /// or retransmission timers fire.
    pub async fn drive(&self, current_tick: u64, tick_rate: u64) -> Result<(), &'static str> {
        self.drive_on(current_tick, tick_rate, None).await
    }

    pub async fn drive_on_interface(
        &self,
        if_id: NetIfId,
        current_tick: u64,
        tick_rate: u64,
    ) -> Result<(), &'static str> {
        self.drive_on(current_tick, tick_rate, Some(if_id)).await
    }

    async fn drive_on(
        &self,
        current_tick: u64,
        tick_rate: u64,
        if_id: Option<NetIfId>,
    ) -> Result<(), &'static str> {
        let state_before = self.state();

        // Initial kick: INIT immediately sends DISCOVER.
        if state_before == DhcpState::Init {
            let _ = self.send_discover_packet_on(if_id, current_tick).await?;
            return Ok(());
        }

        let transitioned = self.check_timeout(current_tick, tick_rate).await;
        let state_after = self.state();

        // OFFER passed ARP probe and moved into REQUESTING.
        if state_before == DhcpState::Selecting && state_after == DhcpState::Requesting {
            log::info!(
                "[NET] DHCP drive: Selecting->Requesting, sending REQUEST (tick={})",
                current_tick
            );
            match self.send_request_packet_on(if_id, current_tick).await {
                Ok(sent) => log::info!("[NET] DHCP REQUEST queued (sent={})", sent),
                Err(e) => {
                    log::error!("[NET] DHCP REQUEST failed: {}", e);
                    return Err(e);
                }
            }
            return Ok(());
        }

        if transitioned {
            log::info!(
                "[NET] DHCP drive: transitioned, state_after={:?} (tick={})",
                state_after,
                current_tick
            );
            match state_after {
                // Selecting retransmit / conflict recovery.
                DhcpState::Selecting => {
                    let _ = self.send_discover_packet_on(if_id, current_tick).await?;
                }
                // Requesting, Renewing, Rebinding retransmits.
                DhcpState::Requesting | DhcpState::Renewing | DhcpState::Rebinding => {
                    let _ = self.send_request_packet_on(if_id, current_tick).await?;
                }
                // Retry budget exhausted and reset to INIT -> restart discovery.
                DhcpState::Init => {
                    log::warn!("[NET] DHCP retries exhausted, restarting discovery");
                    let _ = self.send_discover_packet_on(if_id, current_tick).await?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Force immediate renew (when bound) or restart discovery.
    pub fn force_renew_or_restart(&self, current_tick: u64) {
        let state = self.state();
        match state {
            DhcpState::Bound | DhcpState::Renewing | DhcpState::Rebinding => {
                self.transition_state(DhcpState::Renewing);
            }
            _ => {
                self.transition_state(DhcpState::Init);
                self.clear_all_leases();
            }
        }
        self.state_time.store(current_tick, Ordering::SeqCst);
        self.retry_count.store(0, Ordering::SeqCst);
    }

    // --- check_timeout helper: transition state with error logging ---
    pub(super) fn transition_state(&self, new_state: DhcpState) {
        match self.state.lock() {
            Ok(mut g) => *g = new_state,
            Err(_) => log::error!("[NET] DHCP State lock poisoned - cannot transition state"),
        }
    }

    // --- check_timeout helper: clear all lease state ---
    pub(super) fn clear_all_leases(&self) {
        match self.lease.lock() {
            Ok(mut g) => *g = None,
            Err(_) => log::error!("[NET] DHCP Lease lock poisoned - cannot clear lease"),
        }
        match self.offered_lease.lock() {
            Ok(mut g) => *g = None,
            Err(_) => log::error!("[NET] DHCP Offer lock poisoned - cannot clear offer"),
        }
        self.offered_probe_at.store(0, Ordering::SeqCst);
    }

    // --- check_timeout helper: common retry-or-transition pattern ---
    pub(super) fn check_retry_or_transition(
        &self,
        elapsed_secs: u64,
        max_retry_state: DhcpState,
    ) -> bool {
        let retry = self.retry_count.load(Ordering::SeqCst);

        // RFC 2131: Exponential backoff (1, 2, 4, 8, 16, 32, 64 seconds)
        // We use a base interval of 4s * 2^retry, clamped at 64s.
        // We add a small amount of jitter to avoid synchronization (RFC 2131 recommendation).
        let base_interval = (4u64 << core::cmp::min(retry, 4)).min(64);

        // Add jitter ±1s using pseudo-randomness from available source
        let jitter = if retry > 0 {
            let rnd = crate::net::security::tls::crypto::random::generate_random()[0] as i64;
            (rnd % 3) - 1 // -1, 0, or 1
        } else {
            0
        };
        let interval = (base_interval as i64 + jitter).max(1) as u64;

        if elapsed_secs >= interval {
            let actual_retry = self.retry_count.fetch_add(1, Ordering::SeqCst);
            if actual_retry >= Self::MAX_RETRIES {
                self.transition_state(max_retry_state);
                self.retry_count.store(0, Ordering::SeqCst);
            }
            return true;
        }
        false
    }

    // --- check_timeout helper: send initial ARP probe for offered IP ---
    pub(super) fn send_initial_arp_probe(
        &self,
        offered_ip: Ipv4Address,
        current_tick: u64,
    ) -> bool {
        // ARP probe をイベントキュー経由で送信（デッドロック回避）
        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
            self.runtime,
            crate::net::l4::endpoint::event::NetworkEvent::ArpProbe {
                target_ip: *offered_ip.as_bytes(),
            },
        );
        self.offered_probe_at.store(current_tick, Ordering::SeqCst);
        false // wait for probe reply
    }

    // --- check_timeout helper: check ARP cache for address conflict ---
    pub(super) async fn check_arp_conflict(
        &self,
        offered_ip: Ipv4Address,
        _current_tick: u64,
    ) -> bool {
        // ARP解決結果を非同期で取得（RFC 2131 Section 2.2 / RFC 5227）
        // get_arp_cache() は現在のARPキャッシュスナップショットを返す
        let entries = crate::net::api::connections::get_arp_cache_in(self.runtime).await;
        for entry in entries {
            // offered_ip に対する解決済みエントリが存在すれば、他者がそのIPを使用中と判断
            if entry.ip == offered_ip.octets() && entry.complete {
                log::warn!(
                    "[NET-DHCP] ARP conflict detected for offered IP {}",
                    offered_ip
                );
                return true;
            }
        }

        // また、将来的な競合を防ぐため、追加のプローブを定期的に送信
        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
            self.runtime,
            crate::net::l4::endpoint::event::NetworkEvent::ArpProbe {
                target_ip: *offered_ip.as_bytes(),
            },
        );
        false
    }

    // --- check_timeout helper: handle ARP conflict by sending DECLINE ---
    pub(super) fn handle_conflict_decline(&self, offered_ip: Ipv4Address, server_ip: Ipv4Address) {
        let _ = self.send_decline(offered_ip, Some(server_ip));
        match self.offered_lease.lock() {
            Ok(mut og) => *og = None,
            Err(_) => log::error!(
                "[NET] DHCP Offer lock poisoned (check_timeout) - cannot clear after decline"
            ),
        }
        self.offered_probe_at.store(0, Ordering::SeqCst);
    }

    // --- check_timeout helper: evaluate ARP probe result ---
    pub(super) async fn check_arp_probe_result(
        &self,
        offered_ip: Ipv4Address,
        server_ip: Ipv4Address,
        current_tick: u64,
        tick_rate: u64,
        probe_at: u64,
    ) -> bool {
        let probe_secs = (current_tick.saturating_sub(probe_at)) / tick_rate;
        if probe_secs < Self::PROBE_WAIT_SECS {
            return false; // still waiting for ARP replies
        }

        if self.check_arp_conflict(offered_ip, current_tick).await {
            self.handle_conflict_decline(offered_ip, server_ip);
            return true; // prompt caller to retry discovery
        }

        // No conflict detected -> move to Requesting to accept offer
        self.transition_state(DhcpState::Requesting);
        // reset retry count for request flow
        self.retry_count.store(0, Ordering::SeqCst);
        true
    }

    // --- check_timeout helper: try ARP probe flow for Selecting ---
    pub(super) async fn try_selecting_arp_probe(
        &self,
        current_tick: u64,
        tick_rate: u64,
    ) -> Option<bool> {
        // Extract offered lease info then release the lock to avoid re-entrance deadlock
        let (offered_ip, server_ip) = {
            let off = self.offered_lease.lock().ok()?;
            let offered = off.as_ref()?;
            (offered.ip_address, offered.server_ip)
        };

        let probe_at = self.offered_probe_at.load(Ordering::SeqCst);
        if probe_at == 0 {
            return Some(self.send_initial_arp_probe(offered_ip, current_tick));
        }
        Some(
            self.check_arp_probe_result(offered_ip, server_ip, current_tick, tick_rate, probe_at)
                .await,
        )
    }

    // --- check_timeout helper: handle Selecting state ---
    pub(super) async fn handle_selecting_timeout(
        &self,
        current_tick: u64,
        tick_rate: u64,
        elapsed_secs: u64,
    ) -> bool {
        // If we have an offered lease, perform ARP probe & check for conflicts
        if let Some(result) = self.try_selecting_arp_probe(current_tick, tick_rate).await {
            return result;
        }
        // No offer yet or fallback to retransmit DISCOVER
        self.check_retry_or_transition(elapsed_secs, DhcpState::Init)
    }

    // --- check_timeout helper: handle Bound state ---
    pub(super) fn handle_bound_timeout(&self, current_tick: u64, tick_rate: u64) -> bool {
        if let Ok(guard) = self.lease.lock() {
            if let Some(lease) = guard.as_ref() {
                if lease.needs_renewal(current_tick, tick_rate) {
                    self.transition_state(DhcpState::Renewing);
                    // initialize retry counter and timestamp
                    self.state_time.store(current_tick, Ordering::SeqCst);
                    self.retry_count.store(0, Ordering::SeqCst);
                    return true;
                }
            }
        } else {
            log::error!("[NET] DHCP Lease lock poisoned (check_timeout) - skipping renewal check");
        }
        false
    }

    // --- check_timeout helper: handle Renewing state ---
    pub(super) fn handle_renewing_timeout(
        &self,
        current_tick: u64,
        tick_rate: u64,
        elapsed_secs: u64,
    ) -> bool {
        // If T2 is reached, move to Rebinding
        if let Ok(guard) = self.lease.lock() {
            if let Some(lease) = guard.as_ref() {
                if lease.needs_rebind(current_tick, tick_rate) {
                    self.transition_state(DhcpState::Rebinding);
                    self.state_time.store(current_tick, Ordering::SeqCst);
                    self.retry_count.store(0, Ordering::SeqCst);
                    return true;
                }
            }
        }

        // Retransmit renewal requests at retry interval
        self.check_retry_or_transition(elapsed_secs, DhcpState::Rebinding)
    }

    // --- check_timeout helper: handle Rebinding state ---
    pub(super) fn handle_rebinding_timeout(&self, elapsed_secs: u64) -> bool {
        // RFC 2131: Retransmit rebind requests with exponential backoff.
        // If retried too many times, give up and start over.
        let retry = self.retry_count.load(Ordering::SeqCst);

        // Exponential backoff: 4s * 2^retry, clamped at 64s (matching check_retry_or_transition)
        let base_interval = (4u64 << core::cmp::min(retry, 4)).min(64);

        // Add jitter ±1s
        let jitter = if retry > 0 {
            let rnd = crate::net::security::tls::crypto::random::generate_random()[0] as i64;
            (rnd % 3) - 1 // -1, 0, or 1
        } else {
            0
        };
        let interval = (base_interval as i64 + jitter).max(1) as u64;

        if elapsed_secs >= interval {
            let actual_retry = self.retry_count.fetch_add(1, Ordering::SeqCst);
            if actual_retry >= Self::MAX_RETRIES {
                // Give up
                self.transition_state(DhcpState::Init);
                self.retry_count.store(0, Ordering::SeqCst);
                // Clear leases
                self.clear_all_leases();
            }
            return true;
        }
        false
    }

    /// タイムアウトをチェック
    pub async fn check_timeout(&self, current_tick: u64, tick_rate: u64) -> bool {
        let state = match self.state.lock() {
            Ok(g) => *g,
            Err(_) => {
                log::error!("[NET] DHCP State lock poisoned (check_timeout) - treating as Init");
                DhcpState::Init
            }
        };
        let state_time = self.state_time.load(Ordering::SeqCst);
        let elapsed_secs = (current_tick.saturating_sub(state_time)) / tick_rate;

        match state {
            DhcpState::Selecting => {
                self.handle_selecting_timeout(current_tick, tick_rate, elapsed_secs)
                    .await
            }
            DhcpState::Requesting => self.check_retry_or_transition(elapsed_secs, DhcpState::Init),
            DhcpState::Bound => self.handle_bound_timeout(current_tick, tick_rate),
            DhcpState::Renewing => {
                self.handle_renewing_timeout(current_tick, tick_rate, elapsed_secs)
            }
            DhcpState::Rebinding => self.handle_rebinding_timeout(elapsed_secs),
            _ => false,
        }
    }
}
