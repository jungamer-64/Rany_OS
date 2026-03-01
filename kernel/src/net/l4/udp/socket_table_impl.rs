use super::*;
use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;

impl UdpSocketTable {
    /// Create a new UDP socket table
    pub const fn new() -> Self {
        UdpSocketTable {
            sockets: PoisonLock::new(BTreeMap::new()),
            stats: UdpStats {
                rx_datagrams: core::sync::atomic::AtomicU64::new(0),
                tx_datagrams: core::sync::atomic::AtomicU64::new(0),
                rx_dropped: core::sync::atomic::AtomicU64::new(0),
                checksum_errors: core::sync::atomic::AtomicU64::new(0),
            },
        }
    }

    /// 1024..65535 の範囲からランダムな未使用ポートを選択する
    fn find_available_port(&self, sockets: &BTreeMap<u16, Arc<PoisonLock<UdpSocketInner>>>) -> Option<u16> {
        // 暗号論的に安全な乱数から開始ポートを決定 (Source Port Randomization)
        let random_bytes = crate::net::security::tls::generate_random();
        let seed = u16::from_le_bytes([random_bytes[0], random_bytes[1]]);
        
        // エフェメラルポート範囲 (RFC 6056 / IANA)
        const EPHEMERAL_START: u16 = 49152;
        const EPHEMERAL_END: u16 = 65535;
        const RANGE_SIZE: u16 = EPHEMERAL_END - EPHEMERAL_START + 1;

        let start_port = EPHEMERAL_START + (seed % RANGE_SIZE);
        
        for i in 0..RANGE_SIZE {
            let port = EPHEMERAL_START + ((start_port - EPHEMERAL_START + i) % RANGE_SIZE);
            if !sockets.contains_key(&port) {
                return Some(port);
            }
        }
        None
    }

    /// Bind a socket to a port and associate it with an optional capability token.
    /// If `port` is 0, an available ephemeral port will be automatically assigned.
    pub fn bind_with_token(&self, mut port: u16, token: Option<u64>) -> Option<UdpSocket> {
        match self.sockets.lock() {
            Ok(mut sockets) => {
                // Check table size limit
                if sockets.len() >= MAX_UDP_SOCKETS {
                    log::warn!("[NET] UDP: Socket table full");
                    return None;
                }

                // Autobind if port is 0
                if port == 0 {
                    if let Some(p) = self.find_available_port(&sockets) {
                        port = p;
                    } else {
                        return None;
                    }
                } else {
                    // Security: Check for privileged ports (< 1024)
                    if port < 1024 {
                        let caller = crate::task::context::current_subject().domain.as_u64();
                        let mut permitted = false;

                        if let Some(t) = token {
                            // If a token is provided, it MUST grant CAP_NET_BIND for privileged ports
                            if crate::security::capability::manager().validate_token(caller, t, crate::security::capability::CAP_NET_BIND) {
                                permitted = true;
                            }
                        } else {
                            // If no token, check if the domain has the capability ambiently
                            if crate::security::capability::manager().has_capability(caller, crate::security::capability::CAP_NET_BIND) {
                                permitted = true;
                            }
                        }

                        if !permitted {
                            log::warn!("[NET] UDP: Permission denied for privileged port {}", port);
                            return None;
                        }
                    }

                    if sockets.contains_key(&port) {
                        return None; // Port in use
                    }
                }

                // If a token was provided, attempt to increment in-flight.
                if let Some(t) = token {
                    // Note: We already validated the token if port < 1024.
                    // For non-privileged ports, any valid network token is accepted for now.
                    if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                        return None;
                    }
                }

                let inner = Arc::new(PoisonLock::new(UdpSocketInner {
                    local_port: port,
                    rx_packet_queue: VecDeque::with_capacity(64),
                    rx_queue_bytes: 0,
                    wakers: Vec::new(),
                    closed: false,
                    token,
                }));

                sockets.insert(port, inner.clone());
                Some(UdpSocket { inner })
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned during bind");
                if let Some(t) = token {
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                None
            }
        }
    }

    /// Unbind a socket from a port
    pub fn unbind(&self, port: u16) {
        match self.sockets.lock() {
            Ok(mut sockets) => {
                if let Some(inner) = sockets.remove(&port) {
                    match inner.lock() {
                        Ok(mut guard) => {
                            if let Some(t) = guard.token.take() {
                                let _ = crate::security::capability::manager().decrement_in_flight(t);
                            }
                        }
                        Err(_) => log::error!("[NET] UDP Socket poisoned during unbind"),
                    }
                }
            }
            Err(_) => log::error!("[NET] UDP Table poisoned during unbind"),
        }
    }

    /// Find a socket by port
    pub(crate) fn find(&self, port: u16) -> Option<Arc<PoisonLock<UdpSocketInner>>> {
        match self.sockets.lock() {
            Ok(sockets) => {
                if let Some(inner) = sockets.get(&port) {
                    match inner.lock() {
                        Ok(socket) => {
                            if !socket.closed {
                                return Some(inner.clone());
                            }
                        }
                        Err(_) => log::error!("[NET] UDP Socket poisoned during find"),
                    }
                }
                None
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned (find)");
                None
            }
        }
    }

    /// Deliver a packet to the appropriate socket
    pub fn deliver(&self, src: UdpAddr, dst_port: u16, packet: PacketRef) -> bool {
        if let Some(socket) = self.find(dst_port) {
            match socket.lock() {
                Ok(mut inner) => {
                    if inner.closed {
                        self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }

                    let packet_len = packet.len();
                    if inner.rx_packet_queue.len() < 64 && inner.rx_queue_bytes + packet_len <= MAX_UDP_RX_QUEUE_BYTES {
                        inner.rx_queue_bytes += packet_len;
                        inner.rx_packet_queue.push_back((src, packet));
                        for waker in inner.wakers.drain(..) {
                            waker.wake();
                        }
                        self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
                        true
                    } else {
                        self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                }
                Err(_) => {
                    self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// List all bound UDP sockets
    pub fn list_sockets(&self) -> alloc::vec::Vec<UdpSocketSnapshot> {
        let mut result = alloc::vec::Vec::new();
        match self.sockets.lock() {
            Ok(sockets) => {
                for (port, inner) in sockets.iter() {
                    match inner.lock() {
                        Ok(socket) => {
                            if !socket.closed {
                                result.push(UdpSocketSnapshot {
                                    local_port: *port,
                                    rx_queue_len: socket.rx_packet_queue.len(),
                                });
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => log::error!("[NET] UDP Table poisoned (list_sockets)"),
        }
        result
    }

    /// Get number of bound sockets
    pub fn socket_count(&self) -> usize {
        match self.sockets.lock() {
            Ok(sockets) => sockets.len(),
            Err(_) => 0,
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.rx_datagrams.load(Ordering::Relaxed),
            self.stats.tx_datagrams.load(Ordering::Relaxed),
            self.stats.rx_dropped.load(Ordering::Relaxed),
            self.stats.checksum_errors.load(Ordering::Relaxed),
        )
    }
}
