use super::*;


impl UdpSocketTable {
    /// Create a new UDP socket table
    pub const fn new() -> Self {
        const NONE: Option<Arc<PoisonLock<UdpSocketInner>>> = None;
        UdpSocketTable {
            sockets: PoisonLock::new([NONE; MAX_UDP_SOCKETS]),
            stats: UdpStats {
                rx_datagrams: core::sync::atomic::AtomicU64::new(0),
                tx_datagrams: core::sync::atomic::AtomicU64::new(0),
                rx_dropped: core::sync::atomic::AtomicU64::new(0),
                checksum_errors: core::sync::atomic::AtomicU64::new(0),
            },
        }
    }

    // Legacy `bind(port)` wrapper removed. Use `bind_with_token(port, None)` instead.

    /// Bind a socket to a port and associate it with an optional capability token.
    /// If `token` is Some(id), this will attempt to increment the token's in-flight
    /// counter. On failure, bind will return None.
    pub fn bind_with_token(&self, port: u16, token: Option<u64>) -> Option<UdpSocket> {
        match self.sockets.lock() {
            Ok(mut sockets) => {
                // Find slot for this port
                let slot = (port as usize) % MAX_UDP_SOCKETS;

                // Check if already bound
                if sockets[slot].is_some() {
                    return None;
                }

                // If a token was provided, attempt to increment in-flight. If it fails,
                // abort bind.
                if let Some(t) = token {
                    if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                        return None;
                    }
                }

                let inner = Arc::new(PoisonLock::new(UdpSocketInner {
                    local_port: port,
                    rx_queue: VecDeque::new(),
                    rx_packet_queue: VecDeque::new(),
                    waker: None,
                    closed: false,
                    token,
                }));

                sockets[slot] = Some(inner.clone());

                Some(UdpSocket { inner })
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned during bind");
                // If we incremented in-flight above, roll back
                if let Some(t) = token {
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                None
            }
        }
    }

    /// Unbind a socket from a port and decrement any associated token in-flight counter
    pub fn unbind(&self, port: u16) {
        match self.sockets.lock() {
            Ok(mut sockets) => {
                let slot = (port as usize) % MAX_UDP_SOCKETS;
                if let Some(inner) = sockets[slot].take() {
                    match inner.lock() {
                        Ok(mut guard) => {
                            if let Some(t) = guard.token.take() {
                                let _ = crate::security::capability::manager().decrement_in_flight(t);
                            }
                        }
                        Err(_) => log::error!("[NET] UDP Socket poisoned during unbind - token cleanup skipped"),
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
                let slot = (port as usize) % MAX_UDP_SOCKETS;

                if let Some(ref inner) = sockets[slot] {
                    match inner.lock() {
                        Ok(socket) => {
                            if socket.local_port == port && !socket.closed {
                                return Some(inner.clone());
                            }
                        }
                        Err(_) => {
                            log::error!("[NET] UDP Socket poisoned during find");
                            return None;
                        }
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

    /// Deliver a datagram to the appropriate socket
    pub fn deliver(&self, datagram: UdpDatagram) -> bool {
        use core::sync::atomic::Ordering;

        if let Some(socket) = self.find(datagram.dst_port) {
            match socket.lock() {
                Ok(mut inner) => {
                    if inner.closed {
                        self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }

                    inner.rx_queue.push_back(datagram);

                    if let Some(waker) = inner.waker.take() {
                        waker.wake();
                    }

                    self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(_) => {
                    log::error!("[NET] UDP Socket poisoned during deliver - dropping datagram");
                    self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Deliver a packet to the appropriate socket using a PacketRef (zero-copy)
    pub fn deliver_packet(&self, src: UdpAddr, dst_port: u16, packet: PacketRef) -> bool {
        use core::sync::atomic::Ordering;

        if let Some(socket) = self.find(dst_port) {
            match socket.lock() {
                Ok(mut inner) => {
                    if inner.closed {
                        self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }

                    inner.rx_packet_queue.push_back((src, packet));

                    if let Some(waker) = inner.waker.take() {
                        waker.wake();
                    }

                    self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(_) => {
                    log::error!("[NET] UDP Socket poisoned during deliver_packet - dropping packet");
                    self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        use core::sync::atomic::Ordering;
        (
            self.stats.rx_datagrams.load(Ordering::Relaxed),
            self.stats.tx_datagrams.load(Ordering::Relaxed),
            self.stats.rx_dropped.load(Ordering::Relaxed),
            self.stats.checksum_errors.load(Ordering::Relaxed),
        )
    }

    /// List all bound UDP sockets (for netstat)
    pub fn list_sockets(&self) -> alloc::vec::Vec<UdpSocketSnapshot> {
        let mut result = alloc::vec::Vec::new();
        match self.sockets.lock() {
            Ok(sockets) => {
                for slot in sockets.iter() {
                    if let Some(inner) = slot {
                        match inner.lock() {
                            Ok(socket) => {
                                if !socket.closed {
                                    result.push(UdpSocketSnapshot {
                                        local_port: socket.local_port,
                                        rx_queue_len: socket.rx_queue.len() + socket.rx_packet_queue.len(),
                                    });
                                }
                            }
                            Err(_) => {
                                // Skip poisoned sockets
                            }
                        }
                    }
                }
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned during list_sockets");
            }
        }
        result
    }

    /// Get number of bound sockets
    pub fn socket_count(&self) -> usize {
        match self.sockets.lock() {
            Ok(sockets) => sockets.iter().filter(|s| s.is_some()).count(),
            Err(_) => 0,
        }
    }
}
