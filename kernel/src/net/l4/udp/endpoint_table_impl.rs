use super::*;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use core::sync::atomic::Ordering;

fn family_from_addr(addr: UdpAddr) -> UdpAddressFamily {
    match addr {
        UdpAddr::V4 { .. } => UdpAddressFamily::Ipv4,
        UdpAddr::V6 { .. } => UdpAddressFamily::Ipv6,
    }
}

fn scopes_conflict(lhs: InterfaceScope, rhs: InterfaceScope) -> bool {
    match (lhs, rhs) {
        (InterfaceScope::Any, _) | (_, InterfaceScope::Any) => true,
        (InterfaceScope::Pinned(a), InterfaceScope::Pinned(b)) => a == b,
    }
}

fn key_matches_ingress(key: &UdpBindingKey, if_id: NetIfId) -> bool {
    match key.scope {
        InterfaceScope::Any => true,
        InterfaceScope::Pinned(bound_if) => bound_if == if_id,
    }
}

impl UdpEndpointTable {
    /// Create a new UDP socket table
    pub const fn new() -> Self {
        UdpEndpointTable {
            endpoints: PoisonLock::new(BTreeMap::new()),
            stats: UdpStats {
                rx_datagrams: core::sync::atomic::AtomicU64::new(0),
                tx_datagrams: core::sync::atomic::AtomicU64::new(0),
                rx_dropped: core::sync::atomic::AtomicU64::new(0),
                checksum_errors: core::sync::atomic::AtomicU64::new(0),
            },
        }
    }

    /// 1024..65535 の範囲からランダムな未使用ポートを選択する
    fn find_available_port(
        &self,
        sockets: &BTreeMap<UdpBindingKey, Arc<PoisonLock<UdpEndpointInner>>>,
        family: UdpAddressFamily,
        scope: InterfaceScope,
    ) -> Option<u16> {
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
            let conflict = sockets.keys().any(|key| {
                key.family == family && key.port == port && scopes_conflict(key.scope, scope)
            });
            if !conflict {
                return Some(port);
            }
        }
        None
    }

    /// Bind a socket to a port and associate it with an optional capability token.
    /// If `port` is 0, an available ephemeral port will be automatically assigned.
    pub(crate) fn bind_with_token(
        &self,
        scope: InterfaceScope,
        family: UdpAddressFamily,
        mut port: u16,
        token: Option<u64>,
    ) -> Option<UdpEndpoint> {
        match self.endpoints.lock() {
            Ok(mut sockets) => {
                // Check table size limit
                if sockets.len() >= MAX_UDP_ENDPOINTS {
                    log::warn!("[NET] UDP: Endpoint table full");
                    return None;
                }

                // Autobind if port is 0
                if port == 0 {
                    if let Some(p) = self.find_available_port(&sockets, family, scope) {
                        port = p;
                    } else {
                        return None;
                    }
                } else {
                    // Security: Check for privileged ports (< 1024)
                    if port < 1024 {
                        let subject = crate::task::context::current_subject();
                        let caller = subject.domain.as_u64();
                        // Kernel domain always has full privilege
                        let mut permitted =
                            subject.domain == crate::domain_system::DomainId::KERNEL;

                        if !permitted {
                            if let Some(t) = token {
                                // If a token is provided, it MUST grant CAP_NET_BIND for privileged ports
                                if crate::security::capability::manager().validate_token(
                                    caller,
                                    t,
                                    crate::security::capability::CAP_NET_BIND,
                                ) {
                                    permitted = true;
                                }
                            } else {
                                // If no token, check if the domain has the capability ambiently
                                if crate::security::capability::manager().has_capability(
                                    caller,
                                    crate::security::capability::CAP_NET_BIND,
                                ) {
                                    permitted = true;
                                }
                            }
                        }

                        if !permitted {
                            log::warn!("[NET] UDP: Permission denied for privileged port {}", port);
                            return None;
                        }
                    }

                    if sockets.keys().any(|key| {
                        key.family == family
                            && key.port == port
                            && scopes_conflict(key.scope, scope)
                    }) {
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

                let inner = Arc::new(PoisonLock::new(UdpEndpointInner {
                    local_port: port,
                    scope,
                    last_ingress_if_id: None,
                    rx_packet_queue: VecDeque::with_capacity(64),
                    rx_queue_bytes: 0,
                    wakers: Vec::new(),
                    closed: false,
                    ttl: 64,
                    token,
                }));

                sockets.insert(
                    UdpBindingKey {
                        family,
                        port,
                        scope,
                    },
                    inner.clone(),
                );
                Some(UdpEndpoint { inner })
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

    /// Bind a dual-stack UDP endpoint so a single socket can receive both IPv4 and IPv6.
    pub(crate) fn bind_dual_stack_with_token(
        &self,
        scope: InterfaceScope,
        mut port: u16,
        token: Option<u64>,
    ) -> Option<UdpEndpoint> {
        match self.endpoints.lock() {
            Ok(mut sockets) => {
                if sockets.len().saturating_add(2) > MAX_UDP_ENDPOINTS {
                    log::warn!("[NET] UDP: Endpoint table full");
                    return None;
                }

                if port == 0 {
                    port = self.find_available_port(&sockets, UdpAddressFamily::Ipv4, scope)?;
                    let ipv6_conflict = sockets.keys().any(|key| {
                        key.family == UdpAddressFamily::Ipv6
                            && key.port == port
                            && scopes_conflict(key.scope, scope)
                    });
                    if ipv6_conflict {
                        port = self.find_available_port(&sockets, UdpAddressFamily::Ipv6, scope)?;
                        let ipv4_conflict = sockets.keys().any(|key| {
                            key.family == UdpAddressFamily::Ipv4
                                && key.port == port
                                && scopes_conflict(key.scope, scope)
                        });
                        if ipv4_conflict {
                            return None;
                        }
                    }
                } else {
                    if port < 1024 {
                        let subject = crate::task::context::current_subject();
                        let caller = subject.domain.as_u64();
                        let mut permitted =
                            subject.domain == crate::domain_system::DomainId::KERNEL;

                        if !permitted {
                            if let Some(t) = token {
                                if crate::security::capability::manager().validate_token(
                                    caller,
                                    t,
                                    crate::security::capability::CAP_NET_BIND,
                                ) {
                                    permitted = true;
                                }
                            } else if crate::security::capability::manager()
                                .has_capability(caller, crate::security::capability::CAP_NET_BIND)
                            {
                                permitted = true;
                            }
                        }

                        if !permitted {
                            log::warn!("[NET] UDP: Permission denied for privileged port {}", port);
                            return None;
                        }
                    }

                    let conflict = sockets.keys().any(|key| {
                        (key.family == UdpAddressFamily::Ipv4
                            || key.family == UdpAddressFamily::Ipv6)
                            && key.port == port
                            && scopes_conflict(key.scope, scope)
                    });
                    if conflict {
                        return None;
                    }
                }

                if let Some(t) = token {
                    if crate::security::capability::manager()
                        .increment_in_flight(t)
                        .is_err()
                    {
                        return None;
                    }
                }

                let inner = Arc::new(PoisonLock::new(UdpEndpointInner {
                    local_port: port,
                    scope,
                    last_ingress_if_id: None,
                    rx_packet_queue: VecDeque::with_capacity(64),
                    rx_queue_bytes: 0,
                    wakers: Vec::new(),
                    closed: false,
                    ttl: 64,
                    token,
                }));

                sockets.insert(
                    UdpBindingKey {
                        family: UdpAddressFamily::Ipv4,
                        port,
                        scope,
                    },
                    inner.clone(),
                );
                sockets.insert(
                    UdpBindingKey {
                        family: UdpAddressFamily::Ipv6,
                        port,
                        scope,
                    },
                    inner.clone(),
                );
                Some(UdpEndpoint { inner })
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned during dual-stack bind");
                if let Some(t) = token {
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                None
            }
        }
    }

    /// Unbind a socket from a port
    pub fn unbind(&self, scope: InterfaceScope, port: u16) {
        match self.endpoints.lock() {
            Ok(mut sockets) => {
                let keys: alloc::vec::Vec<_> = sockets
                    .keys()
                    .copied()
                    .filter(|key| key.port == port && key.scope == scope)
                    .collect();
                let mut removed_inner = None;
                for key in keys {
                    let Some(inner) = sockets.remove(&key) else {
                        continue;
                    };
                    if removed_inner.is_none() {
                        removed_inner = Some(inner);
                    }
                }
                if let Some(inner) = removed_inner {
                    match inner.lock() {
                        Ok(mut guard) => {
                            if let Some(t) = guard.token.take() {
                                let _ =
                                    crate::security::capability::manager().decrement_in_flight(t);
                            }
                        }
                        Err(_) => log::error!("[NET] UDP Endpoint poisoned during unbind"),
                    }
                }
            }
            Err(_) => log::error!("[NET] UDP Table poisoned during unbind"),
        }
    }

    /// Find a socket by port
    pub(crate) fn find(
        &self,
        family: UdpAddressFamily,
        port: u16,
        if_id: NetIfId,
    ) -> Option<Arc<PoisonLock<UdpEndpointInner>>> {
        match self.endpoints.lock() {
            Ok(sockets) => {
                let mut wildcard = None;
                for (key, inner) in sockets.iter() {
                    if key.family != family || key.port != port || !key_matches_ingress(key, if_id)
                    {
                        continue;
                    }
                    match inner.lock() {
                        Ok(socket) => {
                            if socket.closed {
                                continue;
                            }
                            if matches!(key.scope, InterfaceScope::Pinned(_)) {
                                return Some(inner.clone());
                            }
                            wildcard = Some(inner.clone());
                        }
                        Err(_) => log::error!("[NET] UDP Endpoint poisoned during find"),
                    }
                }
                wildcard
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned (find)");
                None
            }
        }
    }

    /// Deliver a packet to the appropriate socket
    pub fn deliver(
        &self,
        if_id: NetIfId,
        src: UdpAddr,
        dst_port: u16,
        ttl: u8,
        packet: PacketRef,
    ) -> bool {
        if let Some(inner) = self.find(family_from_addr(src), dst_port, if_id) {
            let socket = crate::net::l4::udp::UdpEndpoint { inner };
            socket.deliver(if_id, src, ttl, packet);
            self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// List all bound UDP sockets
    pub fn list_endpoints(&self) -> alloc::vec::Vec<UdpEndpointSnapshot> {
        let mut result = alloc::vec::Vec::new();
        match self.endpoints.lock() {
            Ok(sockets) => {
                let mut seen = BTreeSet::new();
                for inner in sockets.values() {
                    match inner.lock() {
                        Ok(socket) => {
                            let key = (socket.local_port, socket.scope);
                            if !socket.closed && seen.insert(key) {
                                result.push(UdpEndpointSnapshot {
                                    local_port: socket.local_port,
                                    rx_queue_len: socket.rx_packet_queue.len(),
                                });
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => log::error!("[NET] UDP Table poisoned (list_endpoints)"),
        }
        result
    }

    /// Get number of bound sockets
    pub fn endpoint_count(&self) -> usize {
        match self.endpoints.lock() {
            Ok(sockets) => {
                let mut seen = BTreeSet::new();
                for inner in sockets.values() {
                    if let Ok(socket) = inner.lock() {
                        seen.insert((socket.local_port, socket.scope));
                    }
                }
                seen.len()
            }
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
