use super::*;


/// Global network stack instance
pub(crate) static NETWORK_STACK: PoisonLock<Option<NetworkStack>> = PoisonLock::new(None);

/// Initialize the global network stack
pub fn init(config: NetworkConfig) {
    // Initialization-time best-effort recovery: use helper
    let mut stack = NETWORK_STACK.lock_for_init("[NET] Global Stack init");
    *stack = Some(NetworkStack::new(config));
}

/// Initialize with default configuration
pub fn init_default() {
    init(NetworkConfig::default());
}

/// Get the global network stack
pub fn stack() -> &'static PoisonLock<Option<NetworkStack>> {
    &NETWORK_STACK
}

/// Returns true when the global network stack has been initialized.
pub fn is_initialized() -> bool {
    match NETWORK_STACK.lock() {
        Ok(guard) => guard.is_some(),
        Err(_) => false,
    }
}

/// Process a received packet
pub fn receive(data: &[u8]) {
    use crate::net::datapath::mempool::alloc_packet;

    // Allocate PacketRef to bridge legacy driver to Zero-Copy stack
    if let Some(mut packet) = alloc_packet() {
        // Copy data (Bridge)
        let len = data.len().min(packet.capacity());
        packet.data_mut()[..len].copy_from_slice(&data[..len]);
        packet.set_len(len);

        match NETWORK_STACK.lock() {
            Ok(mut guard) => {
                if let Some(ref mut stack) = *guard {
                    stack.receive(packet);
                }
            }
            Err(_) => {
                log::error!("[NET] Global Stack poisoned - dropping packet");
            }
        }
    } else {
        // Drop packet due to OOM
        // Ideally record stats
    }
}

/// Process a batch of received packets
pub fn receive_batch(batch: PacketBatch) {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.receive_batch(batch);
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - dropping batch");
            // batch is dropped here, packets returned to pool
        }
    }
}

/// Send a UDP datagram

pub fn send_udp(src_port: u16, dst_ip: Ipv4Address, dst_port: u16, data: &[u8]) -> bool {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.send_udp_raw(src_port, dst_ip, dst_port, data)
            } else {
                false
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - send_udp failed");
            false
        }
    }
}

/// Like `send_udp` but routes the datagram on a specific logical interface.
/// The interface argument is currently ignored but provided as an extension
/// point for future multi‑NIC behaviour.
pub fn send_udp_on(if_id: super::NetIfId, src_port: u16, dst_ip: Ipv4Address, dst_port: u16, data: &[u8]) -> bool {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.send_udp_raw_on(if_id, src_port, dst_ip, dst_port, data)
            } else {
                false
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - send_udp_on failed");
            false
        }
    }
}

/// Send a UDP datagram over IPv6
pub fn send_udp_v6(src_port: u16, src_ip: crate::net::l3::ipv6::Ipv6Address, dst_ip: crate::net::l3::ipv6::Ipv6Address, dst_port: u16, data: &[u8]) -> bool {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.send_udp_v6_raw(src_port, src_ip, dst_ip, dst_port, data)
            } else {
                false
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - send_udp_v6 failed");
            false
        }
    }
}

/// IPv6 variant that allows specifying an interface (currently ignored)
pub fn send_udp_v6_on(
    if_id: super::NetIfId,
    src_port: u16,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
) -> bool {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.send_udp_v6_raw_on(if_id, src_port, src_ip, dst_ip, dst_port, data)
            } else {
                false
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - send_udp_v6_on failed");
            false
        }
    }
}

/// Send a TCP segment (IPv4)
pub fn send_tcp(src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_segment: &[u8]) -> bool {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.send_tcp(src_ip, dst_ip, tcp_segment)
            } else {
                false
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - send_tcp failed");
            false
        }
    }
}

/// TCP send helper that specifies an output interface (currently ignored)
pub fn send_tcp_on(_if_id: super::NetIfId, src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_segment: &[u8]) -> bool {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                // interface not yet used
                stack.send_tcp(src_ip, dst_ip, tcp_segment)
            } else {
                false
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - send_tcp_on failed");
            false
        }
    }
}

/// Send a TCP segment over IPv6
pub fn send_tcp_v6(src_ip: crate::net::l3::ipv6::Ipv6Address, dst_ip: crate::net::l3::ipv6::Ipv6Address, tcp_segment: &[u8]) -> bool {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.send_tcp_v6_raw(src_ip, dst_ip, tcp_segment)
            } else {
                false
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - send_tcp_v6 failed");
            false
        }
    }
}

/// Bind a UDP socket
pub fn bind_udp(port: u16) -> Option<UdpSocket> {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => guard.as_mut().and_then(|s| s.bind_udp(port)),
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - bind_udp failed");
            None
        }
    }
}

/// Process retransmission timeouts on the global network stack
pub fn process_timeouts(_current_time: u64) {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.process_timeouts();
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - process_timeouts failed");
        }
    }
}

/// Bind a UDP socket and associate it with an optional capability token
pub fn bind_udp_with_token(port: u16, token: Option<u64>) -> Option<UdpSocket> {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => guard.as_mut().and_then(|s| s.bind_udp_with_token(port, token)),
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - bind_udp_with_token failed");
            None
        }
    }
}

/// Apply IPv6 global address obtained via DHCPv6
pub fn apply_ipv6_global_address(addr: crate::net::l3::ipv6::Ipv6Address) {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut stack) = *guard {
                stack.apply_ipv6_global_address(addr);
            }
        }
        Err(_) => log::error!("[NET] Global Stack poisoned - apply_ipv6_global_address failed"),
    }
}
/// Unbind a UDP socket
pub fn unbind_udp(port: u16) {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.unbind_udp(port);
            }
        }
        Err(_) => log::error!("[NET] Global Stack poisoned - unbind_udp failed"),
    }
}

/// Unbind a TCP connection
pub fn unbind_tcp(local: TcpSocketAddr, remote: TcpSocketAddr) {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.unbind_tcp(local, remote);
            }
        }
        Err(_) => log::error!("[NET] Global Stack poisoned - unbind_tcp failed"),
    }
}

/// Unbind a TCP listener
pub fn unbind_tcp_listener(local: TcpSocketAddr) {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.unbind_tcp_listener(local);
            }
        }
        Err(_) => log::error!("[NET] Global Stack poisoned - unbind_tcp_listener failed"),
    }
}

/// Bind a TCP listener
pub fn bind_tcp(addr: TcpSocketAddr) -> Result<TcpListener, TcpError> {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.bind_tcp(addr)
            } else {
                Err(TcpError::InvalidState)
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - bind_tcp failed");
            Err(TcpError::InvalidState)
        }
    }
}

/// Bind a TCP listener with a capability token
pub fn bind_tcp_with_token(addr: TcpSocketAddr, token: Option<u64>) -> Result<TcpListener, TcpError> {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.bind_tcp_with_token(addr, token)
            } else {
                Err(TcpError::InvalidState)
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - bind_tcp_with_token failed");
            Err(TcpError::InvalidState)
        }
    }
}

/// Connect to a remote TCP address
pub fn connect_tcp(local_addr: TcpSocketAddr, remote_addr: TcpSocketAddr) -> Result<TcpStream, TcpError> {
     match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.connect_tcp(local_addr, remote_addr)
            } else {
                Err(TcpError::InvalidState)
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - connect_tcp failed");
            Err(TcpError::InvalidState)
        }
    }
}

// ============================================================================
// Multicast Group Management (Global API)
// ============================================================================

/// Join a multicast group
/// 
/// # Example
/// ```no_run
/// use crate::net::runtime::stack::join_multicast_group;
/// use crate::net::l3::ipv4::Ipv4Address;
/// 
/// let group = Ipv4Address::new([224, 0, 0, 251]); // mDNS group
/// join_multicast_group(group).expect("Failed to join multicast group");
/// ```
pub fn join_multicast_group(group: Ipv4Address) -> Result<(), IgmpError> {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.join_multicast_group(group)
            } else {
                Err(IgmpError::InvalidGroupAddress)
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - join_multicast_group failed");
            Err(IgmpError::InvalidGroupAddress)
        }
    }
}

/// Leave a multicast group
pub fn leave_multicast_group(group: Ipv4Address) -> Result<(), IgmpError> {
    match NETWORK_STACK.lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.leave_multicast_group(group)
            } else {
                Err(IgmpError::NotMember)
            }
        }
        Err(_) => {
            log::error!("[NET] Global Stack poisoned - leave_multicast_group failed");
            Err(IgmpError::NotMember)
        }
    }
}

/// Check if this host is a member of a multicast group
pub fn is_multicast_member(group: Ipv4Address) -> bool {
    match NETWORK_STACK.lock() {
        Ok(guard) => {
            if let Some(ref s) = *guard {
                s.is_multicast_member(group)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

