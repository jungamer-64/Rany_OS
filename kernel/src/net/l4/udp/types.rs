// ============================================================================
// kernel/src/net/l4/udp/types.rs - L4 / UDP / 型定義
// ============================================================================

use super::*;
use crate::net::l4::socket::{SocketFamily, find_udp_by_port_in};
use crate::net::runtime::NetRuntimeHandle;

fn resolve_ingress_if_id_in(runtime: NetRuntimeHandle, if_id: Option<NetIfId>) -> Option<NetIfId> {
    if let Some(if_id) = if_id {
        return Some(if_id);
    }
    crate::net::runtime::device::primary_if_in(runtime).or_else(|| {
        crate::net::runtime::manager::list_interfaces_in(runtime)
            .ok()
            .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
    })
}

/// UDP processor for handling UDP packets

pub struct UdpProcessor {
    /// Codec / validation statistics
    stats: UdpStats,
}

/// Result of UDP processing
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UdpResult {
    /// Delivered to socket
    Delivered,
    /// No ingress interface exists for this packet
    NoIngressInterface,
    /// No socket for this port
    NoEndpoint,
    /// Checksum error
    ChecksumError,
    /// Invalid packet
    Invalid,
}

impl UdpProcessor {
    /// Create a new UDP processor
    pub fn new() -> Self {
        UdpProcessor {
            stats: UdpStats::default(),
        }
    }

    pub fn stats(&self) -> (u64, u64, u64, u64) {
        self.stats.snapshot()
    }

    fn deliver_payload(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        src: crate::net::l4::EndpointAddr,
        dst_port: u16,
        ttl: u8,
        payload: PacketPayload,
    ) -> bool {
        let family = if src.is_ipv6() {
            SocketFamily::Ipv6
        } else {
            SocketFamily::Ipv4
        };

        let Some(endpoint) = find_udp_by_port_in(runtime, family, dst_port, Some(if_id)) else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        };

        if endpoint
            .deliver_udp_payload(if_id, src, ttl, payload)
            .is_ok()
        {
            self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn lookup_socket(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        family: SocketFamily,
        dst_port: u16,
    ) -> Option<Socket> {
        let endpoint = find_udp_by_port_in(runtime, family, dst_port, Some(if_id));
        if endpoint.is_none() {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
        }
        endpoint
    }

    fn payload_span_checksum(span: crate::net::payload::PayloadSpanRef<'_>, initial: u32) -> u16 {
        let mut sum = initial;
        let mut trailing = None;

        span.for_each_chunk(|chunk| {
            let mut index = 0usize;
            if let Some(prev) = trailing.take() {
                if let Some((&first, rest)) = chunk.split_first() {
                    sum = sum.saturating_add(u16::from_be_bytes([prev, first]) as u32);
                    index = 1;
                    if rest.is_empty() {
                        return;
                    }
                } else {
                    trailing = Some(prev);
                    return;
                }
            }

            while index + 1 < chunk.len() {
                sum =
                    sum.saturating_add(u16::from_be_bytes([chunk[index], chunk[index + 1]]) as u32);
                index += 2;
            }
            if index < chunk.len() {
                trailing = Some(chunk[index]);
            }
        });

        if let Some(last) = trailing {
            sum = sum.saturating_add(u16::from_be_bytes([last, 0]) as u32);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    pub fn process_window_on(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        packet: OwnedPayloadWindow,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        let Some(resolved_if_id) = resolve_ingress_if_id_in(runtime, if_id) else {
            return Err((
                UdpResult::NoIngressInterface,
                packet.into_original_payload(),
            ));
        };
        self.process_window_impl(runtime, resolved_if_id, packet, src_ip, dst_ip, ttl)
    }

    fn process_window_impl(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        packet: OwnedPayloadWindow,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        use core::sync::atomic::Ordering;

        let Some(segment) = packet.span() else {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        };
        let Some(header) = segment.read_array::<8>(0) else {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=segment.total_len()).contains(&length)
            || length != segment.total_len()
        {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum != 0 {
            let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, length as u16);
            let Some(checksum_span) = segment.subspan(0, length) else {
                return Err((UdpResult::Invalid, packet.into_original_payload()));
            };
            if Self::payload_span_checksum(checksum_span, pseudo) != 0 {
                self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
                return Err((UdpResult::ChecksumError, packet.into_original_payload()));
            }
        }

        let src = crate::net::l4::EndpointAddr::new(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let family = SocketFamily::Ipv4;
        let Some(endpoint) = self.lookup_socket(runtime, if_id, family, dst_port) else {
            return Err((UdpResult::NoEndpoint, packet.into_original_payload()));
        };

        let Ok(udp_segment) = packet.into_payload() else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::Invalid, PacketPayload::default()));
        };
        let Some(window) = VerifiedPayloadWindow::for_payload(
            &udp_segment,
            UdpHeader::SIZE,
            length - UdpHeader::SIZE,
        ) else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::Invalid, PacketPayload::default()));
        };
        let Ok(udp_payload) = window.move_from(udp_segment) else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::Invalid, PacketPayload::default()));
        };

        if endpoint
            .deliver_udp_payload(if_id, src, ttl, udp_payload)
            .is_ok()
        {
            self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            Err((UdpResult::Invalid, PacketPayload::default()))
        }
    }

    pub fn process_window_v6_on(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        packet: OwnedPayloadWindow,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        let Some(resolved_if_id) = resolve_ingress_if_id_in(runtime, if_id) else {
            return Err((
                UdpResult::NoIngressInterface,
                packet.into_original_payload(),
            ));
        };
        self.process_window_v6_impl(runtime, resolved_if_id, packet, src_ip, dst_ip, ttl)
    }

    fn process_window_v6_impl(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        packet: OwnedPayloadWindow,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        use core::sync::atomic::Ordering;

        let Some(segment) = packet.span() else {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        };
        let Some(header) = segment.read_array::<8>(0) else {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=segment.total_len()).contains(&length)
            || length != segment.total_len()
        {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum == 0 {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::ChecksumError, packet.into_original_payload()));
        }

        let pseudo = ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Udp, length as u32);
        let Some(checksum_span) = segment.subspan(0, length) else {
            return Err((UdpResult::Invalid, packet.into_original_payload()));
        };
        if Self::payload_span_checksum(checksum_span, pseudo) != 0 {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::ChecksumError, packet.into_original_payload()));
        }

        let src = crate::net::l4::EndpointAddr::new_v6(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let family = SocketFamily::Ipv6;
        let Some(endpoint) = self.lookup_socket(runtime, if_id, family, dst_port) else {
            return Err((UdpResult::NoEndpoint, packet.into_original_payload()));
        };

        let Ok(udp_segment) = packet.into_payload() else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::Invalid, PacketPayload::default()));
        };
        let Some(window) = VerifiedPayloadWindow::for_payload(
            &udp_segment,
            UdpHeader::SIZE,
            length - UdpHeader::SIZE,
        ) else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::Invalid, PacketPayload::default()));
        };
        let Ok(udp_payload) = window.move_from(udp_segment) else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::Invalid, PacketPayload::default()));
        };

        if endpoint
            .deliver_udp_payload(if_id, src, ttl, udp_payload)
            .is_ok()
        {
            self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            Err((UdpResult::Invalid, PacketPayload::default()))
        }
    }

    /// Process an incoming UDP payload that may be backed by a packet chain (zero-copy, IPv4).
    pub fn process_payload_on(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        payload: PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        let Some(resolved_if_id) = resolve_ingress_if_id_in(runtime, if_id) else {
            return UdpResult::NoIngressInterface;
        };
        self.process_payload_impl(runtime, resolved_if_id, payload, src_ip, dst_ip, ttl)
    }

    fn process_payload_impl(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        payload: PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        use core::sync::atomic::Ordering;

        let view = PacketPayloadView::new(&payload);
        let Some(header) = view.read_array::<8>(0) else {
            return UdpResult::Invalid;
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=view.total_len()).contains(&length) || length != view.total_len() {
            return UdpResult::Invalid;
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum != 0 {
            let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, length as u16);
            if payload_checksum(&view, pseudo) != 0 {
                self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
                return UdpResult::ChecksumError;
            }
        }

        let Some(window) =
            VerifiedPayloadWindow::for_payload(&payload, UdpHeader::SIZE, length - UdpHeader::SIZE)
        else {
            return UdpResult::Invalid;
        };
        let Ok(udp_payload) = window.move_from(payload) else {
            return UdpResult::Invalid;
        };
        let src = crate::net::l4::EndpointAddr::new(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);

        if self.deliver_payload(runtime, if_id, src, dst_port, ttl, udp_payload) {
            UdpResult::Delivered
        } else {
            UdpResult::NoEndpoint
        }
    }

    /// Process an incoming UDP payload that may be backed by a packet chain (zero-copy, IPv6).
    pub fn process_payload_v6_on(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        payload: PacketPayload,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> UdpResult {
        let Some(resolved_if_id) = resolve_ingress_if_id_in(runtime, if_id) else {
            return UdpResult::NoIngressInterface;
        };
        self.process_payload_v6_impl(runtime, resolved_if_id, payload, src_ip, dst_ip, ttl)
    }

    fn process_payload_v6_impl(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        payload: PacketPayload,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> UdpResult {
        use core::sync::atomic::Ordering;

        let view = PacketPayloadView::new(&payload);
        let Some(header) = view.read_array::<8>(0) else {
            return UdpResult::Invalid;
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=view.total_len()).contains(&length) || length != view.total_len() {
            return UdpResult::Invalid;
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum == 0 {
            return UdpResult::ChecksumError;
        }

        let pseudo = ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Udp, length as u32);
        if payload_checksum(&view, pseudo) != 0 {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let Some(window) =
            VerifiedPayloadWindow::for_payload(&payload, UdpHeader::SIZE, length - UdpHeader::SIZE)
        else {
            return UdpResult::Invalid;
        };
        let Ok(udp_payload) = window.move_from(payload) else {
            return UdpResult::Invalid;
        };
        let src = crate::net::l4::EndpointAddr::new_v6(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);

        if self.deliver_payload(runtime, if_id, src, dst_port, ttl, udp_payload) {
            UdpResult::Delivered
        } else {
            UdpResult::NoEndpoint
        }
    }
}

impl Default for UdpProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::runtime::create_runtime;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn process_without_ingress_interface_reports_missing_interface() {
        let runtime = create_runtime().expect("test runtime allocation");
        let processor = UdpProcessor::new();

        assert_eq!(
            processor.process_payload_on(
                runtime,
                None,
                PacketPayload::default(),
                Ipv4Address::ANY,
                Ipv4Address::ANY,
                64,
            ),
            UdpResult::NoIngressInterface
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn process_window_without_ingress_interface_reports_missing_interface() {
        let runtime = create_runtime().expect("test runtime allocation");
        let processor = UdpProcessor::new();
        let packet = OwnedPayloadWindow::whole(PacketPayload::default());

        let Err((result, _)) = processor.process_window_on(
            runtime,
            None,
            packet,
            Ipv4Address::ANY,
            Ipv4Address::ANY,
            64,
        ) else {
            panic!("missing ingress interface must reject the packet");
        };

        assert_eq!(result, UdpResult::NoIngressInterface);
    }
}
