// ============================================================================
// kernel/src/net/services/dns/transport_tcp.rs - サービス / DNS / TCPトランスポート
// ============================================================================

use super::*;
use crate::net::l4::udp::UdpAddr;
use crate::task::{self, TimeoutResult};

impl DnsClient {
    pub(super) async fn query_single_server(
        &self,
        socket: &crate::net::l4::udp::UdpEndpoint,
        server: DnsServerAddr,
        name: DnsNameOwned,
        qtype: DnsQueryType,
        tick: u64,
        query_id: u16,
    ) -> Result<DnsResponseView, (DnsNameOwned, &'static str)> {
        let dest = Self::udp_addr_for_server(server);
        let query_payload = match self.build_query_payload_for_name_with_id(&name, qtype, query_id)
        {
            Ok(payload) => payload,
            Err(err) => return Err((name, err)),
        };
        if socket.send(query_payload, dest).await.is_err() {
            return Err((name, "UDP send failed"));
        }

        let mut attempt = 0;
        while attempt < DNS_MAX_RETRIES {
            match task::with_timeout(socket.recv(), DNS_RETRY_TIMEOUT_MS).await {
                TimeoutResult::Completed(Some((_if_id, src, _ttl, packet))) => {
                    if Self::source_matches_server(src, server) && src.port() == DNS_PORT {
                        let parsed =
                            self.parse_response_payload_for_name(packet, tick, &name, qtype);
                        if let Some(parsed) = parsed {
                            return parsed.map_err(|_| (name, "Parse error"));
                        }

                        log::info!(
                            "[NET] DNS: UDP response truncated, retrying with TCP (RFC 7766 fallback)"
                        );
                        return self.query_tcp(server, name, qtype).await;
                    }

                    attempt += 1;
                }
                _ => {
                    attempt += 1;
                    if attempt < DNS_MAX_RETRIES {
                        let retry_payload = match self
                            .build_query_payload_for_name_with_id(&name, qtype, query_id)
                        {
                            Ok(payload) => payload,
                            Err(err) => return Err((name, err)),
                        };
                        let _ = socket.send(retry_payload, dest).await;
                    }
                }
            }
        }

        Err((name, "DNS query timed out"))
    }

    /// DNS query over TCP (RFC 7766)
    async fn query_tcp(
        &self,
        server: DnsServerAddr,
        name: DnsNameOwned,
        qtype: DnsQueryType,
    ) -> Result<DnsResponseView, (DnsNameOwned, &'static str)> {
        async fn read_exact_payload(
            connection: &mut crate::net::l4::tcp::TcpConnection,
            stash: &mut kernel_api::resource::net::PacketPayload,
            len: usize,
        ) -> Result<Option<kernel_api::resource::net::PacketPayload>, &'static str> {
            while stash.total_len() < len {
                let Some(payload) = connection.recv_payload().await else {
                    break;
                };
                if payload.total_len() == 0 {
                    break;
                }
                crate::net::payload::append_payload(stash, payload);
            }
            if stash.total_len() < len {
                return Ok(None);
            }
            let owned_stash = core::mem::take(stash);
            let (prefix, remainder) =
                crate::net::payload::split_payload_prefix_owned(owned_stash, len)
                    .ok_or("TCP payload prefix split failed")?;
            *stash = remainder;
            Ok(Some(prefix))
        }

        let dest = Self::endpoint_addr_for_server(server);

        let connection = crate::net::l4::tcp::TcpConnection::dial_in(
            crate::net::runtime::default_runtime(),
            dest,
        )
        .await;
        let mut connection = match connection {
            Ok(connection) => connection,
            Err(_) => return Err((name, "TCP connection failed")),
        };

        let query_id = self.next_query_id();
        self.register_pending_query_id(query_id);
        let payload = match self.build_tcp_query_payload_for_name_with_id(&name, qtype, query_id) {
            Ok(payload) => payload,
            Err(err) => return Err((name, err)),
        };
        if connection.send_payload(payload).await.is_err() {
            return Err((name, "TCP write failed"));
        }
        if connection.drain_tx().await.is_err() {
            return Err((name, "TCP write drain failed"));
        }

        let mut stash = kernel_api::resource::net::PacketPayload::default();

        // Read 2-byte length prefix
        let len_payload = match read_exact_payload(&mut connection, &mut stash, 2).await {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                return Err((
                    name,
                    "TCP read length prefix failed (connection closed or incomplete)",
                ));
            }
            Err(err) => return Err((name, err)),
        };
        let len_buf = crate::net::payload::PacketPayloadView::new(&len_payload).read_array::<2>(0);
        let len_buf = match len_buf {
            Some(len_buf) => len_buf,
            None => return Err((name, "TCP length prefix parse failed")),
        };
        if len_buf == [0, 0] {
            return Err((
                name,
                "TCP read length prefix failed (connection closed or incomplete)",
            ));
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len > 65535 {
            return Err((name, "TCP message too long"));
        }

        let msg_data = match read_exact_payload(&mut connection, &mut stash, msg_len).await {
            Ok(Some(payload)) => payload,
            Ok(None) => return Err((name, "TCP read incomplete message")),
            Err(err) => return Err((name, err)),
        };

        let tick = crate::task::current_tick();
        match self.parse_response_payload_for_name(msg_data, tick, &name, qtype) {
            Some(Ok(response)) => Ok(response),
            Some(Err(_)) => Err((name, "Parse error")),
            None => Err((name, "TCP fallback requested unexpectedly")),
        }
    }

    fn udp_addr_for_server(server: DnsServerAddr) -> UdpAddr {
        match server {
            DnsServerAddr::V4(ip) => UdpAddr::new(ip, DNS_PORT),
            DnsServerAddr::V6(ip) => UdpAddr::new_v6(ip, DNS_PORT),
        }
    }

    fn source_matches_server(src: UdpAddr, server: DnsServerAddr) -> bool {
        match server {
            DnsServerAddr::V4(ip) => src.ip_v4() == Some(ip),
            DnsServerAddr::V6(ip) => src.ip_v6() == Some(ip),
        }
    }

    fn endpoint_addr_for_server(server: DnsServerAddr) -> crate::net::l4::types::EndpointAddr {
        use crate::net::l4::types::EndpointAddr;

        match server {
            DnsServerAddr::V4(ip) => EndpointAddr::new(ip.octets(), DNS_PORT),
            DnsServerAddr::V6(ip) => EndpointAddr::new_v6(ip.octets(), DNS_PORT),
        }
    }

    /// Parse a DNS response received over TCP
    pub fn parse_tcp_response_payload(
        &self,
        payload: kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Result<DnsResponseView, DnsResponseCode> {
        let view = crate::net::payload::PacketPayloadView::new(&payload);
        if view.total_len() < 2 {
            return Err(DnsResponseCode::FormatError);
        }

        let len = view
            .read_array::<2>(0)
            .ok_or(DnsResponseCode::FormatError)?;
        let msg_len = u16::from_be_bytes(len) as usize;

        if view.total_len() < 2 + msg_len {
            return Err(DnsResponseCode::FormatError);
        }

        let message = crate::net::payload::retain_payload_window_owned(payload, 2, msg_len)
            .ok_or(DnsResponseCode::FormatError)?;
        self.parse_response_payload(message, current_tick, expected_name, expected_type)
            .ok_or(DnsResponseCode::FormatError)?
    }

    /// Check if a UDP response requires TCP fallback
    pub fn needs_tcp_fallback(&self, data: &[u8]) -> bool {
        if data.len() < DnsHeader::SIZE {
            return false;
        }

        let Some(header) = crate::util::get_ref::<DnsHeader>(data, 0) else {
            return false;
        };

        if header.is_truncated() {
            return true;
        }

        if data.len() >= 512 {
            return true;
        }

        false
    }

    /// Calculate expected TCP message length from length prefix
    pub fn tcp_message_length(length_prefix: &[u8; 2]) -> u16 {
        u16::from_be_bytes(*length_prefix)
    }
}
