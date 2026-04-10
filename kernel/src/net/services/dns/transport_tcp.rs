use super::*;
use crate::net::l4::udp::UdpAddr;
use crate::task::{self, TimeoutResult};

impl DnsClient {
    pub(super) async fn query_single_server(
        &self,
        socket: &crate::net::l4::udp::UdpEndpoint,
        query_payload: kernel_api::resource::net::PacketPayload,
        server: Ipv4Address,
        name: &str,
        qtype: DnsQueryType,
        tick: u64,
    ) -> Result<DnsResponseView, &'static str> {
        let dest = UdpAddr::new(server, DNS_PORT);
        if socket.send(query_payload.clone(), dest).await.is_err() {
            return Err("UDP send failed");
        }

        let mut attempt = 0;
        while attempt < DNS_MAX_RETRIES {
            match task::with_timeout(socket.recv(), DNS_RETRY_TIMEOUT_MS).await {
                TimeoutResult::Completed(Some((_if_id, src, _ttl, packet))) => {
                    if src.ip_v4() == Some(server) && src.port() == DNS_PORT {
                        let parsed = self.parse_response_payload(&packet, tick, name, qtype);
                        if let Some(parsed) = parsed {
                            return parsed.map_err(|_| "Parse error");
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
                        let _ = socket.send(query_payload.clone(), dest).await;
                    }
                }
            }
        }

        Err("DNS query timed out")
    }

    /// DNS query over TCP (RFC 7766)
    async fn query_tcp(
        &self,
        server: Ipv4Address,
        name: &str,
        qtype: DnsQueryType,
    ) -> Result<DnsResponseView, &'static str> {
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
            stash
                .take_prefix(len)
                .ok_or("TCP payload prefix split failed")
                .map(Some)
        }

        use crate::net::l4::endpoint::types::EndpointAddr;
        let dest = EndpointAddr::new(server.octets(), DNS_PORT);

        let mut connection = crate::net::l4::tcp::TcpConnection::dial_in(
            crate::net::runtime::default_runtime(),
            dest,
        )
        .await
        .map_err(|_| "TCP connection failed")?;

        let payload = self.build_tcp_query_payload(name, qtype)?;
        connection
            .send_payload(payload)
            .await
            .map_err(|_| "TCP write failed")?;
        connection
            .drain_tx()
            .await
            .map_err(|_| "TCP write drain failed")?;

        let mut stash = kernel_api::resource::net::PacketPayload::default();

        // Read 2-byte length prefix
        let len_payload = read_exact_payload(&mut connection, &mut stash, 2)
            .await?
            .ok_or("TCP read length prefix failed (connection closed or incomplete)")?;
        let len_buf = crate::net::payload::PacketPayloadView::new(&len_payload)
            .read_array::<2>(0)
            .ok_or("TCP length prefix parse failed")?;
        if len_buf == [0, 0] {
            return Err("TCP read length prefix failed (connection closed or incomplete)");
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len > 65535 {
            return Err("TCP message too long");
        }

        let msg_data = read_exact_payload(&mut connection, &mut stash, msg_len)
            .await?
            .ok_or("TCP read incomplete message")?;

        let tick = crate::task::current_tick();
        self.parse_response_payload(&msg_data, tick, name, qtype)
            .ok_or("TCP fallback requested unexpectedly")?
            .map_err(|_| "Parse error")
    }

    /// Parse a DNS response received over TCP
    pub fn parse_tcp_response_payload(
        &self,
        payload: &kernel_api::resource::net::PacketPayload,
        current_tick: u64,
        expected_name: &str,
        expected_type: DnsQueryType,
    ) -> Result<DnsResponseView, DnsResponseCode> {
        let view = crate::net::payload::PacketPayloadView::new(payload);
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

        let message = crate::net::payload::payload_range(payload, 2, msg_len)
            .ok_or(DnsResponseCode::FormatError)?;
        self.parse_response_payload(&message, current_tick, expected_name, expected_type)
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
