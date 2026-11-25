// ============================================================================
// kernel/src/net/services/dns/transport_tcp.rs - サービス / DNS / TCPトランスポート
// ============================================================================

use super::parser::{DnsQuestion, DnsReply};
use super::*;
use crate::net::l4::udp::UdpAddr;
use crate::task::{self, TimeoutResult};

impl DnsClient {
    pub(super) async fn query_single_server(
        &self,
        socket: &crate::net::l4::udp::UdpEndpoint,
        server: DnsServerAddr,
        mut name: DnsNameOwned,
        qtype: DnsQueryType,
    ) -> Result<DnsResponseView, (DnsNameOwned, &'static str)> {
        let dest = Self::udp_addr_for_server(server);
        let id = match self.next_query_id() {
            Ok(id) => id,
            Err(error) => return Err((name, error)),
        };
        for _ in 0..DNS_MAX_RETRIES {
            let payload = match self.build_query_payload_for_name_with_id(&name, qtype, id) {
                Ok(payload) => payload,
                Err(error) => return Err((name, error)),
            };
            if socket.send(payload, dest).await.is_err() {
                return Err((name, "UDP send failed"));
            }

            let question_name = &mut name;
            let reply = async move {
                // LOOP_PROOF: mode=event; reason=Each receive awaits a datagram; unrelated traffic yields to let the attempt deadline be polled.;
                loop {
                    let Some((_if_id, src, _ttl, packet)) = socket.recv().await else {
                        return None;
                    };
                    if Self::source_matches_server(src, server) && src.port() == DNS_PORT {
                        let question = DnsQuestion {
                            id,
                            name: &*question_name,
                            kind: qtype,
                        };
                        match self.parse_reply(packet, &question) {
                            DnsReply::Unrelated => {}
                            matched => return Some(matched),
                        }
                    }
                    task::yield_now().await;
                }
            };
            match task::with_timeout(reply, DNS_RETRY_TIMEOUT_MS).await {
                TimeoutResult::Completed(Some(DnsReply::Answer(result))) => {
                    return result.map_err(|_| (name, "DNS answer rejected"));
                }
                TimeoutResult::Completed(Some(DnsReply::Truncated)) => {
                    return self.query_tcp(server, name, qtype).await;
                }
                TimeoutResult::Completed(_) => return Err((name, "DNS receive ended")),
                TimeoutResult::TimedOut => {}
                TimeoutResult::TimerFailed(cause) => {
                    log::error!("DNS query timer failed: {cause}");
                    return Err((name, "DNS query timer unavailable"));
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
            stash: &mut Option<kernel_api::resource::net::PacketPayload>,
            len: usize,
        ) -> Result<Option<kernel_api::resource::net::PacketPayload>, &'static str> {
            // LOOP_PROOF: mode=condition; reason=Each iteration awaits a nonempty owned payload, advancing the requested byte prefix or ending on closure or allocation failure.;
            while stash.as_ref().map_or(0, |payload| payload.total_len()) < len {
                let Some(payload) = connection.recv_payload().await else {
                    break;
                };
                let Some(queued) = stash.take() else {
                    *stash = Some(payload);
                    continue;
                };
                match queued.try_append(payload) {
                    Ok(combined) => *stash = Some(combined),
                    Err(error) => {
                        let (queued, _incoming) = error.into_owner();
                        *stash = Some(queued);
                        return Err("TCP receive payload allocation failed");
                    }
                }
            }
            let Some(queued) = stash.take() else {
                return Ok(None);
            };
            if queued.total_len() < len {
                *stash = Some(queued);
                return Ok(None);
            }
            let count = kernel_api::resource::net::PacketByteCount::new(len)
                .ok_or("TCP record length must be non-zero")?;
            match queued.try_take_front(count) {
                Ok(kernel_api::resource::net::PacketPayloadFront::Whole(payload)) => {
                    Ok(Some(payload))
                }
                Ok(kernel_api::resource::net::PacketPayloadFront::Prefix { front, remainder }) => {
                    *stash = Some(remainder);
                    Ok(Some(front))
                }
                Err(error) => {
                    *stash = Some(error.into_owner());
                    Err("TCP payload split failed")
                }
            }
        }

        let dest = Self::endpoint_addr_for_server(server);

        let connection = crate::net::l4::tcp::TcpConnection::dial_in(self.runtime, dest).await;
        let mut connection = match connection {
            Ok(connection) => connection,
            Err(_) => return Err((name, "TCP connection failed")),
        };

        let query_id = match self.next_query_id() {
            Ok(query_id) => query_id,
            Err(err) => return Err((name, err)),
        };
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

        let mut stash = None;

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
        connection.close();

        let question = DnsQuestion {
            id: query_id,
            name: &name,
            kind: qtype,
        };
        match self.parse_reply(msg_data, &question) {
            DnsReply::Answer(Ok(response)) => Ok(response),
            DnsReply::Answer(Err(_)) => Err((name, "DNS answer rejected")),
            DnsReply::Unrelated => Err((name, "DNS reply does not match the query")),
            DnsReply::Truncated => Err((name, "Truncated DNS reply over TCP")),
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
}
