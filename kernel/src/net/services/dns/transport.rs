// ============================================================================
// kernel/src/net/services/dns/transport.rs - サービス / DNS / transport
// ============================================================================

use super::*;

impl DnsClient {
    pub(super) async fn query_internal_name(
        &self,
        name: DnsNameOwned,
        qtype: DnsQueryType,
    ) -> Result<DnsResponseView, &'static str> {
        let tick = crate::task::current_tick();
        let ipv4_servers = self.ipv4_servers_snapshot();
        let ipv6_servers = self.ipv6_servers_snapshot();
        let servers = Self::build_prioritized_server_list(&ipv4_servers, &ipv6_servers);
        if servers.is_empty() {
            return Err("No DNS server configured");
        }

        let socket = self.bind_udp_socket()?;
        let query_id = self.next_query_id();
        self.register_pending_query_id(query_id);
        let result = self
            .query_servers_with_failover(&socket, &servers, name, qtype, tick, query_id)
            .await;
        if result.is_err() {
            let mut id_payload_builder = crate::net::payload::PacketPayloadBuilder::new();
            id_payload_builder
                .push_generated_bytes(&query_id.to_be_bytes())
                .ok_or("Failed to allocate DNS query id payload")?;
            self.retire_pending_query_id(&id_payload_builder.build());
        }
        result
    }

    pub(super) fn build_prioritized_server_list(
        ipv4_servers: &[Ipv4Address],
        ipv6_servers: &[Ipv6Address],
    ) -> Vec<DnsServerAddr> {
        let mut servers = Vec::with_capacity(ipv4_servers.len() + ipv6_servers.len());
        servers.extend(ipv4_servers.iter().copied().map(DnsServerAddr::V4));
        servers.extend(ipv6_servers.iter().copied().map(DnsServerAddr::V6));
        servers
    }

    fn bind_udp_socket(&self) -> Result<crate::net::l4::udp::UdpEndpoint, &'static str> {
        crate::net::l4::udp::UdpEndpoint::bind_in(
            crate::net::runtime::default_runtime(),
            crate::net::types::InterfaceScope::Any,
            0,
            None,
        )
        .map_err(|_| "Failed to bind UDP")
    }

    async fn query_servers_with_failover(
        &self,
        socket: &crate::net::l4::udp::UdpEndpoint,
        servers: &[DnsServerAddr],
        name: DnsNameOwned,
        qtype: DnsQueryType,
        tick: u64,
        query_id: u16,
    ) -> Result<DnsResponseView, &'static str> {
        let mut last_error = "DNS query timed out";
        let mut retained_name = name;

        for server in servers {
            match self
                .query_single_server(socket, *server, retained_name, qtype, tick, query_id)
                .await
            {
                Ok(response) => return Ok(response),
                Err((name, err)) => {
                    retained_name = name;
                    last_error = err;
                }
            }
        }
        Err(last_error)
    }
}
