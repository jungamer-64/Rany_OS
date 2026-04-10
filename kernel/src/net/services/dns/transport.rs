use super::*;

impl DnsClient {
    /// Internal DNS query logic with UDP-to-TCP fallback (RFC 7766)
    pub(super) async fn query_internal(
        &self,
        name: &str,
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
        let query_payload = self.build_query_payload(name, qtype)?;
        let result = self
            .query_servers_with_failover(
                &socket,
                query_payload.clone(),
                &servers,
                name,
                qtype,
                tick,
            )
            .await;
        if result.is_err() {
            self.retire_pending_query_id(&query_payload);
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
        query_payload: kernel_api::resource::net::PacketPayload,
        servers: &[DnsServerAddr],
        name: &str,
        qtype: DnsQueryType,
        tick: u64,
    ) -> Result<DnsResponseView, &'static str> {
        let mut last_error = "DNS query timed out";

        for server in servers {
            match self
                .query_single_server(socket, query_payload.clone(), *server, name, qtype, tick)
                .await
            {
                Ok(response) => return Ok(response),
                Err(err) => last_error = err,
            }
        }
        Err(last_error)
    }
}
