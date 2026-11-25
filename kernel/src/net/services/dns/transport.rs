// ============================================================================
// kernel/src/net/services/dns/transport.rs - サービス / DNS / transport
// ============================================================================

use super::*;
use crate::net::runtime::manager;
use crate::net::types::InterfaceScope;

impl DnsServerAddr {
    pub(super) fn scope(self) -> InterfaceScope {
        match self {
            Self::AdvertisedV6 { if_id, .. } => InterfaceScope::Pinned(if_id),
            Self::V4(_) | Self::ConfiguredV6(_) => InterfaceScope::Any,
        }
    }

    pub(super) fn is_live(self, runtime: NetRuntimeHandle) -> bool {
        match self {
            Self::AdvertisedV6 { address, if_id } => {
                manager::rdnss_server_live_in(runtime, if_id, address, crate::task::current_tick())
            }
            Self::V4(_) | Self::ConfiguredV6(_) => true,
        }
    }
}

impl DnsClient {
    pub(super) async fn query_internal_name(
        &self,
        name: DnsNameOwned,
        qtype: DnsQueryType,
    ) -> Result<DnsResponseView, &'static str> {
        let ipv4_servers = self.ipv4_servers_snapshot();
        let ipv6_servers = self.ipv6_servers_snapshot();
        let mut servers = Vec::with_capacity(ipv4_servers.len() + ipv6_servers.len());
        servers.extend(ipv4_servers.into_iter().map(DnsServerAddr::V4));
        servers.extend(ipv6_servers.into_iter().map(DnsServerAddr::ConfiguredV6));
        if let Ok(advertised) = manager::rdnss_servers_in(self.runtime, crate::task::current_tick())
        {
            servers.extend(
                advertised
                    .into_iter()
                    .map(|(if_id, address)| DnsServerAddr::AdvertisedV6 { address, if_id }),
            );
        }
        if servers.is_empty() {
            return Err("No DNS server configured");
        }

        self.query_servers_with_failover(&servers, name, qtype)
            .await
    }

    fn bind_udp_socket(
        &self,
        scope: InterfaceScope,
    ) -> Result<crate::net::l4::udp::UdpEndpoint, &'static str> {
        crate::net::l4::udp::UdpEndpoint::bind_in(self.runtime, scope, 0, None)
            .map_err(|_| "Failed to bind UDP")
    }

    async fn query_servers_with_failover(
        &self,
        servers: &[DnsServerAddr],
        name: DnsNameOwned,
        qtype: DnsQueryType,
    ) -> Result<DnsResponseView, &'static str> {
        let mut last_error = "DNS query timed out";
        let mut retained_name = name;

        for &server in servers {
            let socket = match self.bind_udp_socket(server.scope()) {
                Ok(socket) => socket,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            match self
                .query_single_server(&socket, server, retained_name, qtype)
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
