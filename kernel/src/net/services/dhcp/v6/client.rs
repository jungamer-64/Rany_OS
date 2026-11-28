// ============================================================================
// kernel/src/net/services/dhcp/v6/client.rs - サービス / DHCP / v6 / クライアント
// ============================================================================

use super::response::{Response, ResponseError, ServerId};
use super::types::*;
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv6::Ipv6Address;
use crate::net::l4::udp::UdpPorts;
use crate::net::payload::alloc_packet_with_headroom_in;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::{self, NetIfId};
use crate::sync::PoisonLock;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

pub struct DhcpV6Client {
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    mac: MacAddress,
    duid: [u8; 10],
    iaid: u32,
    phase: PoisonLock<Phase>,
}

struct Server {
    id: ServerId,
    address: Ipv6Address,
}

struct Binding {
    server: Server,
    lease: DhcpV6Lease,
}

struct Exchange {
    xid: [u8; 3],
    last_attempt: u64,
    attempts: u32,
}

impl Exchange {
    fn begin(now: u64) -> Result<Self, &'static str> {
        let random = crate::net::security::tls::crypto::generate_random()
            .map_err(|_| "Secure DHCPv6 XID entropy unavailable")?;
        Ok(Self {
            xid: [random[0], random[1], random[2]],
            last_attempt: now,
            attempts: 0,
        })
    }

    fn due(&self, now: u64, jitter_seed: u8, initial: u64, maximum: u64) -> bool {
        let base = (initial << self.attempts.min(7)).min(maximum);
        let jitter = ((now ^ u64::from(jitter_seed)) % 21) as i64 - 10;
        let interval = (base as i64 * (1000 + jitter * 10)) as u64;
        now.saturating_sub(self.last_attempt) >= interval
    }

    fn attempted(&mut self, now: u64) {
        self.last_attempt = now;
        self.attempts = self.attempts.saturating_add(1);
    }
}

enum Phase {
    Init,
    Soliciting(Exchange),
    Requesting {
        exchange: Exchange,
        server: Server,
        offered: Ipv6Address,
    },
    Bound(Binding),
    Renewing(Exchange, Binding),
    Rebinding(Exchange, Binding),
}

impl Phase {
    fn binding(&self) -> Option<&Binding> {
        match self {
            Self::Bound(binding) | Self::Renewing(_, binding) | Self::Rebinding(_, binding) => {
                Some(binding)
            }
            _ => None,
        }
    }

    fn state(&self) -> DhcpV6State {
        match self {
            Self::Init => DhcpV6State::Init,
            Self::Soliciting(_) => DhcpV6State::SolicitSent,
            Self::Requesting { .. } => DhcpV6State::Requesting,
            Self::Bound(_) => DhcpV6State::Bound,
            Self::Renewing(..) => DhcpV6State::Renewing,
            Self::Rebinding(..) => DhcpV6State::Rebinding,
        }
    }

    fn accepts(&self, kind: DhcpV6MessageType, xid: [u8; 3], server: &ServerId) -> bool {
        match (self, kind) {
            (Self::Soliciting(exchange), DhcpV6MessageType::Advertise)
            | (Self::Rebinding(exchange, _), DhcpV6MessageType::Reply) => exchange.xid == xid,
            (
                Self::Requesting {
                    exchange,
                    server: expected,
                    ..
                },
                DhcpV6MessageType::Reply,
            )
            | (
                Self::Renewing(
                    exchange,
                    Binding {
                        server: expected, ..
                    },
                ),
                DhcpV6MessageType::Reply,
            ) => exchange.xid == xid && expected.id.as_bytes() == server.as_bytes(),
            _ => false,
        }
    }
}

enum ClientMessage<'a> {
    Solicit,
    Request(&'a Server, Ipv6Address),
    Renew(&'a Binding),
    Rebind(&'a Binding),
    Release(&'a Binding),
}

impl ClientMessage<'_> {
    fn kind(&self) -> DhcpV6MessageType {
        match self {
            Self::Solicit => DhcpV6MessageType::Solicit,
            Self::Request(..) => DhcpV6MessageType::Request,
            Self::Renew(_) => DhcpV6MessageType::Renew,
            Self::Rebind(_) => DhcpV6MessageType::Rebind,
            Self::Release(_) => DhcpV6MessageType::Release,
        }
    }

    fn server(&self) -> Option<&Server> {
        match self {
            Self::Request(server, _) => Some(server),
            Self::Renew(binding) | Self::Release(binding) => Some(&binding.server),
            Self::Solicit | Self::Rebind(_) => None,
        }
    }

    fn address(&self) -> Option<Ipv6Address> {
        match self {
            Self::Solicit => None,
            Self::Request(_, offered) => Some(*offered),
            Self::Renew(binding) | Self::Rebind(binding) | Self::Release(binding) => {
                Some(binding.lease.addr)
            }
        }
    }
}

impl DhcpV6Client {
    const MAX_RETRIES: u32 = 4;

    #[inline]
    fn all_dhcp_servers_multicast() -> Ipv6Address {
        // RFC 8415: All_DHCP_Relay_Agents_and_Servers = ff02::1:2
        Ipv6Address::new([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2])
    }

    fn get_link_local(&self) -> Option<Ipv6Address> {
        crate::net::runtime::manager::assigned_ipv6_link_local_in(self.runtime, self.if_id)
    }

    /// 非同期イベントキュー経由でUDPv6パケットを送信（ロック競合回避）
    fn enqueue_v6_send(
        &self,
        src: Ipv6Address,
        dst: Ipv6Address,
        payload: kernel_api::resource::net::PacketPayload,
    ) -> bool {
        crate::net::runtime::command::enqueue_udp_v6_send_scoped_in(
            self.runtime,
            crate::net::types::InterfaceScope::Pinned(self.if_id),
            src,
            dst,
            UdpPorts::new(DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT),
            payload,
            64,
        )
    }

    /// DUID-LL を生成（type=3, hwtype=1 + MAC）
    fn make_duid_ll(mac: &crate::net::l2::ethernet::MacAddress) -> [u8; 10] {
        let mut duid = [0u8; 10];
        duid[0..2].copy_from_slice(&3u16.to_be_bytes());
        duid[2..4].copy_from_slice(&1u16.to_be_bytes());
        duid[4..10].copy_from_slice(mac.as_bytes());
        duid
    }

    pub(crate) fn new(runtime: NetRuntimeHandle, if_id: NetIfId, mac: MacAddress) -> Self {
        let duid = Self::make_duid_ll(&mac);
        let bytes = mac.as_bytes();
        Self {
            runtime,
            if_id,
            mac,
            duid,
            iaid: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            phase: PoisonLock::new(Phase::Init),
        }
    }

    pub(crate) fn snapshot(&self) -> (DhcpV6State, Option<DhcpV6Lease>) {
        self.phase
            .lock()
            .map_or((DhcpV6State::Init, None), |phase| {
                (phase.state(), phase.binding().map(|binding| binding.lease))
            })
    }

    fn encode(
        &self,
        bytes: &mut [u8; 256],
        exchange: &Exchange,
        request: &ClientMessage<'_>,
    ) -> usize {
        bytes[0] = request.kind() as u8;
        bytes[1..4].copy_from_slice(&exchange.xid);
        let mut offset = 4;
        fn option(bytes: &mut [u8], offset: &mut usize, code: u16, data: &[u8]) {
            let start = *offset;
            bytes[start..start + 2].copy_from_slice(&code.to_be_bytes());
            bytes[start + 2..start + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
            *offset += 4 + data.len();
            bytes[start + 4..*offset].copy_from_slice(data);
        }
        option(bytes, &mut offset, 1, &self.duid);
        if let Some(server) = request.server() {
            option(bytes, &mut offset, 2, server.id.as_bytes());
        }
        let mut ia = [0; 40];
        ia[..4].copy_from_slice(&self.iaid.to_be_bytes());
        let ia_len = if let Some(address) = request.address() {
            let mut ia_offset = 12;
            let mut iaaddr = [0; 24];
            iaaddr[..16].copy_from_slice(address.as_bytes());
            option(&mut ia, &mut ia_offset, 5, &iaaddr);
            ia_offset
        } else {
            12
        };
        option(bytes, &mut offset, 3, &ia[..ia_len]);
        offset
    }

    fn send(&self, exchange: &Exchange, request: ClientMessage<'_>) -> Result<(), &'static str> {
        let src = self
            .get_link_local()
            .ok_or("No assigned link-local address")?;
        let dst = request
            .server()
            .map_or_else(Self::all_dhcp_servers_multicast, |server| server.address);
        let mut bytes = [0; 256];
        let len = self.encode(&mut bytes, exchange, &request);
        let mut packet = alloc_packet_with_headroom_in(self.runtime, len, DEFAULT_PACKET_HEADROOM)
            .ok_or("Failed to allocate DHCPv6 payload")?;
        packet.data_mut().copy_from_slice(&bytes[..len]);
        let payload = PacketPayload::try_single(packet).map_err(|_| "Invalid DHCPv6 payload")?;
        self.enqueue_v6_send(src, dst, payload)
            .then_some(())
            .ok_or("DHCPv6 send queue rejected the message")
    }

    pub(crate) fn receive(
        &self,
        payload: PacketPayload,
        src: Ipv6Address,
        now: u64,
    ) -> Result<(), ResponseError> {
        let response = Response::parse(&payload, &self.duid, self.iaid, now)?;
        let mut phase = self
            .phase
            .lock()
            .map_err(|_| ResponseError::StateUnavailable)?;
        if !phase.accepts(response.kind(), response.xid(), response.server()) {
            return Err(ResponseError::Unrelated);
        }
        match response {
            Response::Advertise {
                server, address, ..
            } => {
                let server = Server {
                    id: server,
                    address: src,
                };
                let exchange = Exchange::begin(now).map_err(ResponseError::PrepareRequest)?;
                self.send(&exchange, ClientMessage::Request(&server, address))
                    .map_err(ResponseError::PrepareRequest)?;
                *phase = Phase::Requesting {
                    exchange,
                    server,
                    offered: address,
                };
            }
            Response::Reply {
                server,
                lease,
                lifetimes,
                dns_servers,
                domain_search,
                ..
            } => {
                // The topology owner stages the address synchronously; DAD gates its later use.
                manager::stage_dhcp_ipv6_in(self.runtime, self.if_id, lease.addr, lifetimes, now)
                    .map_err(ResponseError::ApplyLease)?;
                *phase = Phase::Bound(Binding {
                    server: Server {
                        id: server,
                        address: src,
                    },
                    lease,
                });
                if manager::primary_interface_in(self.runtime) == Some(self.if_id) {
                    if !dns_servers.is_empty() {
                        crate::net::services::dns::set_ipv6_servers_in(self.runtime, &dns_servers);
                    }
                    if !domain_search.is_empty() {
                        crate::net::services::dns::set_search_domains_in(
                            self.runtime,
                            &domain_search,
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn check_timeout(&self, now: u64) -> Result<(), &'static str> {
        let mut phase = self.phase.lock().map_err(|_| "DHCPv6 state unavailable")?;
        if phase
            .binding()
            .is_some_and(|binding| elapsed(now, &binding.lease, binding.lease.valid_lifetime))
        {
            *phase = Phase::Init;
            return Ok(());
        }
        let jitter = self.mac.as_bytes()[5];
        match &mut *phase {
            Phase::Init if self.get_link_local().is_some() => {
                let exchange = Exchange::begin(now)?;
                self.send(&exchange, ClientMessage::Solicit)?;
                *phase = Phase::Soliciting(exchange);
            }
            Phase::Soliciting(exchange) if exchange.due(now, jitter, 1, 120) => {
                if exchange.attempts >= Self::MAX_RETRIES {
                    *phase = Phase::Init;
                } else {
                    exchange.attempted(now);
                    self.send(exchange, ClientMessage::Solicit)?;
                }
            }
            Phase::Requesting {
                exchange,
                server,
                offered,
            } if exchange.due(now, jitter, 1, 30) => {
                if exchange.attempts >= Self::MAX_RETRIES {
                    *phase = Phase::Init;
                } else {
                    exchange.attempted(now);
                    self.send(exchange, ClientMessage::Request(server, *offered))?;
                }
            }
            Phase::Bound(binding) | Phase::Renewing(_, binding)
                if elapsed(now, &binding.lease, binding.lease.t2) =>
            {
                let exchange = Exchange::begin(now)?;
                self.send(&exchange, ClientMessage::Rebind(binding))?;
                if let Phase::Bound(binding) | Phase::Renewing(_, binding) =
                    core::mem::replace(&mut *phase, Phase::Init)
                {
                    *phase = Phase::Rebinding(exchange, binding);
                }
            }
            Phase::Bound(binding) if elapsed(now, &binding.lease, binding.lease.t1) => {
                let exchange = Exchange::begin(now)?;
                self.send(&exchange, ClientMessage::Renew(binding))?;
                if let Phase::Bound(binding) = core::mem::replace(&mut *phase, Phase::Init) {
                    *phase = Phase::Renewing(exchange, binding);
                }
            }
            Phase::Renewing(exchange, binding) if exchange.due(now, jitter, 10, 600) => {
                exchange.attempted(now);
                self.send(exchange, ClientMessage::Renew(binding))?;
            }
            Phase::Rebinding(exchange, binding) if exchange.due(now, jitter, 10, 600) => {
                exchange.attempted(now);
                self.send(exchange, ClientMessage::Rebind(binding))?;
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn release(&self) {
        if let Ok(mut phase) = self.phase.lock() {
            if let Some(binding) = phase.binding()
                && let Err(error) = Exchange::begin(crate::task::current_tick())
                    .and_then(|exchange| self.send(&exchange, ClientMessage::Release(binding)))
            {
                log::warn!("[NET] DHCPv6 RELEASE admission failed: {error}");
            }
            *phase = Phase::Init;
        }
    }

    pub(crate) fn force_renew_or_restart(&self, now: u64) -> Result<(), &'static str> {
        let mut phase = self.phase.lock().map_err(|_| "DHCPv6 state unavailable")?;
        let Some(binding) = phase.binding() else {
            *phase = Phase::Init;
            return Ok(());
        };
        let exchange = Exchange::begin(now)?;
        self.send(&exchange, ClientMessage::Renew(binding))?;
        match core::mem::replace(&mut *phase, Phase::Init) {
            Phase::Bound(binding) | Phase::Renewing(_, binding) | Phase::Rebinding(_, binding) => {
                *phase = Phase::Renewing(exchange, binding);
            }
            _ => {}
        }
        Ok(())
    }
}

fn elapsed(now: u64, lease: &DhcpV6Lease, seconds: u32) -> bool {
    seconds != u32::MAX && now.saturating_sub(lease.obtained_at) >= u64::from(seconds) * 1000
}

#[cfg(any(
    all(test, any(feature = "std", target_os = "linux")),
    feature = "qemu-test-export"
))]
pub(crate) mod tests {
    use super::*;
    use crate::net::l3::ipv6::Ipv6Config;
    use crate::net::runtime::manager::{LinkState, PrimaryPreference};
    use crate::net::runtime::stack::NetworkConfig;
    use alloc::vec::Vec;

    const MAC: MacAddress = MacAddress::new([2, 0, 0, 0, 0, 1]);
    const SERVER: Ipv6Address =
        Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    const ADDRESS: Ipv6Address =
        Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    const SERVER_ID: [u8; 6] = [0, 3, 0, 1, 2, 3];
    const OTHER_ID: [u8; 6] = [0, 3, 0, 1, 2, 4];
    const XID: [u8; 3] = [1, 2, 3];

    fn payload(bytes: &[u8]) -> PacketPayload {
        #[cfg(all(test, any(feature = "std", target_os = "linux")))]
        let packet = crate::net::l4::test_support::packet_fixture_with_data(bytes);
        #[cfg(not(all(test, any(feature = "std", target_os = "linux"))))]
        let packet = {
            let mut packet = crate::net::payload::alloc_packet_with_headroom(bytes.len(), 0)
                .expect("DHCPv6 fixture");
            packet.data_mut().copy_from_slice(bytes);
            packet
        };
        PacketPayload::try_single(packet).expect("DHCPv6 packet")
    }

    fn exchange() -> Exchange {
        Exchange {
            xid: XID,
            last_attempt: 0,
            attempts: 0,
        }
    }

    fn interface() -> DhcpV6Client {
        #[cfg(all(test, any(feature = "std", target_os = "linux")))]
        let runtime = crate::net::runtime::context::tests::runtime_fixture();
        #[cfg(not(all(test, any(feature = "std", target_os = "linux"))))]
        let runtime = crate::net::runtime::create_runtime().expect("isolated DHCPv6 runtime");
        manager::init_network_manager_in(runtime);
        let if_id = manager::register_interface_in(runtime, "dhcp-v6", PrimaryPreference::Auto)
            .expect("interface");
        let config = NetworkConfig {
            mac: MAC,
            ipv6: Some(Ipv6Config::default()),
            ..NetworkConfig::default()
        };
        manager::set_interface_config_in(runtime, if_id, config).expect("IPv6 config");
        DhcpV6Client::new(runtime, if_id, MAC)
    }

    fn option(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        bytes.extend(kind.to_be_bytes());
        bytes.extend((value.len() as u16).to_be_bytes());
        bytes.extend(value);
    }

    fn response(
        client: &DhcpV6Client,
        kind: DhcpV6MessageType,
        xid: [u8; 3],
        id: &[u8],
        iaid: u32,
        preferred: u32,
        valid: u32,
    ) -> Vec<u8> {
        let mut bytes = alloc::vec![kind as u8, xid[0], xid[1], xid[2]];
        option(&mut bytes, 1, &client.duid);
        if !id.is_empty() {
            option(&mut bytes, 2, id);
        }
        let mut ia = iaid.to_be_bytes().to_vec();
        ia.extend([0; 8]);
        let mut addr = ADDRESS.octets().to_vec();
        addr.extend(preferred.to_be_bytes());
        addr.extend(valid.to_be_bytes());
        option(&mut ia, 5, &addr);
        option(&mut bytes, 3, &ia);
        bytes
    }

    fn server(id: &[u8; 6]) -> Server {
        Server {
            id: ServerId::parse(crate::net::payload::PayloadSpanRef::from_payload(&payload(
                id,
            )))
            .unwrap(),
            address: SERVER,
        }
    }

    fn phase(client: &DhcpV6Client) -> crate::sync::poison_lock::PoisonLockGuard<'_, Phase> {
        client
            .phase
            .lock()
            .unwrap_or_else(|_| panic!("DHCPv6 phase lock"))
    }

    fn requesting() -> Phase {
        Phase::Requesting {
            exchange: exchange(),
            server: server(&SERVER_ID),
            offered: ADDRESS,
        }
    }

    fn set_up(client: &DhcpV6Client) {
        manager::set_interface_link_state_in(client.runtime, client.if_id, LinkState::Up)
            .expect("operational link");
    }

    #[cfg(all(feature = "qemu-test-export", target_os = "none"))]
    fn assign_link_local(client: &DhcpV6Client) {
        use crate::net::runtime::device::tx::TxReceipt;
        use crate::net::runtime::manager::DadEvent;
        use kernel_api::service::netdev::TxDeviceOutcome;

        set_up(client);
        let (receipt, reporter) = TxReceipt::reserve().expect("DAD completion");
        let address = Ipv6Address::from_eui64(MAC.as_bytes());
        let now = crate::task::current_tick();
        assert_eq!(
            manager::update_ipv6_dad_in(
                client.runtime,
                client.if_id,
                address,
                DadEvent::Reserve {
                    nonce: [0; 6],
                    receipt
                }
            ),
            Ok(true)
        );
        reporter.finish(TxDeviceOutcome::Transmitted, now);
        manager::maintain_ipv6_in(client.runtime, now + 1000).unwrap();
        assert_eq!(client.get_link_local(), Some(address));
    }

    fn addresses(client: &DhcpV6Client) -> crate::net::l3::ipv6::address_state::Ipv6AddressSet {
        manager::try_interface_topology_in(client.runtime)
            .unwrap()
            .into_entries()
            .find(|entry| entry.if_id == client.if_id)
            .unwrap()
            .config
            .ipv6
            .unwrap()
            .addresses
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    pub fn test_build_solicit_min_size() {
        let client = interface();
        let mut bytes = [0; 256];
        let len = client.encode(&mut bytes, &exchange(), &ClientMessage::Solicit);
        assert_eq!(&bytes[..4], &[1, 1, 2, 3]);
        assert_eq!(len, 34);
        assert_eq!(&bytes[22..26], &client.iaid.to_be_bytes());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    pub fn test_parse_reply_with_iaaddr() {
        let client = interface();
        let bytes = response(
            &client,
            DhcpV6MessageType::Reply,
            XID,
            &SERVER_ID,
            client.iaid,
            60,
            120,
        );
        let parsed = Response::parse(&payload(&bytes), &client.duid, client.iaid, 1000);
        match parsed {
            Ok(Response::Reply { lease, .. }) => {
                assert_eq!(lease.addr, ADDRESS);
                assert_eq!(
                    (
                        lease.preferred_lifetime,
                        lease.valid_lifetime,
                        lease.t1,
                        lease.t2
                    ),
                    (60, 120, 30, 48)
                );
            }
            _ => panic!("a usable IA Address"),
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    pub fn test_build_request_min_size() {
        let client = interface();
        let mut bytes = [0; 256];
        let server = server(&SERVER_ID);
        let len = client.encode(
            &mut bytes,
            &exchange(),
            &ClientMessage::Request(&server, ADDRESS),
        );
        assert_eq!(&bytes[..4], &[3, 1, 2, 3]);
        assert_eq!(&bytes[18..28], &[0, 2, 0, 6, 0, 3, 0, 1, 2, 3]);
        assert_eq!(&bytes[48..64], ADDRESS.as_bytes());
        assert_eq!(len, 72);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    pub fn test_handle_packet_stores_server_addr_and_duid() {
        let client = interface();
        set_up(&client);
        *phase(&client) = requesting();
        let reply = |xid, id: &[u8], iaid, preferred, valid| {
            response(
                &client,
                DhcpV6MessageType::Reply,
                xid,
                id,
                iaid,
                preferred,
                valid,
            )
        };
        for bytes in [
            reply([3, 2, 1], &SERVER_ID, client.iaid, 60, 120),
            reply(XID, &OTHER_ID, client.iaid, 60, 120),
            reply(XID, &[], client.iaid, 60, 120),
            reply(XID, &SERVER_ID, client.iaid + 1, 60, 120),
            reply(XID, &SERVER_ID, client.iaid, 121, 120),
        ] {
            assert!(client.receive(payload(&bytes), SERVER, 1000).is_err());
            assert_eq!(client.snapshot().0, DhcpV6State::Requesting);
            assert!(client.snapshot().1.is_none());
            assert!(
                !addresses(&client)
                    .entries
                    .iter()
                    .flatten()
                    .any(|entry| entry.address == ADDRESS)
            );
        }
        let mut failed = reply(XID, &SERVER_ID, client.iaid, 60, 120);
        option(&mut failed, 13, &[0, 2]);
        assert!(matches!(
            client.receive(payload(&failed), SERVER, 1000),
            Err(ResponseError::Status(2))
        ));
        let valid = reply(XID, &SERVER_ID, client.iaid, 60, 120);
        client.receive(payload(&valid), SERVER, 1000).unwrap();
        assert_eq!(client.snapshot().0, DhcpV6State::Bound);
        assert_eq!(client.snapshot().1.unwrap().addr, ADDRESS);
        assert!(
            addresses(&client)
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.address == ADDRESS && !entry.assigned())
        );
        assert!(matches!(
            client.receive(payload(&valid), SERVER, 1001),
            Err(ResponseError::Unrelated)
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    pub fn test_advertise_triggers_request_and_requesting_state() {
        let client = interface();
        *phase(&client) = Phase::Soliciting(exchange());
        let unsolicited_reply = response(
            &client,
            DhcpV6MessageType::Reply,
            XID,
            &SERVER_ID,
            client.iaid,
            60,
            120,
        );
        assert!(matches!(
            client.receive(payload(&unsolicited_reply), SERVER, 1000),
            Err(ResponseError::Unrelated)
        ));
        let mut offer = response(
            &client,
            DhcpV6MessageType::Advertise,
            [3, 2, 1],
            &SERVER_ID,
            client.iaid,
            60,
            120,
        );
        assert!(matches!(
            client.receive(payload(&offer), SERVER, 1000),
            Err(ResponseError::Unrelated)
        ));
        offer[1..4].copy_from_slice(&XID);
        assert!(matches!(
            client.receive(payload(&offer), SERVER, 1000),
            Err(ResponseError::PrepareRequest(_))
        ));
        offer.push(0);
        assert!(matches!(
            client.receive(payload(&offer), SERVER, 1000),
            Err(ResponseError::Malformed)
        ));
        assert_eq!(client.snapshot().0, DhcpV6State::SolicitSent);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    pub fn test_requesting_retransmit_exhaustion_goes_to_init() {
        let client = interface();
        let mut request = requesting();
        if let Phase::Requesting { exchange, .. } = &mut request {
            exchange.attempts = DhcpV6Client::MAX_RETRIES;
        }
        *phase(&client) = request;
        client.check_timeout(60_000).unwrap();
        assert_eq!(client.snapshot().0, DhcpV6State::Init);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    pub fn test_bound_to_renewing_and_rebinding_transitions() {
        let client = interface();
        set_up(&client);
        *phase(&client) = requesting();
        let reply = response(
            &client,
            DhcpV6MessageType::Reply,
            XID,
            &SERVER_ID,
            client.iaid,
            60,
            120,
        );
        client.receive(payload(&reply), SERVER, 1000).unwrap();
        let Phase::Bound(binding) = core::mem::replace(&mut *phase(&client), Phase::Init) else {
            panic!("applied lease");
        };
        *phase(&client) = Phase::Renewing(exchange(), binding);
        let other = response(
            &client,
            DhcpV6MessageType::Reply,
            XID,
            &OTHER_ID,
            client.iaid,
            60,
            120,
        );
        assert!(matches!(
            client.receive(payload(&other), SERVER, 1001),
            Err(ResponseError::Unrelated)
        ));
        let Phase::Renewing(_, binding) = core::mem::replace(&mut *phase(&client), Phase::Init)
        else {
            panic!("pending renewal");
        };
        *phase(&client) = Phase::Rebinding(exchange(), binding);
        client.receive(payload(&other), SERVER, 1002).unwrap();
        let phase = phase(&client);
        assert_eq!(phase.binding().unwrap().server.id.as_bytes(), OTHER_ID);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    fn failed_lease_application_preserves_the_exchange() {
        let client = interface();
        *phase(&client) = requesting();
        let bytes = response(
            &client,
            DhcpV6MessageType::Reply,
            XID,
            &SERVER_ID,
            client.iaid,
            60,
            120,
        );

        assert!(matches!(
            client.receive(payload(&bytes), SERVER, 1000),
            Err(ResponseError::ApplyLease(_))
        ));
        assert_eq!(client.snapshot().0, DhcpV6State::Requesting);
        assert!(client.snapshot().1.is_none());

        set_up(&client);
        client.receive(payload(&bytes), SERVER, 1001).unwrap();
        assert_eq!(client.snapshot().0, DhcpV6State::Bound);
        assert_eq!(client.snapshot().1.unwrap().obtained_at, 1001);
    }

    #[cfg(all(feature = "qemu-test-export", target_os = "none"))]
    pub fn test_solicit_advertise_request_reply_complete_flow() {
        failed_lease_application_preserves_the_exchange();
        let client = interface();
        assign_link_local(&client);
        let now = crate::task::current_tick() + 1000;
        client.check_timeout(now).expect("SOLICIT admission");
        let solicit_xid = match &*phase(&client) {
            Phase::Soliciting(exchange) => exchange.xid,
            _ => panic!("SOLICIT exchange"),
        };
        let offer = response(
            &client,
            DhcpV6MessageType::Advertise,
            solicit_xid,
            &SERVER_ID,
            client.iaid,
            60,
            120,
        );
        client
            .receive(payload(&offer), SERVER, now + 1)
            .expect("REQUEST admission");
        let request_xid = match &*phase(&client) {
            Phase::Requesting { exchange, .. } => exchange.xid,
            _ => panic!("REQUEST exchange"),
        };
        let reply = response(
            &client,
            DhcpV6MessageType::Reply,
            request_xid,
            &SERVER_ID,
            client.iaid,
            60,
            120,
        );
        client
            .receive(payload(&reply), SERVER, now + 2)
            .expect("apply REPLY");
        assert_eq!(client.snapshot().0, DhcpV6State::Bound);
    }

    #[cfg(all(feature = "qemu-test-export", not(target_os = "none")))]
    pub fn test_solicit_advertise_request_reply_complete_flow() {
        failed_lease_application_preserves_the_exchange();
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    pub fn test_renew_uses_known_server_address_for_dst() {
        let client = interface();
        let server = server(&SERVER_ID);
        let binding = Binding {
            server,
            lease: DhcpV6Lease {
                addr: ADDRESS,
                preferred_lifetime: 60,
                valid_lifetime: 120,
                t1: 30,
                t2: 48,
                obtained_at: 1000,
            },
        };
        let renew = ClientMessage::Renew(&binding);
        let rebind = ClientMessage::Rebind(&binding);
        assert_eq!(renew.server().unwrap().address, SERVER);
        assert!(rebind.server().is_none());
        let mut bytes = [0; 256];
        client.encode(&mut bytes, &exchange(), &renew);
        assert_eq!(bytes[0], 5);
        assert_eq!(&bytes[22..28], &SERVER_ID);
        client.encode(&mut bytes, &exchange(), &rebind);
        assert_eq!(bytes[0], 6);
        assert_eq!(&bytes[18..22], &[0, 3, 0, 40]);
    }
}
