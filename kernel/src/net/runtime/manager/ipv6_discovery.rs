//! Learned IPv6 routes and address admission belong to the interface topology.
use super::*;
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv6::address_state::{
    AddressLifetimes, DadState, Ipv6AddressOrigin, Ipv6AddressSet, LearnedIpv6Address,
    MAX_IPV6_ADDRESSES, expiration_at,
};
use crate::net::l3::ndp::NdpOption;
use crate::net::runtime::device::tx::TxReceipt;

const MAX_ON_LINK_PREFIXES: usize = 8;
const MAX_ADVERTISED_ROUTERS: usize = 4;
const MAX_RDNSS_SERVERS_PER_LINK: usize = crate::net::services::dns::DNS_MAX_SERVERS;

#[derive(Debug, Clone, Copy)]
struct AdvertisedDns {
    address: Ipv6Address,
    expires_at: u64,
}
const MAX_LEARNED_ROUTES: usize = MAX_ON_LINK_PREFIXES + MAX_ADVERTISED_ROUTERS + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OnLinkPrefix {
    network: Ipv6Address,
    len: u8,
    expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdvertisedRouter {
    address: Ipv6Address,
    expires_at: u64,
}

#[derive(Debug, Default, Clone)]
pub(super) struct Ipv6Discovery {
    addresses: [Option<LearnedIpv6Address>; MAX_IPV6_ADDRESSES],
    prefixes: [Option<OnLinkPrefix>; MAX_ON_LINK_PREFIXES],
    routers: [Option<AdvertisedRouter>; MAX_ADVERTISED_ROUTERS],
    dns: [Option<AdvertisedDns>; MAX_RDNSS_SERVERS_PER_LINK],
    now: u64,
}

fn update_slot<T>(
    slots: &mut [Option<T>],
    matches: impl Fn(&T) -> bool,
    entry: Option<T>,
) -> Result<(), NetworkError> {
    if let Some(index) = slots
        .iter()
        .position(|slot| slot.as_ref().is_some_and(&matches))
    {
        slots[index] = entry;
    } else if entry.is_some() {
        let slot = slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(NetworkError::ResourceExhausted)?;
        *slot = entry;
    }
    Ok(())
}

impl Ipv6Discovery {
    pub(super) fn with_link_local(mac: MacAddress) -> Self {
        let mut discovery = Self::default();
        discovery.addresses[0] = Some(LearnedIpv6Address {
            address: Ipv6Address::from_eui64(mac.as_bytes()),
            origin: Ipv6AddressOrigin::LinkLocal,
            lifetimes: AddressLifetimes {
                preferred_until: u64::MAX,
                valid_until: u64::MAX,
            },
            dad: DadState::AwaitingProbe,
        });
        discovery
    }

    pub(super) fn link_unavailable(&mut self) {
        self.dns.fill(None);
        for address in self.addresses.iter_mut().flatten() {
            address.dad = DadState::AwaitingProbe;
        }
    }

    pub(super) fn snapshot(&self) -> Ipv6AddressSet {
        Ipv6AddressSet {
            entries: core::array::from_fn(|index| {
                self.addresses[index]
                    .as_ref()
                    .and_then(|address| address.snapshot(self.now))
            }),
        }
    }

    fn advance(&mut self, now: u64) {
        self.now = self.now.max(now);
        for slot in &mut self.addresses {
            if let Some(entry) = slot {
                if entry.lifetimes.valid_until <= self.now {
                    *slot = None;
                } else {
                    entry.tick(self.now);
                }
            }
        }
        for prefix in &mut self.prefixes {
            if prefix.is_some_and(|entry| entry.expires_at <= self.now) {
                *prefix = None;
            }
        }
        for dns in &mut self.dns {
            if dns.is_some_and(|entry| entry.expires_at <= self.now) {
                *dns = None;
            }
        }
        for router in &mut self.routers {
            if router.is_some_and(|entry| entry.expires_at <= self.now) {
                *router = None;
            }
        }
    }

    fn stage_address(
        &mut self,
        address: Ipv6Address,
        origin: Ipv6AddressOrigin,
        mut lifetimes: AddressLifetimes,
    ) -> Result<(), NetworkError> {
        let old = self
            .addresses
            .iter()
            .flatten()
            .find(|entry| entry.address == address && entry.origin == origin);
        if let Some(old) = old.filter(|_| origin == Ipv6AddressOrigin::Slaac) {
            lifetimes = lifetimes.refresh_slaac(old.lifetimes, self.now);
        }
        let dad = old
            .or_else(|| {
                self.addresses
                    .iter()
                    .flatten()
                    .find(|entry| entry.address == address)
            })
            .map_or(DadState::AwaitingProbe, |entry| entry.dad.clone());
        let entry = (lifetimes.valid_until > self.now).then_some(LearnedIpv6Address {
            address,
            origin,
            lifetimes,
            dad,
        });
        if origin == Ipv6AddressOrigin::Dhcp && entry.is_some() {
            // A DHCP renewal can replace the IA address. SLAAC entries are independent.
            return update_slot(&mut self.addresses, |old| old.origin == origin, entry);
        }
        update_slot(
            &mut self.addresses,
            |old| old.address == address && old.origin == origin,
            entry,
        )
    }

    fn apply_advertisement(
        &mut self,
        mac: MacAddress,
        router: Ipv6Address,
        router_secs: u16,
        options: &[NdpOption],
        now: u64,
    ) -> Result<(), NetworkError> {
        self.advance(now);
        let advertised = (router_secs != 0)
            .then(|| AdvertisedRouter {
                address: router,
                expires_at: expiration_at(now, u32::from(router_secs)),
            })
            .filter(|entry| entry.expires_at > self.now);
        update_slot(
            &mut self.routers,
            |entry| entry.address == router,
            advertised,
        )?;

        for option in options {
            if let NdpOption::RecursiveDnsServer { lifetime, servers } = option {
                self.update_dns(servers, now, *lifetime);
                continue;
            }
            let NdpOption::PrefixInfo {
                prefix,
                prefix_len,
                on_link,
                autonomous,
                valid_lifetime,
                preferred_lifetime,
            } = *option
            else {
                continue;
            };
            if prefix_len > 128 || prefix.is_link_local() || prefix.is_multicast() {
                continue;
            }
            let network = ipv6_apply_prefix(prefix, prefix_len);
            if on_link {
                let expires_at = expiration_at(now, valid_lifetime);
                let on_link = (expires_at > self.now).then_some(OnLinkPrefix {
                    network,
                    len: prefix_len,
                    expires_at,
                });
                update_slot(
                    &mut self.prefixes,
                    |entry| entry.network == network && entry.len == prefix_len,
                    on_link,
                )?;
            }
            if autonomous
                && prefix_len == 64
                && let Some(lifetimes) =
                    AddressLifetimes::new(now, preferred_lifetime, valid_lifetime)
            {
                let address = Ipv6Address::from_prefix_eui64(&network, mac.as_bytes());
                self.stage_address(address, Ipv6AddressOrigin::Slaac, lifetimes)?;
            }
        }
        Ok(())
    }

    fn update_dns(&mut self, servers: &[Ipv6Address], now: u64, lifetime: u32) {
        let expires_at = expiration_at(now, lifetime);
        for &address in servers {
            if address.is_multicast() || address.is_unspecified() || address.is_loopback() {
                continue;
            }
            let entry = (expires_at > self.now).then_some(AdvertisedDns {
                address,
                expires_at,
            });
            // Retain current entries when the per-link repository is full. A
            // full resolver list does not invalidate the rest of the RA.
            let _capacity = update_slot(&mut self.dns, |old| old.address == address, entry);
        }
    }

    fn advertised_dns(&self, now: u64) -> impl Iterator<Item = Ipv6Address> + '_ {
        self.dns
            .iter()
            .flatten()
            .filter(move |entry| entry.expires_at > now)
            .map(|entry| entry.address)
    }

    fn transition_dad(&mut self, address: Ipv6Address, event: DadEvent) -> bool {
        let mut changed = false;
        for entry in self
            .addresses
            .iter_mut()
            .flatten()
            .filter(|entry| entry.address == address)
        {
            entry.dad = match (&entry.dad, &event) {
                (DadState::AwaitingProbe, DadEvent::Reserve { nonce, receipt }) => {
                    DadState::Submitting {
                        nonce: *nonce,
                        receipt: receipt.clone(),
                    }
                }
                (
                    DadState::Submitting { nonce, .. } | DadState::Probing { nonce, .. },
                    DadEvent::Conflict {
                        received_nonce: Some(received),
                    },
                ) if nonce == received => continue,
                (
                    DadState::AwaitingProbe
                    | DadState::Submitting { .. }
                    | DadState::Probing { .. },
                    DadEvent::Conflict { .. },
                ) => DadState::Duplicate,
                _ => continue,
            };
            changed = true;
        }
        changed
    }

    pub(super) fn append_routes(&self, routes: &mut Vec<Ipv6Route>, if_id: NetIfId) {
        routes.extend(self.prefixes.iter().flatten().map(|prefix| Ipv6Route {
            destination: prefix.network,
            prefix_len: prefix.len,
            gateway: None,
            if_id,
            metric: 0,
            flags: RouteFlags::connected(),
            admin_enabled: true,
            managed_by_interface: true,
        }));
        routes.extend(self.routers.iter().flatten().map(|router| Ipv6Route {
            destination: Ipv6Address::UNSPECIFIED,
            prefix_len: 0,
            gateway: Some(router.address),
            if_id,
            metric: 101,
            flags: RouteFlags {
                default_route: true,
                connected: false,
                static_route: false,
            },
            admin_enabled: true,
            managed_by_interface: true,
        }));
    }
}

pub(crate) enum DadEvent {
    Reserve { nonce: [u8; 6], receipt: TxReceipt },
    Conflict { received_nonce: Option<[u8; 6]> },
}

impl NetworkManager {
    fn publish_discovery(
        &mut self,
        if_id: NetIfId,
        config: NetworkConfig,
        state: Ipv6Discovery,
    ) -> Result<TopologyChange, NetworkError> {
        let interface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::NetworkUnreachable)?;
        let old = &interface.ipv6_discovery;
        let routes_changed = old.prefixes != state.prefixes || old.routers != state.routers;
        let changed = routes_changed || old.snapshot() != state.snapshot();
        if routes_changed {
            self.routes_v6
                .try_reserve(MAX_LEARNED_ROUTES)
                .map_err(|_| NetworkError::ResourceExhausted)?;
        }
        if routes_changed {
            Self::replace_ipv6_routes(&mut self.routes_v6, if_id, config, &state);
        }
        interface.ipv6_discovery = state;
        if routes_changed {
            self.sort_ipv6_routes();
        }
        Ok(if changed {
            TopologyChange::Changed
        } else {
            TopologyChange::Unchanged
        })
    }

    pub(super) fn replace_ipv6_routes(
        routes: &mut Vec<Ipv6Route>,
        if_id: NetIfId,
        config: NetworkConfig,
        state: &Ipv6Discovery,
    ) {
        routes.retain(|route| !(route.if_id == if_id && route.managed_by_interface));
        let Some(ipv6) = config.ipv6 else {
            return;
        };
        if let Some(gateway) = ipv6.gateway {
            routes.push(Ipv6Route {
                destination: Ipv6Address::UNSPECIFIED,
                prefix_len: 0,
                gateway: Some(gateway),
                if_id,
                metric: 100,
                flags: RouteFlags::default_static(),
                admin_enabled: true,
                managed_by_interface: true,
            });
        }
        state.append_routes(routes, if_id);
    }

    pub(super) fn learn_ipv6_ra(
        &mut self,
        if_id: NetIfId,
        router: Ipv6Address,
        router_lifetime: u16,
        options: &[NdpOption],
        now: u64,
    ) -> Result<TopologyChange, NetworkError> {
        let (config, mut state) = self.discovery_config(if_id)?;
        state.apply_advertisement(config.mac, router, router_lifetime, options, now)?;
        self.publish_discovery(if_id, config, state)
    }

    fn discovery_config(
        &self,
        if_id: NetIfId,
    ) -> Result<(NetworkConfig, Ipv6Discovery), NetworkError> {
        let iface = self
            .interfaces
            .get(&if_id)
            .filter(|iface| iface.is_operational())
            .ok_or(NetworkError::NetworkUnreachable)?;
        let config = iface
            .config
            .filter(|cfg| cfg.ipv6.is_some())
            .ok_or(NetworkError::InvalidAddress)?;
        Ok((config, iface.ipv6_discovery.clone()))
    }

    pub(super) fn maintain_ipv6(&mut self, now: u64) -> TopologyChange {
        let mut routes_changed = false;
        let mut changed = false;
        for (&id, iface) in &mut self.interfaces {
            let Some(config) = iface.config.filter(|cfg| cfg.ipv6.is_some()) else {
                continue;
            };
            let old = &iface.ipv6_discovery;
            let (addresses, routers, prefixes) = (old.snapshot(), old.routers, old.prefixes);
            iface.ipv6_discovery.advance(now);
            let current = &iface.ipv6_discovery;
            if routers != current.routers || prefixes != current.prefixes {
                Self::replace_ipv6_routes(&mut self.routes_v6, id, config, current);
                routes_changed = true;
            }
            changed |= addresses != current.snapshot();
        }
        if routes_changed {
            self.sort_ipv6_routes();
        }
        if changed || routes_changed {
            TopologyChange::Changed
        } else {
            TopologyChange::Unchanged
        }
    }
}

pub(crate) fn assigned_ipv6_link_local_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Option<Ipv6Address> {
    with_manager_in(runtime, |manager| {
        manager
            .get_interface(if_id)
            .filter(|iface| iface.is_operational())
            .and_then(|iface| iface.ipv6_discovery.snapshot().link_local())
    })
    .ok()
    .flatten()
}

pub(crate) fn rdnss_servers_in(
    runtime: NetRuntimeHandle,
    now: u64,
) -> Result<Vec<(NetIfId, Ipv6Address)>, NetworkError> {
    with_manager_in(runtime, |manager| {
        let mut servers = Vec::new();
        for iface in manager
            .interfaces
            .values()
            .filter(|iface| iface.is_operational())
        {
            for server in iface.ipv6_discovery.advertised_dns(now) {
                servers
                    .try_reserve(1)
                    .map_err(|_| NetworkError::ResourceExhausted)?;
                servers.push((iface.if_id, server));
            }
        }
        Ok(servers)
    })?
}

pub(crate) fn rdnss_server_live_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    server: Ipv6Address,
    now: u64,
) -> bool {
    with_manager_in(runtime, |manager| {
        manager.get_interface(if_id).is_some_and(|iface| {
            iface.is_operational()
                && iface
                    .ipv6_discovery
                    .advertised_dns(now)
                    .any(|address| address == server)
        })
    })
    .unwrap_or(false)
}

pub(crate) fn learn_ipv6_ra_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    router: Ipv6Address,
    router_lifetime: u16,
    options: &[NdpOption],
    now: u64,
) -> Result<(), NetworkError> {
    mutate_topology_in(runtime, |manager| {
        Ok((
            (),
            manager.learn_ipv6_ra(if_id, router, router_lifetime, options, now)?,
        ))
    })
}

pub(crate) fn stage_dhcp_ipv6_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    address: Ipv6Address,
    lifetimes: AddressLifetimes,
    now: u64,
) -> Result<(), NetworkError> {
    if address.is_unspecified()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_loopback()
    {
        return Err(NetworkError::InvalidAddress);
    }
    mutate_topology_in(runtime, |manager| {
        let (config, mut state) = manager.discovery_config(if_id)?;
        state.advance(now);
        if lifetimes.valid_until <= state.now {
            return Err(NetworkError::Timeout);
        }
        state.stage_address(address, Ipv6AddressOrigin::Dhcp, lifetimes)?;
        Ok(((), manager.publish_discovery(if_id, config, state)?))
    })
}

pub(crate) fn update_ipv6_dad_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    address: Ipv6Address,
    event: DadEvent,
) -> Result<bool, NetworkError> {
    mutate_topology_in(runtime, |manager| {
        let (config, mut state) = manager.discovery_config(if_id)?;
        let updated = state.transition_dad(address, event);
        Ok((updated, manager.publish_discovery(if_id, config, state)?))
    })
}

pub(crate) fn maintain_ipv6_in(runtime: NetRuntimeHandle, now: u64) -> Result<(), NetworkError> {
    mutate_topology_in(runtime, |manager| Ok(((), manager.maintain_ipv6(now))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::l3::ipv6::{Ipv6Config, address_state::LocalAddressState};
    use kernel_api::service::netdev::TxDeviceOutcome;

    #[test]
    fn router_prefix_and_address_lifetimes_are_independent() {
        let mut manager = NetworkManager::new();
        let id = manager
            .register_interface("ipv6", PrimaryPreference::Auto)
            .unwrap();
        let mut config = NetworkConfig::default();
        config.ipv6 = Some(Ipv6Config::default());
        manager.set_interface_config(id, config).unwrap();
        manager.set_link_state(id, LinkState::Up).unwrap();

        let router = Ipv6Address::from_eui64(&[0, 1, 2, 3, 4, 5]);
        let autonomous =
            Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let on_link = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let options = [
            NdpOption::PrefixInfo {
                prefix: autonomous,
                prefix_len: 64,
                on_link: false,
                autonomous: true,
                valid_lifetime: 5,
                preferred_lifetime: 3,
            },
            NdpOption::PrefixInfo {
                prefix: on_link,
                prefix_len: 80,
                on_link: true,
                autonomous: false,
                valid_lifetime: 4,
                preferred_lifetime: 4,
            },
        ];
        manager.learn_ipv6_ra(id, router, 2, &options, 100).unwrap();
        let address = Ipv6Address::from_prefix_eui64(&autonomous, config.mac.as_bytes());
        let addresses = |manager: &NetworkManager| {
            manager.try_active_interfaces().unwrap()[0]
                .config
                .ipv6
                .unwrap()
                .addresses
        };
        assert!(!addresses(&manager).for_destination(address));
        assert!(addresses(&manager).for_destination(address.solicited_node()));
        assert_eq!(
            manager
                .ipv6_path(InterfaceScope::Any, autonomous)
                .unwrap()
                .next_hop,
            router
        );
        assert_eq!(
            manager
                .ipv6_path(InterfaceScope::Pinned(id), on_link)
                .unwrap()
                .next_hop,
            on_link
        );

        let discovery = &mut manager.interfaces.get_mut(&id).unwrap().ipv6_discovery;
        let (receipt, reporter) = TxReceipt::reserve().unwrap();
        assert!(discovery.transition_dad(
            address,
            DadEvent::Reserve {
                nonce: [1; 6],
                receipt
            }
        ));
        reporter.finish(TxDeviceOutcome::Transmitted, 100);
        assert!(!discovery.transition_dad(
            address,
            DadEvent::Conflict {
                received_nonce: Some([1; 6])
            }
        ));
        manager.maintain_ipv6(1099);
        assert!(!addresses(&manager).for_destination(address));
        manager.maintain_ipv6(1100);
        assert_eq!(addresses(&manager).source(), Some(address));
        manager.maintain_ipv6(2100);
        assert_eq!(
            manager.ipv6_path(InterfaceScope::Any, autonomous),
            Err(NetworkError::NetworkUnreachable)
        );
        assert_eq!(addresses(&manager).source(), Some(address));
        manager.maintain_ipv6(3100);
        assert_eq!(
            addresses(&manager)
                .entries
                .into_iter()
                .flatten()
                .find(|entry| entry.address == address)
                .unwrap()
                .state,
            LocalAddressState::Deprecated
        );
        manager.maintain_ipv6(4100);
        assert!(manager.ipv6_path(InterfaceScope::Any, on_link).is_err());
        assert!(addresses(&manager).for_destination(address));
        manager.maintain_ipv6(5100);
        assert!(!addresses(&manager).for_destination(address));
    }

    #[test]
    fn rdnss_lifetime_and_withdrawal_are_link_local() {
        let server = Ipv6Address::from_eui64(&[2, 1, 2, 3, 4, 5]);
        let router = Ipv6Address::from_eui64(&[4, 1, 2, 3, 4, 5]);
        let mac = MacAddress::new([6, 1, 2, 3, 4, 5]);
        let mut first = Ipv6Discovery::with_link_local(mac);
        let mut second = Ipv6Discovery::with_link_local(mac);
        let option = |lifetime| NdpOption::RecursiveDnsServer {
            lifetime,
            servers: alloc::vec![server],
        };
        first
            .apply_advertisement(mac, router, 0, &[option(1)], 100)
            .unwrap();
        second
            .apply_advertisement(mac, router, 0, &[option(10)], 100)
            .unwrap();
        assert_eq!(first.advertised_dns(1099).next(), Some(server));
        assert_eq!(first.advertised_dns(1100).next(), None);
        first
            .apply_advertisement(mac, router, 0, &[option(10)], 1100)
            .unwrap();
        first
            .apply_advertisement(mac, router, 0, &[option(0)], 1200)
            .unwrap();
        assert_eq!(first.advertised_dns(1200).next(), None);
        assert_eq!(second.advertised_dns(1200).next(), Some(server));
        second.link_unavailable();
        assert_eq!(second.advertised_dns(1200).next(), None);
    }

    #[test]
    fn duplicate_address_cannot_become_assigned_after_probe_timeout() {
        let mut discovery = Ipv6Discovery::default();
        let address = Ipv6Address::new([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let lifetimes = AddressLifetimes::new(0, 10, 20).unwrap();
        discovery
            .stage_address(address, Ipv6AddressOrigin::Dhcp, lifetimes)
            .unwrap();
        let (receipt, reporter) = TxReceipt::reserve().unwrap();
        assert!(discovery.transition_dad(
            address,
            DadEvent::Reserve {
                nonce: [0; 6],
                receipt
            }
        ));
        discovery.advance(1000);
        assert!(discovery.snapshot().assigned().next().is_none());
        reporter.finish(TxDeviceOutcome::OutcomeUnknown, 1000);
        discovery.advance(2000);
        assert!(discovery.snapshot().assigned().next().is_none());
        let (receipt, reporter) = TxReceipt::reserve().unwrap();
        assert!(discovery.transition_dad(
            address,
            DadEvent::Reserve {
                nonce: [1; 6],
                receipt
            }
        ));
        reporter.finish(TxDeviceOutcome::Transmitted, 2000);
        assert!(discovery.transition_dad(
            address,
            DadEvent::Conflict {
                received_nonce: None
            }
        ));
        discovery.advance(3000);
        assert!(!discovery.snapshot().for_destination(address));
        assert!(
            !discovery
                .snapshot()
                .for_destination(address.solicited_node())
        );
    }
}
