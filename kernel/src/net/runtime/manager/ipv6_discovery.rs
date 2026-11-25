//! Learned IPv6 routes and address admission belong to the interface topology.
use super::*;
use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv6::address_state::{
    AddressLifetimes, DadState, Ipv6AddressOrigin, Ipv6AddressSet, LearnedIpv6Address,
    MAX_IPV6_ADDRESSES, expiration_at,
};
use crate::net::l3::ndp::NdpOption;

const MAX_ON_LINK_PREFIXES: usize = 8;
const MAX_ADVERTISED_ROUTERS: usize = 4;
const DAD_RETRANS_TIMER_MS: u64 = 1000;
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Ipv6Discovery {
    addresses: [Option<LearnedIpv6Address>; MAX_IPV6_ADDRESSES],
    prefixes: [Option<OnLinkPrefix>; MAX_ON_LINK_PREFIXES],
    routers: [Option<AdvertisedRouter>; MAX_ADVERTISED_ROUTERS],
    now: u64,
}

fn update_slot<T: Copy>(
    slots: &mut [Option<T>],
    matches: impl Fn(T) -> bool,
    entry: Option<T>,
) -> Result<(), NetworkError> {
    if let Some(index) = slots.iter().position(|slot| slot.is_some_and(&matches)) {
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
    pub(super) fn suspend_dad(&mut self) {
        for address in self.addresses.iter_mut().flatten() {
            if matches!(
                address.dad,
                DadState::Submitting(_) | DadState::Probing { .. }
            ) {
                address.dad = DadState::AwaitingProbe;
            }
        }
    }

    pub(super) fn snapshot(&self) -> Ipv6AddressSet {
        Ipv6AddressSet {
            entries: self
                .addresses
                .map(|entry| entry.and_then(|address| address.snapshot(self.now))),
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
            .find(|entry| entry.address == address && entry.origin == origin)
            .copied();
        if let Some(old) = old.filter(|_| origin == Ipv6AddressOrigin::Slaac) {
            lifetimes = lifetimes.refresh_slaac(old.lifetimes, self.now);
        }
        let dad = old
            .or_else(|| {
                self.addresses
                    .iter()
                    .flatten()
                    .find(|entry| entry.address == address)
                    .copied()
            })
            .map_or(DadState::AwaitingProbe, |entry| entry.dad);
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

    fn transition_dad(&mut self, address: Ipv6Address, event: DadEvent) -> bool {
        let mut changed = false;
        for entry in self
            .addresses
            .iter_mut()
            .flatten()
            .filter(|entry| entry.address == address)
        {
            entry.dad = match (entry.dad, event) {
                (DadState::AwaitingProbe, DadEvent::Reserve(nonce)) => DadState::Submitting(nonce),
                (DadState::Submitting(nonce), DadEvent::Submitted(now)) => DadState::Probing {
                    nonce,
                    until: now.saturating_add(DAD_RETRANS_TIMER_MS),
                },
                (DadState::Submitting(_), DadEvent::Rejected) => DadState::AwaitingProbe,
                (
                    DadState::Submitting(nonce) | DadState::Probing { nonce, .. },
                    DadEvent::Conflict {
                        received_nonce: Some(received),
                    },
                ) if nonce == received => continue,
                (
                    DadState::AwaitingProbe | DadState::Submitting(_) | DadState::Probing { .. },
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

#[derive(Clone, Copy)]
pub(crate) enum DadEvent {
    Reserve([u8; 6]),
    Submitted(u64),
    Rejected,
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
        let old = interface.ipv6_discovery;
        let routes_changed = old.prefixes != state.prefixes || old.routers != state.routers;
        let changed = routes_changed || old.snapshot() != state.snapshot();
        if routes_changed {
            self.routes_v6
                .try_reserve(MAX_LEARNED_ROUTES)
                .map_err(|_| NetworkError::ResourceExhausted)?;
        }
        interface.ipv6_discovery = state;
        if routes_changed {
            self.refresh_managed_ipv6_routes(if_id, config, state);
            self.sort_ipv6_routes();
        }
        Ok(if changed {
            TopologyChange::Changed
        } else {
            TopologyChange::Unchanged
        })
    }

    pub(super) fn refresh_managed_ipv6_routes(
        &mut self,
        if_id: NetIfId,
        config: NetworkConfig,
        state: Ipv6Discovery,
    ) {
        Self::replace_ipv6_routes(&mut self.routes_v6, if_id, config, state);
    }

    fn replace_ipv6_routes(
        routes: &mut Vec<Ipv6Route>,
        if_id: NetIfId,
        config: NetworkConfig,
        state: Ipv6Discovery,
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
        Ok((config, iface.ipv6_discovery))
    }

    pub(super) fn maintain_ipv6(&mut self, now: u64) -> TopologyChange {
        let mut routes_changed = false;
        let mut changed = false;
        for (&id, iface) in &mut self.interfaces {
            let Some(config) = iface.config.filter(|cfg| cfg.ipv6.is_some()) else {
                continue;
            };
            let old = iface.ipv6_discovery;
            iface.ipv6_discovery.advance(now);
            let current = iface.ipv6_discovery;
            if old.routers != current.routers || old.prefixes != current.prefixes {
                Self::replace_ipv6_routes(&mut self.routes_v6, id, config, current);
                routes_changed = true;
            }
            changed |= old.snapshot() != current.snapshot();
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

    #[test]
    fn router_prefix_and_address_lifetimes_are_independent() {
        let mut manager = NetworkManager::new();
        let id = manager
            .register_interface("ipv6", PrimaryPreference::Auto)
            .unwrap();
        let mut config = NetworkConfig::default();
        config.ipv6 = Some(Ipv6Config::from_mac(config.mac.as_bytes()));
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
        assert!(discovery.transition_dad(address, DadEvent::Reserve([1; 6])));
        assert!(discovery.transition_dad(address, DadEvent::Submitted(100)));
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
            addresses(&manager).entries[0].unwrap().state,
            LocalAddressState::Deprecated
        );
        manager.maintain_ipv6(4100);
        assert!(manager.ipv6_path(InterfaceScope::Any, on_link).is_err());
        assert!(addresses(&manager).for_destination(address));
        manager.maintain_ipv6(5100);
        assert!(!addresses(&manager).for_destination(address));
    }

    #[test]
    fn duplicate_address_cannot_become_assigned_after_probe_timeout() {
        let mut discovery = Ipv6Discovery::default();
        let address = Ipv6Address::new([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let lifetimes = AddressLifetimes::new(0, 10, 20).unwrap();
        discovery
            .stage_address(address, Ipv6AddressOrigin::Dhcp, lifetimes)
            .unwrap();
        assert!(discovery.transition_dad(address, DadEvent::Reserve([0; 6])));
        assert!(discovery.transition_dad(address, DadEvent::Rejected));
        discovery.advance(DAD_RETRANS_TIMER_MS);
        assert!(discovery.snapshot().assigned().next().is_none());
        assert!(discovery.transition_dad(address, DadEvent::Reserve([1; 6])));
        assert!(discovery.transition_dad(address, DadEvent::Submitted(DAD_RETRANS_TIMER_MS)));
        assert!(discovery.transition_dad(
            address,
            DadEvent::Conflict {
                received_nonce: None
            }
        ));
        discovery.advance(DAD_RETRANS_TIMER_MS * 2);
        assert!(!discovery.snapshot().for_destination(address));
        assert!(
            !discovery
                .snapshot()
                .for_destination(address.solicited_node())
        );
    }
}
