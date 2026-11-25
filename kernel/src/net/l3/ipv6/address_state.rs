use super::Ipv6Address;

pub(crate) const MAX_IPV6_ADDRESSES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalAddressState {
    AwaitingProbe,
    Tentative,
    Preferred,
    Deprecated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalIpv6Address {
    pub(crate) address: Ipv6Address,
    pub(crate) state: LocalAddressState,
}

impl LocalIpv6Address {
    pub(crate) fn assigned(self) -> bool {
        matches!(
            self.state,
            LocalAddressState::Preferred | LocalAddressState::Deprecated
        )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ipv6AddressSet {
    pub(crate) entries: [Option<LocalIpv6Address>; MAX_IPV6_ADDRESSES],
}

impl Ipv6AddressSet {
    pub(crate) fn assigned(&self) -> impl Iterator<Item = Ipv6Address> + '_ {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.assigned())
            .map(|entry| entry.address)
    }

    pub(crate) fn source(&self) -> Option<Ipv6Address> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.state == LocalAddressState::Preferred)
            .map(|entry| entry.address)
            .or_else(|| self.assigned().next())
    }

    pub(crate) fn for_destination(&self, destination: Ipv6Address) -> bool {
        self.entries.iter().flatten().any(|entry| {
            (entry.assigned() && destination == entry.address)
                || destination == entry.address.solicited_node()
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ipv6AddressOrigin {
    Slaac,
    Dhcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressLifetimes {
    pub(crate) preferred_until: u64,
    pub(crate) valid_until: u64,
}

impl AddressLifetimes {
    pub(crate) fn new(now: u64, preferred_secs: u32, valid_secs: u32) -> Option<Self> {
        (preferred_secs <= valid_secs).then(|| Self {
            preferred_until: expiration_at(now, preferred_secs),
            valid_until: expiration_at(now, valid_secs),
        })
    }

    pub(crate) fn refresh_slaac(mut self, previous: Self, now: u64) -> Self {
        // RFC 4862 section 5.5.3(e) limits a reduction from an unauthenticated RA.
        const TWO_HOURS_MS: u64 = 2 * 60 * 60 * 1000;
        let remaining = previous.valid_until.saturating_sub(now);
        let advertised = self.valid_until.saturating_sub(now);
        if advertised <= TWO_HOURS_MS && advertised <= remaining {
            self.valid_until = if remaining <= TWO_HOURS_MS {
                previous.valid_until
            } else {
                now.saturating_add(TWO_HOURS_MS)
            };
        }
        self
    }
}

pub(crate) fn expiration_at(now: u64, seconds: u32) -> u64 {
    if seconds == u32::MAX {
        u64::MAX
    } else {
        now.saturating_add(u64::from(seconds) * 1000)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DadState {
    AwaitingProbe,
    Submitting([u8; 6]),
    Probing { nonce: [u8; 6], until: u64 },
    Assigned,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LearnedIpv6Address {
    pub(crate) address: Ipv6Address,
    pub(crate) origin: Ipv6AddressOrigin,
    pub(crate) lifetimes: AddressLifetimes,
    pub(crate) dad: DadState,
}

impl LearnedIpv6Address {
    pub(crate) fn tick(&mut self, now: u64) {
        if matches!(self.dad, DadState::Probing { until, .. } if now >= until) {
            self.dad = DadState::Assigned;
        }
    }

    pub(crate) fn snapshot(self, now: u64) -> Option<LocalIpv6Address> {
        let state = match self.dad {
            DadState::AwaitingProbe => LocalAddressState::AwaitingProbe,
            DadState::Submitting(_) | DadState::Probing { .. } => LocalAddressState::Tentative,
            DadState::Assigned if now < self.lifetimes.preferred_until => {
                LocalAddressState::Preferred
            }
            DadState::Assigned => LocalAddressState::Deprecated,
            DadState::Duplicate => return None,
        };
        Some(LocalIpv6Address {
            address: self.address,
            state,
        })
    }
}
