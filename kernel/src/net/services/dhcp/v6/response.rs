use super::types::{DhcpV6Lease, DhcpV6MessageType};
use crate::net::l3::ipv6::{Ipv6Address, address_state::AddressLifetimes};
use crate::net::payload::{FixedPayloadBytes, PayloadSpanRef};
use crate::net::services::dns::{DNS_MAX_SEARCH_DOMAINS, DnsNormalizedName};
use crate::net::types::NetworkError;
use alloc::{string::String, vec::Vec};
use kernel_api::resource::net::PacketPayload;

#[derive(Debug)]
pub(crate) enum ResponseError {
    Malformed,
    Unrelated,
    Status(u16),
    NoUsableAddress,
    StateUnavailable,
    PrepareRequest(&'static str),
    ApplyLease(NetworkError),
}

impl core::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed response"),
            Self::Unrelated => f.write_str("no matching exchange"),
            Self::Status(code) => write!(f, "server returned status {code}"),
            Self::NoUsableAddress => f.write_str("no usable address for our IAID"),
            Self::StateUnavailable => f.write_str("client state unavailable"),
            Self::PrepareRequest(error) => write!(f, "could not submit REQUEST: {error}"),
            Self::ApplyLease(error) => write!(f, "could not stage lease: {error:?}"),
        }
    }
}

pub(super) struct ServerId(FixedPayloadBytes<130>);

impl ServerId {
    pub(super) fn parse(value: PayloadSpanRef<'_>) -> Result<Self, ResponseError> {
        let len = value.total_len();
        if len < 3 {
            return Err(ResponseError::Malformed);
        }
        value
            .read_fixed_bytes(len)
            .map(Self)
            .ok_or(ResponseError::Malformed)
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(super) enum Response {
    Advertise {
        xid: [u8; 3],
        server: ServerId,
        address: Ipv6Address,
    },
    Reply {
        xid: [u8; 3],
        server: ServerId,
        lease: DhcpV6Lease,
        lifetimes: AddressLifetimes,
        dns_servers: Vec<Ipv6Address>,
        domain_search: Vec<DnsNormalizedName>,
    },
}

impl Response {
    pub(super) fn kind(&self) -> DhcpV6MessageType {
        match self {
            Self::Advertise { .. } => DhcpV6MessageType::Advertise,
            Self::Reply { .. } => DhcpV6MessageType::Reply,
        }
    }

    pub(super) fn xid(&self) -> [u8; 3] {
        match self {
            Self::Advertise { xid, .. } | Self::Reply { xid, .. } => *xid,
        }
    }

    pub(super) fn server(&self) -> &ServerId {
        match self {
            Self::Advertise { server, .. } | Self::Reply { server, .. } => server,
        }
    }

    pub(super) fn parse(
        payload: &PacketPayload,
        duid: &[u8],
        iaid: u32,
        now: u64,
    ) -> Result<Self, ResponseError> {
        use ResponseError::{Malformed, NoUsableAddress, Unrelated};
        let span = PayloadSpanRef::from_payload(payload);
        let [kind, a, b, c] = span.read_array::<4>(0).ok_or(Malformed)?;
        let reply = match kind {
            2 => false,
            7 => true,
            _ => return Err(Unrelated),
        };
        let xid = [a, b, c];
        let mut options = Options(span.subspan(4, span.total_len() - 4).ok_or(Malformed)?);
        let mut client_matches = false;
        let mut server = None;
        let mut ia = None;
        let mut matched_ia = false;
        let mut status = None;
        let mut dns_servers = Vec::new();
        let mut domain_search = Vec::new();

        // LOOP_PROOF: mode=condition; reason=Options::next consumes a checked four-byte header and value per iteration.;
        while let Some((code, value)) = options.next()? {
            match code {
                1 if !client_matches => {
                    if !value.eq_bytes(duid) {
                        return Err(Unrelated);
                    }
                    client_matches = true;
                }
                2 if server.is_none() => server = Some(ServerId::parse(value)?),
                3 => {
                    if u32::from_be_bytes(value.read_array::<4>(0).ok_or(Malformed)?) == iaid {
                        if matched_ia {
                            return Err(Malformed);
                        }
                        matched_ia = true;
                        ia = parse_ia(value, now)?;
                    }
                }
                13 if status.is_none() => status = Some(status_code(value)?),
                23 if reply => {
                    if value.total_len() % 16 != 0 {
                        return Err(Malformed);
                    }
                    for offset in (0..value.total_len()).step_by(16) {
                        if dns_servers.len() == 8 {
                            break;
                        }
                        dns_servers.push(Ipv6Address::new(
                            value.read_array::<16>(offset).ok_or(Malformed)?,
                        ));
                    }
                }
                24 if reply => parse_search_domains(value, &mut domain_search)?,
                1 | 2 | 13 => return Err(Malformed),
                _ => {}
            }
        }

        if !client_matches {
            return Err(Unrelated);
        }
        let server = server.ok_or(Malformed)?;
        if let Some(code) = status.filter(|code| *code != 0) {
            return Err(ResponseError::Status(code));
        }
        let (lease, lifetimes) = ia.ok_or(NoUsableAddress)?;
        Ok(if reply {
            Self::Reply {
                xid,
                server,
                lease,
                lifetimes,
                dns_servers,
                domain_search,
            }
        } else {
            Self::Advertise {
                xid,
                server,
                address: lease.addr,
            }
        })
    }
}

struct Options<'a>(PayloadSpanRef<'a>);

impl<'a> Options<'a> {
    fn next(&mut self) -> Result<Option<(u16, PayloadSpanRef<'a>)>, ResponseError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let [hi, lo, lh, ll] = self.0.read_array::<4>(0).ok_or(ResponseError::Malformed)?;
        let len = usize::from(u16::from_be_bytes([lh, ll]));
        let value = self.0.subspan(4, len).ok_or(ResponseError::Malformed)?;
        let consumed = 4 + len;
        self.0 = self
            .0
            .subspan(consumed, self.0.total_len() - consumed)
            .ok_or(ResponseError::Malformed)?;
        Ok(Some((u16::from_be_bytes([hi, lo]), value)))
    }
}

fn status_code(value: PayloadSpanRef<'_>) -> Result<u16, ResponseError> {
    value
        .read_array::<2>(0)
        .map(u16::from_be_bytes)
        .ok_or(ResponseError::Malformed)
}

fn parse_ia(
    ia: PayloadSpanRef<'_>,
    now: u64,
) -> Result<Option<(DhcpV6Lease, AddressLifetimes)>, ResponseError> {
    use ResponseError::Malformed;
    let t1 = u32::from_be_bytes(ia.read_array::<4>(4).ok_or(Malformed)?);
    let t2 = u32::from_be_bytes(ia.read_array::<4>(8).ok_or(Malformed)?);
    let mut options = Options(ia.subspan(12, ia.total_len() - 12).ok_or(Malformed)?);
    let mut address = None;
    let mut status = None;
    // LOOP_PROOF: mode=condition; reason=Each IA suboption consumes a checked header and value.;
    while let Some((code, value)) = options.next()? {
        match code {
            5 => {
                let candidate = parse_address(value, now)?;
                address = address.or(candidate);
            }
            13 if status.is_none() => status = Some(status_code(value)?),
            13 => return Err(Malformed),
            _ => {}
        }
    }
    if let Some(code) = status.filter(|code| *code != 0) {
        return Err(ResponseError::Status(code));
    }
    if t2 != 0 && t1 > t2 {
        return Ok(None);
    }
    Ok(address.map(|(mut lease, lifetimes)| {
        let preferred = lease.preferred_lifetime;
        let default_t2 = (u64::from(preferred) * 8 / 10) as u32;
        lease.t1 = if t1 == 0 {
            (preferred / 2).min(if t2 == 0 { default_t2 } else { t2 })
        } else {
            t1
        };
        lease.t2 = if t2 == 0 {
            default_t2.max(lease.t1)
        } else {
            t2
        };
        (lease, lifetimes)
    }))
}

fn parse_address(
    value: PayloadSpanRef<'_>,
    now: u64,
) -> Result<Option<(DhcpV6Lease, AddressLifetimes)>, ResponseError> {
    use ResponseError::Malformed;
    let addr = Ipv6Address::new(value.read_array::<16>(0).ok_or(Malformed)?);
    let preferred = u32::from_be_bytes(value.read_array::<4>(16).ok_or(Malformed)?);
    let valid = u32::from_be_bytes(value.read_array::<4>(20).ok_or(Malformed)?);
    let mut options = Options(value.subspan(24, value.total_len() - 24).ok_or(Malformed)?);
    let mut status = None;
    // LOOP_PROOF: mode=condition; reason=Each IA Address suboption consumes a checked header and value.;
    while let Some((code, option)) = options.next()? {
        if code == 13 {
            if status.is_some() {
                return Err(Malformed);
            }
            status = Some(status_code(option)?);
        }
    }
    if status.is_some_and(|code| code != 0)
        || valid == 0
        || addr.is_unspecified()
        || addr.is_multicast()
        || addr.is_link_local()
        || addr.is_loopback()
    {
        return Ok(None);
    }
    Ok(
        AddressLifetimes::new(now, preferred, valid).map(|lifetimes| {
            (
                DhcpV6Lease {
                    addr,
                    preferred_lifetime: preferred,
                    valid_lifetime: valid,
                    t1: 0,
                    t2: 0,
                    obtained_at: now,
                },
                lifetimes,
            )
        }),
    )
}

fn parse_search_domains(
    value: PayloadSpanRef<'_>,
    domains: &mut Vec<DnsNormalizedName>,
) -> Result<(), ResponseError> {
    use ResponseError::Malformed;
    let mut offset = 0;
    let mut name = String::new();
    // LOOP_PROOF: mode=bounded; reason=Each iteration consumes a length byte and its checked label.;
    while offset < value.total_len() {
        let len = usize::from(value.byte_at(offset).ok_or(Malformed)?);
        offset += 1;
        if len == 0 {
            let domain = DnsNormalizedName::parse_ascii(&name).ok_or(Malformed)?;
            if domains.len() < DNS_MAX_SEARCH_DOMAINS {
                domains.push(domain);
            }
            name.clear();
            continue;
        }
        if len > 63 || offset + len > value.total_len() || name.len() + len >= 254 {
            return Err(Malformed);
        }
        if !name.is_empty() {
            name.push('.');
        }
        for index in offset..offset + len {
            name.push(char::from(value.byte_at(index).ok_or(Malformed)?));
        }
        offset += len;
    }
    name.is_empty().then_some(()).ok_or(Malformed)
}
