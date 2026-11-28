use super::*;

pub(crate) struct ValidatedNdp(pub(super) Message);

pub(super) enum Message {
    Solicitation {
        target: Ipv6Address,
        source: Ipv6Address,
        mac: Option<[u8; 6]>,
        nonce: Option<[u8; 6]>,
    },
    Advertisement {
        target: Ipv6Address,
        mac: Option<[u8; 6]>,
        solicited: bool,
        override_mac: bool,
    },
    Router {
        source: Ipv6Address,
        lifetime: u16,
        options: Vec<NdpOption>,
    },
}

pub(crate) enum TentativeObservation {
    AddressResolution,
    Conflict { nonce: Option<[u8; 6]> },
}

impl ValidatedNdp {
    /// The ICMPv6 ingress processor verifies the checksum before dispatch.
    pub(crate) fn parse(
        kind: Icmpv6Type,
        payload: &PacketPayload,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: [u8; 6],
        hop_limit: u8,
    ) -> Option<Self> {
        let view = PacketPayloadView::new(payload);
        if hop_limit != 255 || view.read_array::<2>(0)? != [kind.into(), 0] {
            return None;
        }
        let message = match kind {
            Icmpv6Type::NeighborSolicitation | Icmpv6Type::NeighborAdvertisement => {
                let target = Ipv6Address::new(view.read_array::<16>(8)?);
                if target.is_multicast() || target.is_unspecified() || src.is_multicast() {
                    return None;
                }
                if kind == Icmpv6Type::NeighborSolicitation {
                    let (mac, nonce) = neighbor_options(&view, NS_MIN_SIZE, 1, src_mac)?;
                    if src.is_unspecified() && (dst != target.solicited_node() || mac.is_some()) {
                        return None;
                    }
                    Message::Solicitation {
                        target,
                        source: src,
                        mac,
                        nonce,
                    }
                } else {
                    let [flags] = view.read_array::<1>(4)?;
                    let solicited = flags & 0x40 != 0;
                    if src.is_unspecified() || (solicited && dst.is_multicast()) {
                        return None;
                    }
                    let (mac, _) = neighbor_options(&view, NA_MIN_SIZE, 2, src_mac)?;
                    Message::Advertisement {
                        target,
                        mac,
                        solicited,
                        override_mac: flags & 0x20 != 0,
                    }
                }
            }
            Icmpv6Type::RouterAdvertisement if src.is_link_local() => {
                let header = view.read_array::<16>(0)?;
                Message::Router {
                    source: src,
                    lifetime: u16::from_be_bytes([header[6], header[7]]),
                    options: router_options(&view, 16)?,
                }
            }
            _ => return None,
        };
        Some(Self(message))
    }

    pub(crate) fn tentative_observation(&self) -> Option<(Ipv6Address, TentativeObservation)> {
        match self.0 {
            Message::Solicitation {
                target,
                source,
                nonce,
                ..
            } => Some((
                target,
                if source.is_unspecified() {
                    TentativeObservation::Conflict { nonce }
                } else {
                    TentativeObservation::AddressResolution
                },
            )),
            Message::Advertisement { target, .. } => {
                Some((target, TentativeObservation::Conflict { nonce: None }))
            }
            Message::Router { .. } => None,
        }
    }
}

fn walk_options(
    view: &PacketPayloadView<'_>,
    mut offset: usize,
    mut visit: impl FnMut(u8, usize, usize) -> Option<()>,
) -> Option<()> {
    let end = view.total_len();
    // LOOP_PROOF: mode=bounded; reason=Each valid ND option consumes at least eight bytes in the remaining packet.;
    while offset < end {
        let [kind, units] = view.read_array::<2>(offset)?;
        let len = usize::from(units) * 8;
        if len == 0 || len > end - offset {
            return None;
        }
        visit(kind, offset, len)?;
        offset += len;
    }
    Some(())
}

fn neighbor_options(
    view: &PacketPayloadView<'_>,
    start: usize,
    link_layer_option: u8,
    src_mac: [u8; 6],
) -> Option<(Option<[u8; 6]>, Option<[u8; 6]>)> {
    let mut mac = None;
    let mut nonce = None;
    walk_options(view, start, |kind, offset, len| {
        if kind == link_layer_option {
            let supplied = view.read_array::<6>(offset + 2)?;
            if len != 8 || supplied != src_mac {
                return None;
            }
            mac = Some(supplied);
        } else if kind == 14 && len == 8 {
            nonce = Some(view.read_array::<6>(offset + 2)?);
        }
        Some(())
    })?;
    Some((mac, nonce))
}

pub(super) fn router_options(view: &PacketPayloadView<'_>, start: usize) -> Option<Vec<NdpOption>> {
    let mut options = Vec::new();
    walk_options(view, start, |kind, offset, len| {
        let option_type = NdpOptionType::from(kind);
        let option = match option_type {
            NdpOptionType::SourceLinkLayerAddress if len == 8 => NdpOption::LinkLayerAddress {
                option_type,
                mac: view.read_array::<6>(offset + 2)?,
            },
            NdpOptionType::PrefixInformation if len == 32 => {
                let [prefix_len, flags] = view.read_array::<2>(offset + 2)?;
                NdpOption::PrefixInfo {
                    prefix_len,
                    on_link: flags & 0x80 != 0,
                    autonomous: flags & 0x40 != 0,
                    valid_lifetime: u32::from_be_bytes(view.read_array::<4>(offset + 4)?),
                    preferred_lifetime: u32::from_be_bytes(view.read_array::<4>(offset + 8)?),
                    prefix: Ipv6Address::new(view.read_array::<16>(offset + 16)?),
                }
            }
            NdpOptionType::RecursiveDnsServer if len >= 24 && len % 16 == 8 => {
                let lifetime = u32::from_be_bytes(view.read_array::<4>(offset + 4)?);
                let mut servers = Vec::new();
                for addr_offset in (offset + 8..offset + len).step_by(16) {
                    let server = Ipv6Address::new(view.read_array::<16>(addr_offset)?);
                    if server.is_multicast() || server.is_unspecified() {
                        return Some(());
                    }
                    servers.push(server);
                }
                NdpOption::RecursiveDnsServer { lifetime, servers }
            }
            _ => return Some(()),
        };
        options.push(option);
        Some(())
    })?;
    Some(options)
}
