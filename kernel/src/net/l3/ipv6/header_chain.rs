use super::{
    EXT_HEADER_DESTINATION, EXT_HEADER_FRAGMENT, EXT_HEADER_HOP_BY_HOP, EXT_HEADER_ROUTING,
    Ipv6FragmentHeader, MAX_EXTENSION_HEADERS,
};
use crate::net::l3::ipv4::IpProtocol;
use crate::net::payload::PayloadSpanRef;

#[derive(Clone, Copy)]
pub(crate) enum Ipv6PacketBytes<'a> {
    Contiguous(&'a [u8]),
    Segmented(PayloadSpanRef<'a>),
}

impl Ipv6PacketBytes<'_> {
    fn len(self) -> usize {
        match self {
            Self::Contiguous(bytes) => bytes.len(),
            Self::Segmented(span) => span.total_len(),
        }
    }

    fn read<const N: usize>(self, offset: usize) -> Option<[u8; N]> {
        match self {
            Self::Contiguous(bytes) => bytes.get(offset..offset.checked_add(N)?)?.try_into().ok(),
            Self::Segmented(span) => span.read_array(offset),
        }
    }
}

pub(crate) enum Ipv6HeaderChain {
    UpperLayer {
        protocol: IpProtocol,
        offset: usize,
        len: usize,
        next_header_pointer: u32,
    },
    Fragment {
        header: Ipv6FragmentHeader,
        header_offset: usize,
        payload_len: usize,
    },
    Discard,
    ParameterProblem {
        code: u8,
        pointer: u32,
        allow_multicast_dst: bool,
    },
}

impl Ipv6HeaderChain {
    /// Resolve offsets against the IPv6 Payload Length, including when
    /// extension or transport headers cross packet segments.
    pub(crate) fn parse(bytes: Ipv6PacketBytes<'_>) -> Self {
        let Some([version, _, _, _, len_hi, len_lo, mut next_header]) = bytes.read(0) else {
            return Self::Discard;
        };
        let end = 40 + usize::from(u16::from_be_bytes([len_hi, len_lo]));
        if version >> 4 != 6 || end > bytes.len() {
            return Self::Discard;
        }

        let mut offset = 40;
        let mut next_header_pointer = 6;
        let mut saw_fragment = false;
        for _ in 0..MAX_EXTENSION_HEADERS {
            match next_header {
                EXT_HEADER_HOP_BY_HOP | EXT_HEADER_ROUTING | EXT_HEADER_DESTINATION => {
                    if next_header == EXT_HEADER_HOP_BY_HOP && offset != 40 {
                        return Self::Discard;
                    }
                    let Some([following, units]) = bytes.read(offset).filter(|_| offset + 2 <= end)
                    else {
                        return Self::Discard;
                    };
                    let length = (usize::from(units) + 1) * 8;
                    if offset + length > end {
                        return Self::Discard;
                    }
                    if next_header == EXT_HEADER_ROUTING && bytes.read(offset + 2) == Some([0]) {
                        return Self::Discard;
                    }
                    if matches!(next_header, EXT_HEADER_HOP_BY_HOP | EXT_HEADER_DESTINATION)
                        && let Err(action) = Self::check_options(bytes, offset + 2, offset + length)
                    {
                        return action;
                    }
                    next_header_pointer = offset as u32;
                    next_header = following;
                    offset += length;
                }
                EXT_HEADER_FRAGMENT => {
                    if saw_fragment || offset + Ipv6FragmentHeader::SIZE > end {
                        return Self::Discard;
                    }
                    let Some(header) = bytes
                        .read::<{ Ipv6FragmentHeader::SIZE }>(offset)
                        .and_then(|raw| Ipv6FragmentHeader::parse(&raw))
                    else {
                        return Self::Discard;
                    };
                    if header.next_header == EXT_HEADER_FRAGMENT {
                        return Self::Discard;
                    }
                    if header.fragment_offset != 0 || header.more_fragments {
                        return Self::Fragment {
                            header,
                            header_offset: offset,
                            payload_len: end - offset - Ipv6FragmentHeader::SIZE,
                        };
                    }
                    saw_fragment = true;
                    next_header_pointer = offset as u32;
                    next_header = header.next_header;
                    offset += Ipv6FragmentHeader::SIZE;
                }
                _ => {
                    return Self::UpperLayer {
                        protocol: IpProtocol::from(next_header),
                        offset,
                        len: end - offset,
                        next_header_pointer,
                    };
                }
            }
        }
        Self::Discard
    }

    fn check_options(
        bytes: Ipv6PacketBytes<'_>,
        mut offset: usize,
        end: usize,
    ) -> Result<(), Self> {
        // LOOP_PROOF: mode=bounded; reason=Each validated option advances offset within the extension or returns a disposition.;
        while offset < end {
            let [option] = bytes.read(offset).ok_or(Self::Discard)?;
            if option == 0 {
                offset += 1;
                continue;
            }
            let [len] = bytes.read(offset + 1).ok_or(Self::Discard)?;
            let next_offset = offset + 2 + usize::from(len);
            if next_offset > end {
                return Err(Self::Discard);
            }
            match option >> 6 {
                0 => {}
                1 => return Err(Self::Discard),
                action => {
                    return Err(Self::ParameterProblem {
                        code: 2,
                        pointer: offset as u32,
                        allow_multicast_dst: action == 2,
                    });
                }
            }
            offset = next_offset;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::l4::test_support::packet_fixture_with_data;
    use kernel_api::resource::net::PacketPayload;

    #[test]
    fn resolves_the_transport_window_across_ipv6_packet_segments() {
        let mut packet = [0; 59];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = EXT_HEADER_DESTINATION;
        packet[40] = u8::from(IpProtocol::Udp);
        let payload = PacketPayload::try_pair(
            packet_fixture_with_data(&packet[..41]),
            packet_fixture_with_data(&packet[41..]),
        )
        .expect("segmented IPv6 payload");
        for bytes in [
            Ipv6PacketBytes::Contiguous(&packet),
            Ipv6PacketBytes::Segmented(PayloadSpanRef::from_payload(&payload)),
        ] {
            assert!(matches!(
                Ipv6HeaderChain::parse(bytes),
                Ipv6HeaderChain::UpperLayer {
                    protocol: IpProtocol::Udp,
                    offset: 48,
                    len: 8,
                    next_header_pointer: 40,
                }
            ));
        }

        packet[41] = 2;
        assert!(matches!(
            Ipv6HeaderChain::parse(Ipv6PacketBytes::Contiguous(&packet)),
            Ipv6HeaderChain::Discard
        ));
    }
}
