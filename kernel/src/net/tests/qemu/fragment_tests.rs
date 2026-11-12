// ============================================================================
// kernel/src/net/tests/qemu/fragment_tests.rs - IP reassembly budgets and timer
// ============================================================================

use crate::net::l3::ipv4::{FragmentBuffer, FragmentReassembler, Ipv4Address, Ipv4Header};
use crate::net::l3::ipv6::Ipv6ReassemblyError;
use crate::net::l3::ipv6::fragment::Ipv6FragmentBuffer;
use crate::net::l3::ipv6::{Ipv6Address, Ipv6FragmentHeader, Ipv6FragmentReassembler};
use crate::net::payload::GeneratedPacketWriter;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

const UDP: u8 = 17;
const FRAGMENT_BYTES: usize = 8;
/// IPv4 and IPv6 both use a 60 s reassembly timer.
const AFTER_TIMEOUT_MS: u64 = 60_001;

fn payload(len: usize) -> PacketPayload {
    let mut writer =
        GeneratedPacketWriter::new(len, DEFAULT_PACKET_HEADROOM).expect("fragment allocation");
    writer
        .write_generated_bytes(&[0xA5; 64][..len])
        .expect("fragment write");
    writer.finish().expect("fragment payload is exact")
}

fn ipv4_header(src: [u8; 4], id: u16, offset_units: u16, more_fragments: bool) -> Ipv4Header {
    let mut header = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: [0, 0],
        identification: [0, 0],
        flags_fragment: [0, 0],
        ttl: 64,
        protocol: UDP,
        checksum: [0, 0],
        src_addr: src,
        dst_addr: [10, 0, 0, 1],
    };
    header.set_identification(id);
    header.set_fragmentation(false, more_fragments, offset_units);
    header
}

fn ipv4_fragment(
    reassembler: &mut FragmentReassembler,
    src: [u8; 4],
    id: u16,
    index: u16,
    now: u64,
) -> Option<PacketPayload> {
    let header = ipv4_header(src, id, index, true);
    reassembler.process_fragment(&header, payload(20), payload(FRAGMENT_BYTES), now)
}

/// A datagram may retain `FragmentBuffer::MAX_FRAGMENTS` fragments; one more
/// discards it, releasing every retained packet.
pub fn ipv4_fragment_count_limit_discards_datagram_smoke() -> bool {
    let mut reassembler = FragmentReassembler::new(FragmentReassembler::DEFAULT_MAX_BUFFERS);
    let limit = u16::try_from(FragmentBuffer::MAX_FRAGMENTS).expect("limit fits offsets");
    for index in 0..limit {
        assert!(ipv4_fragment(&mut reassembler, [10, 0, 0, 2], 1, index, 0).is_none());
    }
    assert_eq!(reassembler.active_buffers(), 1);
    assert!(ipv4_fragment(&mut reassembler, [10, 0, 0, 2], 1, limit, 0).is_none());
    assert_eq!(reassembler.active_buffers(), 0);
    assert_eq!(reassembler.stats().dropped_invalid, 1);
    true
}

/// Fragments retained across datagrams are bounded; the datagram whose
/// fragment would exceed the bound is discarded while the others survive.
pub fn ipv4_held_fragment_budget_bounds_reassembler_smoke() -> bool {
    let mut reassembler = FragmentReassembler::new(FragmentReassembler::DEFAULT_MAX_BUFFERS);
    let per_datagram = u16::try_from(FragmentBuffer::MAX_FRAGMENTS).expect("limit fits");
    let datagrams = FragmentReassembler::MAX_HELD_FRAGMENTS / FragmentBuffer::MAX_FRAGMENTS;
    for id in 0..u16::try_from(datagrams).expect("datagram count fits") {
        for index in 0..per_datagram {
            assert!(ipv4_fragment(&mut reassembler, [10, 0, 0, 3], id, index, 0).is_none());
        }
    }
    assert_eq!(reassembler.active_buffers(), datagrams);

    let overflow_id = u16::try_from(datagrams).expect("id fits");
    assert!(ipv4_fragment(&mut reassembler, [10, 0, 0, 3], overflow_id, 0, 0).is_none());
    assert_eq!(reassembler.active_buffers(), datagrams);
    assert_eq!(reassembler.stats().dropped_limit, 1);
    true
}

/// The timer reclaims datagrams without further fragment arrivals and quotes
/// the first fragment's header plus 8 payload octets for each datagram whose
/// first fragment arrived.
pub fn ipv4_reassembly_timer_reclaims_and_quotes_smoke() -> bool {
    let mut reassembler = FragmentReassembler::new(FragmentReassembler::DEFAULT_MAX_BUFFERS);
    let with_first = [10, 0, 0, 4];
    let without_first = [10, 0, 0, 5];
    assert!(ipv4_fragment(&mut reassembler, with_first, 7, 0, 0).is_none());
    assert!(ipv4_fragment(&mut reassembler, without_first, 8, 3, 0).is_none());
    assert!(reassembler.expire(AFTER_TIMEOUT_MS - 2).is_empty());

    let expired = reassembler.expire(AFTER_TIMEOUT_MS);
    assert_eq!(reassembler.active_buffers(), 0);
    assert_eq!(reassembler.stats().timeouts, 2);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].source, Ipv4Address::new(with_first));
    assert_eq!(expired[0].quoted.total_len(), 20 + 8);
    true
}

fn ipv6_address(last: u8) -> Ipv6Address {
    let mut octets = [0u8; 16];
    octets[0] = 0xfe;
    octets[1] = 0x80;
    octets[15] = last;
    Ipv6Address::new(octets)
}

fn ipv6_fragment(
    reassembler: &mut Ipv6FragmentReassembler,
    src: Ipv6Address,
    identification: u32,
    index: u16,
    now: u64,
) -> Result<Option<PacketPayload>, Ipv6ReassemblyError> {
    let header = Ipv6FragmentHeader {
        next_header: UDP,
        fragment_offset: index,
        more_fragments: true,
        identification,
    };
    let unfragmentable = (index == 0).then(|| payload(40));
    reassembler.process_fragment(
        src,
        ipv6_address(1),
        unfragmentable,
        &header,
        payload(FRAGMENT_BYTES),
        now,
    )
}

/// A datagram exceeding `Ipv6FragmentBuffer::MAX_FRAGMENTS` is discarded with
/// a resource-limit error rather than being misreported as an overlap.
pub fn ipv6_fragment_count_limit_discards_datagram_smoke() -> bool {
    let mut reassembler =
        Ipv6FragmentReassembler::new(Ipv6FragmentReassembler::DEFAULT_MAX_BUFFERS);
    let src = ipv6_address(2);
    let limit = u16::try_from(Ipv6FragmentBuffer::MAX_FRAGMENTS).expect("limit fits offsets");
    for index in 0..limit {
        assert!(matches!(
            ipv6_fragment(&mut reassembler, src, 1, index, 0),
            Ok(None)
        ));
    }
    assert!(matches!(
        ipv6_fragment(&mut reassembler, src, 1, limit, 0),
        Err(Ipv6ReassemblyError::ResourceLimit)
    ));
    assert_eq!(reassembler.active_buffers(), 0);
    true
}

/// The IPv6 timer reclaims datagrams and quotes the unfragmentable part
/// followed by the 8-byte Fragment header of the first fragment.
pub fn ipv6_reassembly_timer_reclaims_and_quotes_smoke() -> bool {
    let mut reassembler =
        Ipv6FragmentReassembler::new(Ipv6FragmentReassembler::DEFAULT_MAX_BUFFERS);
    let with_first = ipv6_address(3);
    assert!(matches!(
        ipv6_fragment(&mut reassembler, with_first, 9, 0, 0),
        Ok(None)
    ));
    assert!(matches!(
        ipv6_fragment(&mut reassembler, ipv6_address(4), 10, 2, 0),
        Ok(None)
    ));

    let expired = reassembler.expire(AFTER_TIMEOUT_MS);
    assert_eq!(reassembler.active_buffers(), 0);
    assert_eq!(reassembler.stats().timeouts, 2);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].source, with_first);
    assert_eq!(expired[0].quoted.total_len(), 40 + 8);
    true
}
