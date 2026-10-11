// ============================================================================
// kernel/src/net/tests/qemu/payload_tests.rs - Packet-backed window ownership
// ============================================================================

use crate::net::payload::{
    MutablePayloadBounds, OwnedPayloadBounds, PayloadRange, PayloadSpanRef,
    alloc_packet_with_headroom,
};
use kernel_api::resource::net::{
    DEFAULT_PACKET_HEADROOM, PacketByteCount, PacketPayload, PacketPayloadFront, PacketRef,
};

pub fn payload_trim_respects_subspan_bounds_smoke() -> bool {
    let payload = PacketPayload::try_pair(
        test_packet_with_contents(b"xx  a"),
        test_packet_with_contents(b"bc \tzz"),
    )
    .expect("nonempty trim input");
    let whole = PayloadSpanRef::from_payload(&payload);
    let selected = whole.subspan(2, 7).expect("bounded whitespace span");
    let trimmed = selected
        .trim_ascii_whitespace()
        .expect("valid trimmed span");
    assert_eq!(trimmed.offset(), 4);
    assert_eq!(trimmed.total_len(), 3);
    assert!(trimmed.eq_bytes(b"abc"));
    let whitespace = whole.subspan(7, 2).expect("whitespace-only span");
    let empty = whitespace
        .trim_ascii_whitespace()
        .expect("empty trimmed span");
    assert!(empty.is_empty());
    assert_eq!(empty.offset(), 9);
    assert!(whole.subspan(usize::MAX, 1).is_none());
    assert!(whole.subspan(10, 2).is_none());
    true
}

fn test_packet_with_contents(bytes: &[u8]) -> PacketRef {
    let mut packet =
        alloc_packet_with_headroom(bytes.len(), DEFAULT_PACKET_HEADROOM).expect("packet");
    packet.data_mut().copy_from_slice(bytes);
    packet
}

fn assert_payload_bytes(payload: &PacketPayload, expected: &[u8]) {
    assert!(PayloadSpanRef::from_payload(payload).eq_bytes(expected));
}

pub fn payload_bound_window_rejects_out_of_bounds_request_smoke() -> bool {
    let payload = PacketPayload::try_single(test_packet_with_contents(b"abcd"))
        .expect("test payload is non-empty");

    let bounds = OwnedPayloadBounds::checked(&payload, 4, 0).expect("empty tail bounds");
    assert!(bounds.take_from(payload).is_some());
    let payload = PacketPayload::try_single(test_packet_with_contents(b"abcd"))
        .expect("test payload is non-empty");
    assert!(PayloadRange::checked(&payload, 5, 0).is_none());
    let payload = PacketPayload::try_single(test_packet_with_contents(b"abcd"))
        .expect("test payload is non-empty");
    assert!(PayloadRange::checked(&payload, 3, 2).is_none());
    true
}

pub fn packet_payload_take_front_splits_single_packet_smoke() -> bool {
    let payload = PacketPayload::try_single(test_packet_with_contents(b"abcdef"))
        .expect("test payload is non-empty");
    let len = PacketByteCount::new(3).expect("non-empty prefix");

    let (front, remainder) = match payload.try_take_front(len).expect("single split") {
        PacketPayloadFront::Prefix { front, remainder } => (front, remainder),
        PacketPayloadFront::Whole(_) => panic!("partial split must produce prefix"),
    };

    assert_payload_bytes(&front, b"abc");
    assert_payload_bytes(&remainder, b"def");
    true
}

pub fn packet_payload_take_front_splits_on_chain_boundary_smoke() -> bool {
    let payload = PacketPayload::try_from_segments(alloc::vec![
        test_packet_with_contents(b"abc"),
        test_packet_with_contents(b"def"),
    ])
    .expect("test segments are non-empty");
    let len = PacketByteCount::new(3).expect("non-empty prefix");

    let (front, remainder) = match payload.try_take_front(len).expect("chain boundary split") {
        PacketPayloadFront::Prefix { front, remainder } => (front, remainder),
        PacketPayloadFront::Whole(_) => panic!("partial split must produce prefix"),
    };

    assert_payload_bytes(&front, b"abc");
    assert_payload_bytes(&remainder, b"def");
    true
}

pub fn packet_payload_take_front_splits_inside_chain_segment_smoke() -> bool {
    let payload = PacketPayload::try_from_segments(alloc::vec![
        test_packet_with_contents(b"abc"),
        test_packet_with_contents(b"defgh"),
    ])
    .expect("test segments are non-empty");
    let len = PacketByteCount::new(5).expect("non-empty prefix");

    let (front, remainder) = match payload.try_take_front(len).expect("middle segment split") {
        PacketPayloadFront::Prefix { front, remainder } => (front, remainder),
        PacketPayloadFront::Whole(_) => panic!("partial split must produce prefix"),
    };

    assert_payload_bytes(&front, b"abcde");
    assert_payload_bytes(&remainder, b"fgh");
    true
}

pub fn owned_payload_window_takes_bounds_from_same_payload_smoke() -> bool {
    let source = PacketPayload::try_single(test_packet_with_contents(b"abcdef"))
        .expect("test payload is non-empty");

    let bounds = OwnedPayloadBounds::checked(&source, 3, 3).expect("same-payload bounds");
    let taken = bounds
        .take_from(source)
        .expect("same-payload owned bounds")
        .into_payload()
        .expect("same-payload bounds are valid");

    assert_payload_bytes(&taken, b"def");
    true
}

pub fn payload_span_mut_mutates_only_checked_range_smoke() -> bool {
    let mut payload = PacketPayload::try_pair(
        test_packet_with_contents(b"abcd"),
        test_packet_with_contents(b"efgh"),
    )
    .expect("test segments are non-empty");
    let bounds = MutablePayloadBounds::checked(&payload, 2, 4).expect("cross-segment bounds");
    let mut span = bounds.open(&mut payload).expect("mutable span");

    span.for_each_chunk_mut(|chunk| {
        for byte in chunk {
            *byte = byte.to_ascii_uppercase();
        }
    });

    assert_payload_bytes(&payload, b"abCDEFgh");
    true
}

pub fn owned_payload_window_rejects_bounds_against_target_payload_smoke() -> bool {
    let shorter_payload = PacketPayload::try_single(test_packet_with_contents(b"xy"))
        .expect("test payload is non-empty");

    assert!(
        PayloadRange::checked(&shorter_payload, 3, 3).is_none(),
        "bounds are validated against the consumed payload"
    );
    true
}
