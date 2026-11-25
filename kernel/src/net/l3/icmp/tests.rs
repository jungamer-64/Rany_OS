// ============================================================================
// kernel/src/net/l3/icmp/tests.rs - L3 / ICMP / テスト
// ============================================================================

use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub fn test_icmp_type() {
    assert_eq!(IcmpType::from(8), IcmpType::EchoRequest);
    assert_eq!(IcmpType::from(0), IcmpType::EchoReply);
    assert_eq!(u8::from(IcmpType::EchoRequest), 8);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub fn test_echo_builder() {
    let mut buffer = [0u8; 64];
    let mut builder = IcmpEchoBuilder::new(&mut buffer).unwrap();

    builder.build_request(1234, 1);
    let len = builder.finalize();

    assert_eq!(len, IcmpEchoHeader::SIZE);

    // RFC 792 echo layout: type, code, checksum, identifier, sequence.
    let wire = &buffer[..len];
    assert_eq!(wire[0], u8::from(IcmpType::EchoRequest));
    assert_eq!(wire[1], 0);
    assert_eq!(&wire[4..6], &1234u16.to_be_bytes());
    assert_eq!(&wire[6..8], &1u16.to_be_bytes());
    // The one's-complement sum over a message with a valid checksum is 0xffff.
    let mut sum = 0u32;
    for word in wire.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
    }
    // LOOP_PROOF: mode=condition; reason=Each carry fold decreases the sum until it fits in 16 bits.;
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    assert_eq!(sum, 0xffff);
}
