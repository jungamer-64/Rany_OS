// ============================================================================
// kernel/src/net/l3/icmp/tests.rs - L3 / ICMP / テスト
// ============================================================================

use super::*;

#[cfg_attr(test, test_case)]
pub fn test_icmp_type() {
    assert_eq!(IcmpType::from(8), IcmpType::EchoRequest);
    assert_eq!(IcmpType::from(0), IcmpType::EchoReply);
    assert_eq!(u8::from(IcmpType::EchoRequest), 8);
}

#[cfg_attr(test, test_case)]
pub fn test_echo_builder() {
    let mut buffer = [0u8; 64];
    let mut builder = IcmpEchoBuilder::new(&mut buffer).unwrap();

    builder.build_request(1234, 1);
    let len = builder.finalize();

    assert_eq!(len, IcmpEchoHeader::SIZE);

    // Verify we can parse it back
    let packet = IcmpPacket::parse(&buffer[..len]).unwrap();
    assert_eq!(packet.icmp_type(), IcmpType::EchoRequest);
    assert!(packet.verify_checksum());

    let echo = packet.as_echo().unwrap();
    assert_eq!(echo.identifier(), 1234);
    assert_eq!(echo.sequence(), 1);
    assert!(echo.data().is_empty());
}
