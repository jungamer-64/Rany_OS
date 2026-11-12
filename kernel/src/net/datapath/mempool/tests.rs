// ============================================================================
// kernel/src/net/datapath/mempool/tests.rs - データパス / メモリプール / テスト
// ============================================================================

use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn rx_geometry_holds_headroom_driver_header_and_an_mtu_frame() {
    let geometry = PacketPoolGeometry::rx(1500, 8).expect("standard MTU geometry");
    assert!(
        geometry.slot_bytes()
            >= DEFAULT_PACKET_HEADROOM + RX_DEVICE_HEADER_ALLOWANCE + RX_LINK_HEADER_BYTES + 1500
    );
    assert_eq!(geometry.slot_bytes() % SLOT_ALIGN, 0);

    let jumbo = PacketPoolGeometry::rx(9000, 8).expect("jumbo MTU geometry");
    assert!(jumbo.slot_bytes() >= 9000);
    assert!(jumbo.slots_per_chunk() >= 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn rx_geometry_rejects_an_empty_pool() {
    assert_eq!(PacketPoolGeometry::rx(1500, 0), None);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn header_slots_hold_every_generated_frame_header() {
    // Ethernet, IPv6 and its fragment header are the longest generated header.
    assert!(PacketPoolGeometry::HEADERS.slot_bytes() >= 14 + 40 + 8);
    assert!(PacketPoolGeometry::FRAMES.slot_bytes() > PacketPoolGeometry::HEADERS.slot_bytes());
}
