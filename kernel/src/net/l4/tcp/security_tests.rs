use super::*;
use crate::net::l4::tcp::{EndpointAddr, Ipv4Addr};

#[cfg_attr(test, test_case)]
pub fn test_sack_scoreboard_wrapping_bug() {
    let mut options = TcpOptionsState::new();
    options.sack_enabled = true;

    // Initial state: empty scoreboard
    assert_eq!(options.sack_scoreboard.len(), 0);

    // Case 1: Normal overlap (no wrapping)
    // Existing: [100, 200]
    options.sack_scoreboard.push((100, 200));
    // New: [150, 250]
    options.process_sack_option(&[(150, 250)]);
    assert_eq!(options.sack_scoreboard.len(), 1);
    assert_eq!(options.sack_scoreboard[0], (100, 250));

    // Case 2: Wrapping overlap
    // Current: [(100, 250)]
    // Clear and set to near wrap
    options.sack_scoreboard.clear();
    let left = 0xFFFF_FFF0u32;
    let right = 0xFFFF_FFFFu32;
    options.sack_scoreboard.push((left, right));

    // New: [0xFFFF_FFF5, 0x0000_0010] - wraps around
    let new_left = 0xFFFF_FFF5u32;
    let new_right = 0x0000_0010u32;
    options.process_sack_option(&[(new_left, new_right)]);

    // If bug exists, min(0xFFFF_FFF0, 0xFFFF_FFF5) = 0xFFFF_FFF0 (OK)
    // But max(0xFFFF_FFFF, 0x0000_0010) = 0xFFFF_FFFF (WRONG, should be 0x0000_0010)
    assert_eq!(options.sack_scoreboard.len(), 1);

    // This assertion will FAIL if the bug exists.
    // If bug exists, it will be (0xFFFF_FFF0, 0xFFFF_FFFF)
    assert_eq!(
        options.sack_scoreboard[0],
        (0xFFFF_FFF0, 0x0000_0010),
        "SACK scoreboard failed to handle wrapping sequence numbers correctly"
    );
}

#[cfg_attr(test, test_case)]
pub fn test_sack_scoreboard_inverted_range_vulnerability() {
    let mut options = TcpOptionsState::new();
    options.sack_enabled = true;

    // Attacker sends an "inverted" SACK block: left > right (numerically)
    // But in wrapping space, it might be interpreted as a huge range or something else.
    // RFC 2018 says Left Edge is first, Right Edge is following.
    // If left = 1000, right = 500, this is invalid unless it's meant to wrap (but SACK blocks don't wrap internally usually)

    options.sack_scoreboard.push((100, 200));
    // Inverted block
    options.process_sack_option(&[(500, 400)]);

    // If we don't validate left < right (wrapping), we might push it or merge it incorrectly.
    // Ideally, we should ignore invalid blocks.
    for &(l, r) in &options.sack_scoreboard {
        let diff = r.wrapping_sub(l) as i32;
        assert!(
            diff >= 0,
            "SACK scoreboard contains inverted range: [{}, {}]",
            l,
            r
        );
    }
}
