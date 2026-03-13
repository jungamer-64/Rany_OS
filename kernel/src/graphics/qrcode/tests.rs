use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_rs_ec7_known_vector() {
    // Known vector test for Reed-Solomon RS(26,19) over GF(256) with primitive 0x11D.
    // Data derived from standard example but adapted for 19 data bytes (V1-L).
    let data19: [u8; 19] = [
        0x41, 0x17, 0x77, 0x77, 0x72, 0xE7, 0x76, 0x96, 0xB6, 0x97, 0x06, 0x56, 0x46, 0x96, 0x12,
        0xE6, 0xF7, 0x26, 0x70,
    ];
    let ec = rs_encode_ec7(&data19);
    // Correct EC codewords for this input using our generator polynomial
    assert_eq!(ec, [0xAE, 0xAD, 0xEF, 0x06, 0x97, 0x8F, 0x25]);
}
