use super::*;

#[test_case]
fn test_mgf1_produces_requested_length() {
    let seed = [0x11u8, 0x22, 0x33, 0x44];
    let out = mgf1(&seed, 37, HashAlgorithm::Sha256);
    assert_eq!(out.len(), 37);
}

#[test_case]
fn test_mgf1_is_deterministic_for_same_input() {
    let seed = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let out1 = mgf1(&seed, 48, HashAlgorithm::Sha256);
    let out2 = mgf1(&seed, 48, HashAlgorithm::Sha256);
    assert_eq!(out1, out2);
}
