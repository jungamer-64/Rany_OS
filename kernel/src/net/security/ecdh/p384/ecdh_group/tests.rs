use super::*;

#[test_case]
fn test_named_group_roundtrip() {
    assert_eq!(EcdhGroup::from_named_group(0x001D), Some(EcdhGroup::X25519));
    assert_eq!(EcdhGroup::from_named_group(0x0017), Some(EcdhGroup::Secp256r1));
    assert_eq!(EcdhGroup::from_named_group(0xFFFF), None);
    assert_eq!(EcdhGroup::X25519.to_named_group(), 0x001D);
    assert_eq!(EcdhGroup::Secp256r1.to_named_group(), 0x0017);
}

#[test_case]
fn test_public_key_len_constants() {
    assert_eq!(EcdhGroup::X25519.public_key_len(), 32);
    assert_eq!(EcdhGroup::Secp256r1.public_key_len(), 65);
}
