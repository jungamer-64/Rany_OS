use super::*;

/// X25519 鍵交換対称性テスト
///
/// Alice.shared_secret(Bob.pk) == Bob.shared_secret(Alice.pk)
#[test_case]
fn test_x25519_key_exchange_symmetry() {
    let alice = EcdhKeyPair::generate(EcdhGroup::X25519).expect("Alice keygen");
    let bob = EcdhKeyPair::generate(EcdhGroup::X25519).expect("Bob keygen");

    let alice_pk = alice.public_key_bytes();
    let bob_pk = bob.public_key_bytes();

    let alice_secret = alice.shared_secret(&bob_pk).expect("Alice DH");
    let bob_secret = bob.shared_secret(&alice_pk).expect("Bob DH");

    assert_eq!(alice_secret, bob_secret, "ECDH shared secrets must match");
    assert_eq!(alice_secret.len(), 32, "X25519 shared secret must be 32 bytes");
}

/// X25519 公開鍵の長さテスト
#[test_case]
fn test_x25519_public_key_length() {
    let kp = EcdhKeyPair::generate(EcdhGroup::X25519).expect("keygen");
    assert_eq!(kp.public_key_bytes().len(), 32);
}

/// X25519 グループ識別テスト
#[test_case]
fn test_x25519_group() {
    let kp = EcdhKeyPair::generate(EcdhGroup::X25519).expect("keygen");
    assert_eq!(kp.group(), EcdhGroup::X25519);
}

/// NamedGroup変換テスト
#[test_case]
fn test_ecdh_group_from_named_group() {
    assert_eq!(EcdhGroup::from_named_group(0x001D), Some(EcdhGroup::X25519));
    assert_eq!(EcdhGroup::from_named_group(0x0017), Some(EcdhGroup::Secp256r1));
    assert_eq!(EcdhGroup::from_named_group(0x001E), None); // X448 — 未サポート
}

/// 不正なピア公開鍵の拒否テスト
#[test_case]
fn test_x25519_reject_invalid_peer_key() {
    let kp = EcdhKeyPair::generate(EcdhGroup::X25519).expect("keygen");

    // 短すぎる鍵
    let result = kp.shared_secret(&[0u8; 16]);
    assert!(result.is_err());

    // 長すぎる鍵
    let result = kp.shared_secret(&[0u8; 64]);
    assert!(result.is_err());
}

/// X25519 RFC 7748 テストベクトル
///
/// Section 6.1 の既知のスカラー倍算結果を検証
#[test_case]
fn test_x25519_rfc7748_vector() {
    // テストベクトル（RFC 7748 Section 6.1）:
    // scalar: a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
    // u-coordinate: e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
    // expected output: c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
    let scalar_bytes: [u8; 32] = [
        0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
        0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
        0xba, 0x44, 0x9a, 0xc4,
    ];
    let u_bytes: [u8; 32] = [
        0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
        0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
        0xd0, 0xab, 0x1c, 0x4c,
    ];
    let expected: [u8; 32] = [
        0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
        0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
        0x77, 0xa2, 0x85, 0x52,
    ];

    let sk = X25519SecretKey::new(scalar_bytes);
    let pk = X25519PublicKey::from_slice(&u_bytes).expect("valid u-coordinate");

    // Note: dh() applies clamping internally, so this tests the clamped result.
    // The RFC test vector input is already valid for the clamped computation.
    let result = pk.dh(&sk);
    assert!(result.is_ok(), "DH computation should succeed");
    let output: &[u8; 32] = &result.unwrap();
    assert_eq!(output, &expected, "RFC 7748 Section 6.1 test vector mismatch");
}

// ========================================================================
// P-256 ユニットテスト
// ========================================================================

/// P-256 鍵交換対称性テスト
///
/// Alice.shared_secret(Bob.pk) == Bob.shared_secret(Alice.pk)
#[test_case]
fn test_p256_key_exchange_symmetry() {
    let alice = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("Alice keygen");
    let bob = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("Bob keygen");

    let alice_pk = alice.public_key_bytes();
    let bob_pk = bob.public_key_bytes();

    let alice_secret = alice.shared_secret(&bob_pk).expect("Alice DH");
    let bob_secret = bob.shared_secret(&alice_pk).expect("Bob DH");

    assert_eq!(alice_secret, bob_secret, "P-256 ECDH shared secrets must match");
    assert_eq!(alice_secret.len(), 32, "P-256 shared secret must be 32 bytes");
}

/// P-256 公開鍵の長さテスト（65バイト: 04 || x || y）
#[test_case]
fn test_p256_public_key_length() {
    let kp = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("keygen");
    assert_eq!(kp.public_key_bytes().len(), 65, "P-256 public key must be 65 bytes");
}

/// P-256 公開鍵が曲線上の有効な点であることを確認
#[test_case]
fn test_p256_public_key_on_curve() {
    let kp = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("keygen");
    let pk_bytes = kp.public_key_bytes();

    // 0x04プレフィックスの確認
    assert_eq!(pk_bytes[0], 0x04, "P-256 public key must start with 0x04");

    // 曲線上の点であることを確認
    let point = p256::parse_uncompressed_point(&pk_bytes);
    assert!(point.is_some(), "P-256 public key must be a valid curve point");
    assert!(point.unwrap().is_on_curve(), "P-256 public key must be on curve");
}

/// P-256 グループ識別テスト
#[test_case]
fn test_p256_group() {
    let kp = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("keygen");
    assert_eq!(kp.group(), EcdhGroup::Secp256r1);
}

/// P-256 不正なピア公開鍵の拒否テスト
#[test_case]
fn test_p256_reject_invalid_peer_key() {
    let kp = EcdhKeyPair::generate(EcdhGroup::Secp256r1).expect("keygen");

    // 短すぎる鍵
    assert!(kp.shared_secret(&[0u8; 16]).is_err(), "should reject short key");

    // 長すぎる鍵
    assert!(kp.shared_secret(&[0u8; 128]).is_err(), "should reject long key");

    // 不正なプレフィックス
    let mut bad_prefix = [0u8; 65];
    bad_prefix[0] = 0x05;
    assert!(kp.shared_secret(&bad_prefix).is_err(), "should reject bad prefix");

    // 曲線上にない点
    let mut off_curve = [0u8; 65];
    off_curve[0] = 0x04;
    off_curve[1] = 0x01;
    off_curve[33] = 0x01;
    assert!(kp.shared_secret(&off_curve).is_err(), "should reject off-curve point");
}

/// P-256 ベースポイントが曲線上にあることを確認
#[test_case]
fn test_p256_generator_on_curve() {
    let g = p256::P256Point::generator();
    assert!(g.is_on_curve(), "P-256 generator must be on curve");
}

/// P-256 フィールド演算基本テスト
#[test_case]
fn test_p256_field_arithmetic() {
    let a = p256::P256FieldElement::from_limbs([1, 0, 0, 0]);
    let b = p256::P256FieldElement::from_limbs([2, 0, 0, 0]);

    // 1 + 2 = 3
    let c = a.add(&b);
    assert_eq!(c.limbs[0], 3);
    assert_eq!(c.limbs[1], 0);

    // 3 - 1 = 2
    let d = c.sub(&a);
    assert_eq!(d.limbs[0], 2);
    assert_eq!(d.limbs[1], 0);

    // 2 * 3 = 6
    let e = b.mul(&c);
    assert_eq!(e.limbs[0], 6);

    // 1の逆元は1
    let one = p256::P256FieldElement::ONE;
    let one_inv = one.inv();
    assert_eq!(one_inv, one, "inverse of 1 must be 1");
}

/// P-256 ポイント2倍算テスト（Gの2倍が曲線上にある）
#[test_case]
fn test_p256_point_double() {
    let g = p256::P256Point::generator();
    let g2 = g.double();
    assert!(g2.is_on_curve(), "2G must be on curve");
    assert!(!g2.is_identity(), "2G must not be identity");
}

/// P-256 ポイント加算テスト（G + G = 2G）
#[test_case]
fn test_p256_point_add() {
    let g = p256::P256Point::generator();
    let g_plus_g = g.add(&g);
    let g2 = g.double();

    // G + G のアフィン座標と 2G のアフィン座標が一致すること
    let (ax1, ay1) = g_plus_g.to_affine().expect("G+G affine");
    let (ax2, ay2) = g2.to_affine().expect("2G affine");
    assert_eq!(ax1, ax2, "G+G x must equal 2G x");
    assert_eq!(ay1, ay2, "G+G y must equal 2G y");
}

/// P-256 スカラー倍算テスト（[1]G = G）
#[test_case]
fn test_p256_scalar_mul_one() {
    let g = p256::P256Point::generator();
    let mut scalar = [0u8; 32];
    scalar[31] = 1; // k = 1 (ビッグエンディアン)

    let result = g.scalar_mul(&scalar);
    let (rx, ry) = result.to_affine().expect("[1]G affine");
    let (gx, gy) = g.to_affine().expect("G affine");

    assert_eq!(rx, gx, "[1]G x must equal Gx");
    assert_eq!(ry, gy, "[1]G y must equal Gy");
}

/// P-256 無限遠点テスト
#[test_case]
fn test_p256_identity() {
    let id = p256::P256Point::identity();
    assert!(id.is_identity(), "identity must be identity");

    let g = p256::P256Point::generator();
    let sum = g.add(&id);
    let (sx, sy) = sum.to_affine().expect("G + O affine");
    let (gx, gy) = g.to_affine().expect("G affine");
    assert_eq!(sx, gx, "G + O must equal G (x)");
    assert_eq!(sy, gy, "G + O must equal G (y)");
}

/// P-256 スカラー有効性検証テスト
#[test_case]
fn test_p256_scalar_validity() {
    // ゼロスカラーは無効
    assert!(!p256::scalar_is_valid(&[0u8; 32]), "zero scalar must be invalid");

    // 1は有効
    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(p256::scalar_is_valid(&one), "scalar 1 must be valid");

    // n自体は無効（k < n が必要）
    let n_bytes = p256::P256FieldElement::from_limbs(super::p256::N).to_be_bytes();
    assert!(!p256::scalar_is_valid(&n_bytes), "scalar n must be invalid");
}

/// P-256 バイトエンコーディングのラウンドトリップテスト
#[test_case]
fn test_p256_field_element_roundtrip() {
    let original = p256::P256FieldElement::from_limbs([
        0xF4A13945D898C296,
        0x77037D812DEB33A0,
        0xF8BCE6E563A440F2,
        0x6B17D1F2E12C4247,
    ]);

    let bytes = original.to_be_bytes();
    let restored = p256::P256FieldElement::from_be_bytes(&bytes);
    assert_eq!(original, restored, "field element roundtrip must be exact");
}
