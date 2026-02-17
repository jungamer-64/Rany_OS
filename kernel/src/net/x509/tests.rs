use super::*;

/// DERパーサー基本テスト: タグ・長さの読み取り
#[test_case]
fn test_der_parser_basic() {
    // INTEGER (0x02), length 1, value 0x2A
    let data = [0x02, 0x01, 0x2A];
    let mut parser = DerParser::new(&data);

    assert_eq!(parser.read_tag(), Some(0x02));
    assert_eq!(parser.read_length(), Some(1));
    assert_eq!(parser.remaining(), &[0x2A]);
}

/// DERパーサー長形式長さテスト
#[test_case]
fn test_der_parser_long_length() {
    // Tag 0x30, long-form length 0x81 0x80 = 128 bytes
    let mut data = [0u8; 131];
    data[0] = 0x30; // SEQUENCE tag
    data[1] = 0x81; // Long form: 1 byte follows
    data[2] = 0x80; // Length = 128

    let mut parser = DerParser::new(&data);
    let content = parser.read_sequence();
    assert!(content.is_some());
    assert_eq!(content.unwrap().len(), 128);
}

/// DERパーサーSEQUENCE読み取りテスト
#[test_case]
fn test_der_parser_sequence() {
    // SEQUENCE { INTEGER 1, INTEGER 2 }
    let data = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let mut parser = DerParser::new(&data);
    let content = parser.read_sequence().expect("read SEQUENCE");

    let mut inner = DerParser::new(content);
    let a = inner.read_integer().expect("read first INTEGER");
    let b = inner.read_integer().expect("read second INTEGER");

    assert_eq!(a, &[0x01]);
    assert_eq!(b, &[0x02]);
    assert!(inner.is_empty());
}

/// DERパーサーINTEGER読み取りテスト（先頭0x00付き）
#[test_case]
fn test_der_parser_integer() {
    // INTEGER with leading 0x00: 02 02 00 FF
    let data = [0x02, 0x02, 0x00, 0xFF];
    let mut parser = DerParser::new(&data);
    let value = parser.read_integer().expect("read INTEGER");
    assert_eq!(value, &[0x00, 0xFF]);
}

/// DERパーサーOID読み取りテスト
#[test_case]
fn test_der_parser_oid() {
    // OID for CN (2.5.4.3): 06 03 55 04 03
    let data = [0x06, 0x03, 0x55, 0x04, 0x03];
    let mut parser = DerParser::new(&data);
    let value = parser.read_oid().expect("read OID");
    assert_eq!(value, &[0x55, 0x04, 0x03]);
}

/// DERパーサーBIT STRING読み取りテスト
#[test_case]
fn test_der_parser_bitstring() {
    // BIT STRING: 03 03 00 AA BB (0 unused bits, data = AA BB)
    let data = [0x03, 0x03, 0x00, 0xAA, 0xBB];
    let mut parser = DerParser::new(&data);
    let value = parser.read_bitstring().expect("read BIT STRING");
    assert_eq!(value, &[0xAA, 0xBB]);
}

/// DERパーサーOCTET STRING読み取りテスト
#[test_case]
fn test_der_parser_octet_string() {
    // OCTET STRING: 04 02 CC DD
    let data = [0x04, 0x02, 0xCC, 0xDD];
    let mut parser = DerParser::new(&data);
    let value = parser.read_octet_string().expect("read OCTET STRING");
    assert_eq!(value, &[0xCC, 0xDD]);
}

/// DERパーサーskip_tlvテスト
#[test_case]
fn test_der_parser_skip_tlv() {
    // Two TLVs: INTEGER 0x01, INTEGER 0x02
    let data = [0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let mut parser = DerParser::new(&data);

    parser.skip_tlv().expect("skip first TLV");
    assert_eq!(parser.position(), 3);

    let second = parser.read_integer().expect("read second INTEGER");
    assert_eq!(second, &[0x02]);
    assert!(parser.is_empty());
}

/// DERパーサー不正入力拒否テスト
#[test_case]
fn test_der_parser_invalid_input() {
    // 空入力
    let mut parser = DerParser::new(&[]);
    assert!(parser.read_tag().is_none());

    // 長さが入力を超える
    let data = [0x30, 0xFF]; // SEQUENCE with length 255, but no content
    let mut parser = DerParser::new(&data);
    assert!(parser.read_sequence().is_none());

    // 不正なタグでSEQUENCE読み取り
    let data = [0x02, 0x01, 0x00]; // INTEGER, not SEQUENCE
    let mut parser = DerParser::new(&data);
    assert!(parser.read_sequence().is_none());
}

/// X.509証明書パース基本テスト
#[test_case]
fn test_parse_x509_basic() {
    let cert = parse_x509(&TEST_CERT_DER).expect("parse test cert");

    assert_eq!(
        cert.signature_algorithm,
        SignatureAlgorithmId::Sha256WithRsa,
        "signature algorithm must be sha256WithRSA"
    );
    assert_eq!(
        cert.signature_value,
        &[0xDE, 0xAD, 0xBE, 0xEF],
        "signature value must match"
    );
}

/// raw_tbs抽出テスト
#[test_case]
fn test_parse_x509_raw_tbs() {
    let cert = parse_x509(&TEST_CERT_DER).expect("parse test cert");

    assert_eq!(cert.raw_tbs.len(), 129, "raw_tbs must be 129 bytes");
    assert_eq!(cert.raw_tbs[0], 0x30, "raw_tbs must start with SEQUENCE tag");
    assert_eq!(cert.raw_tbs[1], 0x7F, "raw_tbs length must be 127");
}

/// 発行者・サブジェクト抽出テスト
#[test_case]
fn test_parse_x509_issuer_subject() {
    let cert = parse_x509(&TEST_CERT_DER).expect("parse test cert");

    assert_eq!(cert.issuer_raw.len(), 17, "issuer must be 17 bytes");
    assert_eq!(cert.subject_raw.len(), 17, "subject must be 17 bytes");

    // 自己署名なのでissuer == subject
    assert_eq!(
        cert.issuer_raw, cert.subject_raw,
        "self-signed cert: issuer must equal subject"
    );

    // issuer/subjectはSEQUENCEで始まること
    assert_eq!(cert.issuer_raw[0], 0x30, "issuer must start with SEQUENCE tag");
    assert_eq!(cert.subject_raw[0], 0x30, "subject must start with SEQUENCE tag");
}

/// RSA公開鍵抽出テスト
#[test_case]
fn test_parse_x509_rsa_spki() {
    let cert = parse_x509(&TEST_CERT_DER).expect("parse test cert");

    match cert.subject_public_key_info {
        SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
            // モジュラス: 先頭0x00除去後、8バイトの0xFF
            assert_eq!(modulus.len(), 8, "modulus must be 8 bytes (leading 0x00 stripped)");
            assert!(
                modulus.iter().all(|&b| b == 0xFF),
                "modulus bytes must all be 0xFF"
            );
            // 公開指数: 65537 = 0x010001
            assert_eq!(exponent, &[0x01, 0x00, 0x01], "exponent must be 65537");
        }
        _ => panic!("expected RSA SPKI"),
    }
}

/// 署名アルゴリズムOIDマッピングテスト
#[test_case]
fn test_signature_algorithm_oid() {
    assert_eq!(
        parse_signature_algorithm_id(OID_SHA256_WITH_RSA),
        SignatureAlgorithmId::Sha256WithRsa
    );
    assert_eq!(
        parse_signature_algorithm_id(OID_SHA384_WITH_RSA),
        SignatureAlgorithmId::Sha384WithRsa
    );
    assert_eq!(
        parse_signature_algorithm_id(OID_SHA512_WITH_RSA),
        SignatureAlgorithmId::Sha512WithRsa
    );
    assert_eq!(
        parse_signature_algorithm_id(OID_ECDSA_WITH_SHA256),
        SignatureAlgorithmId::EcdsaWithSha256
    );
    assert_eq!(
        parse_signature_algorithm_id(OID_ECDSA_WITH_SHA384),
        SignatureAlgorithmId::EcdsaWithSha384
    );
    assert_eq!(
        parse_signature_algorithm_id(&[0x01, 0x02, 0x03]),
        SignatureAlgorithmId::Unknown
    );
}

/// 不正入力拒否テスト
#[test_case]
fn test_parse_x509_invalid_input() {
    // 空入力
    assert!(parse_x509(&[]).is_none(), "empty input must fail");

    // 非SEQUENCE
    assert!(
        parse_x509(&[0x02, 0x01, 0x00]).is_none(),
        "non-SEQUENCE must fail"
    );

    // 切り詰められた入力
    assert!(
        parse_x509(&[0x30, 0x03, 0x02, 0x01]).is_none(),
        "truncated input must fail"
    );
}

/// 証明書チェーン検証テスト（自己署名証明書1枚）
#[test_case]
fn test_validate_chain_single_cert() {
    // 自己署名証明書 — 公開鍵が返されること
    let chain: &[&[u8]] = &[&TEST_CERT_DER];
    let result = validate_certificate_chain(chain, None);
    assert!(result.is_some());
}

/// 証明書チェーン検証テスト（空チェーン）
#[test_case]
fn test_validate_chain_empty() {
    let chain: &[&[u8]] = &[];
    let result = validate_certificate_chain(chain, None);
    assert!(result.is_none(), "empty chain must return None");
}

/// 証明書チェーン検証テスト（サーバー名一致）
#[test_case]
fn test_validate_chain_server_name_match() {
    // TEST_CERT_DERのsubjectは CN=Test なので "Test" を含む
    let chain: &[&[u8]] = &[&TEST_CERT_DER];
    let result = validate_certificate_chain(chain, Some("Test"));
    assert!(result.is_some(), "server name 'Test' should match");
}

/// 証明書チェーン検証テスト（サーバー名不一致）
#[test_case]
fn test_validate_chain_server_name_mismatch() {
    let chain: &[&[u8]] = &[&TEST_CERT_DER];
    let result = validate_certificate_chain(chain, Some("example.com"));
    assert!(result.is_none(), "server name 'example.com' should not match");
}
