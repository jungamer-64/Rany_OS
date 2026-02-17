// ============================================================================
// src/net/x509.rs - X.509 Certificate Parser
// ============================================================================
//!
//! # X.509証明書パーサー
//!
//! ASN.1 DERエンコードされたX.509v3証明書を解析するための
//! 最小限のゼロコピーパーサー実装。
//!
//! ## 機能
//! - **DERパーサー** — ASN.1 DER基本型の解析（SEQUENCE, INTEGER, OID, BIT STRING等）
//! - **X.509v3証明書解析** — TBSCertificate, SignatureAlgorithm, SignatureValueの抽出
//! - **公開鍵情報抽出** — RSA / ECDSA P-256 SubjectPublicKeyInfoの解析
//!
//! ## セキュリティ特性
//! - ゼロコピー設計（入力バッファの参照のみ保持）
//! - 境界チェック付きパース（バッファオーバーフロー防止）
//! - 不正なDERエンコーディングの検出

#![allow(dead_code)]

// ============================================================================
// OID Constants (DER-encoded OID value bytes)
// ============================================================================

/// sha256WithRSAEncryption (1.2.840.113549.1.1.11)
const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

/// sha384WithRSAEncryption (1.2.840.113549.1.1.12)
const OID_SHA384_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];

/// sha512WithRSAEncryption (1.2.840.113549.1.1.13)
const OID_SHA512_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];

/// ecdsaWithSHA256 (1.2.840.10045.4.3.2)
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// ecdsaWithSHA384 (1.2.840.10045.4.3.3)
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

/// rsaEncryption (1.2.840.113549.1.1.1)
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

/// ecPublicKey (1.2.840.10045.2.1)
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// secp256r1 / prime256v1 (1.2.840.10045.3.1.7)
const OID_SECP256R1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// secp384r1 (1.3.132.0.34)
const OID_SECP384R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];

/// id-RSASSA-PSS (1.2.840.113549.1.1.10)
const OID_RSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];

// ============================================================================
// Signature Algorithm
// ============================================================================

/// 署名アルゴリズム識別子
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithmId {
    /// SHA-256 with RSA Encryption (1.2.840.113549.1.1.11)
    Sha256WithRsa,
    /// SHA-384 with RSA Encryption (1.2.840.113549.1.1.12)
    Sha384WithRsa,
    /// SHA-512 with RSA Encryption (1.2.840.113549.1.1.13)
    Sha512WithRsa,
    /// ECDSA with SHA-256 (1.2.840.10045.4.3.2)
    EcdsaWithSha256,
    /// ECDSA with SHA-384 (1.2.840.10045.4.3.3)
    EcdsaWithSha384,
    /// RSASSA-PSS (1.2.840.113549.1.1.10)
    RsaPss,
    /// 未知のアルゴリズム
    Unknown,
}

/// OIDバイト列から署名アルゴリズムを判定
fn parse_signature_algorithm_id(oid: &[u8]) -> SignatureAlgorithmId {
    if oid == OID_SHA256_WITH_RSA {
        SignatureAlgorithmId::Sha256WithRsa
    } else if oid == OID_SHA384_WITH_RSA {
        SignatureAlgorithmId::Sha384WithRsa
    } else if oid == OID_SHA512_WITH_RSA {
        SignatureAlgorithmId::Sha512WithRsa
    } else if oid == OID_ECDSA_WITH_SHA256 {
        SignatureAlgorithmId::EcdsaWithSha256
    } else if oid == OID_ECDSA_WITH_SHA384 {
        SignatureAlgorithmId::EcdsaWithSha384
    } else if oid == OID_RSA_PSS {
        SignatureAlgorithmId::RsaPss
    } else {
        SignatureAlgorithmId::Unknown
    }
}

// ============================================================================
// Subject Public Key Info
// ============================================================================

/// サブジェクト公開鍵情報
///
/// RSAの場合、モジュラスの先頭0x00符号バイトは除去済み。
/// ECDSA P-256の場合、BIT STRINGの内容（非圧縮ポイント）をそのまま保持。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectPublicKeyInfo<'a> {
    /// RSA公開鍵
    Rsa {
        /// モジュラス（先頭0x00符号バイト除去済み）
        modulus: &'a [u8],
        /// 公開指数
        exponent: &'a [u8],
    },
    /// ECDSA P-256公開鍵（非圧縮ポイント 04 || x || y）
    EcdsaP256 {
        /// 公開鍵データ
        public_key: &'a [u8],
    },
    /// ECDSA P-384公開鍵（非圧縮ポイント 04 || x || y）
    EcdsaP384 {
        /// 公開鍵データ
        public_key: &'a [u8],
    },
    /// 未知のアルゴリズムの公開鍵
    Unknown(&'a [u8]),
}

// ============================================================================
// X.509 Certificate
// ============================================================================

/// X.509v3証明書（ゼロコピー）
///
/// DERエンコードされた証明書をパースし、各フィールドへの参照を保持する。
/// 入力バッファのライフタイム `'a` に依存する。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X509Certificate<'a> {
    /// TBSCertificateの生DERバイト列（署名検証用、タグ+長さ+値の全体）
    pub raw_tbs: &'a [u8],
    /// 署名アルゴリズム
    pub signature_algorithm: SignatureAlgorithmId,
    /// 発行者の生DERバイト列（SEQUENCE TLV全体）
    pub issuer_raw: &'a [u8],
    /// サブジェクトの生DERバイト列（SEQUENCE TLV全体）
    pub subject_raw: &'a [u8],
    /// サブジェクト公開鍵情報
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    /// 署名値（BIT STRINGの未使用ビットバイトを除いたデータ）
    pub signature_value: &'a [u8],
}

// ============================================================================
// DER Parser
// ============================================================================

/// ASN.1 DERパーサー（ゼロコピー）
///
/// 入力バイト列上のカーソルベースパーサー。
/// 各読み取りメソッドはカーソル位置を進め、入力バッファへの参照を返す。
#[derive(Debug)]
pub struct DerParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerParser<'a> {
    /// 新しいパーサーを生成
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// 現在のカーソル位置を取得
    pub fn position(&self) -> usize {
        self.pos
    }

    /// 残りデータを取得
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// 残りデータがないか判定
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// タグバイトを1つ読み取る
    pub fn read_tag(&mut self) -> Option<u8> {
        if self.pos >= self.data.len() {
            return None;
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        Some(tag)
    }

    /// DER長さエンコーディングを読み取る
    ///
    /// 短形式（< 128）: 1バイトで長さを直接表現
    /// 長形式（>= 128）: 先頭バイトの下位7ビットが後続の長さバイト数を示す
    pub fn read_length(&mut self) -> Option<usize> {
        if self.pos >= self.data.len() {
            return None;
        }
        let first = self.data[self.pos];
        self.pos += 1;

        if first < 0x80 {
            // 短形式
            Some(first as usize)
        } else if first == 0x80 {
            // 不定長形式（DERでは不許可）
            None
        } else {
            // 長形式: 下位7ビットが長さバイト数
            let num_bytes = (first & 0x7F) as usize;
            if num_bytes > 4 || self.pos + num_bytes > self.data.len() {
                return None;
            }
            let mut length: usize = 0;
            for i in 0..num_bytes {
                length = length.checked_shl(8)?;
                length = length.checked_add(self.data[self.pos + i] as usize)?;
            }
            self.pos += num_bytes;
            Some(length)
        }
    }

    /// TLV（Tag-Length-Value）を読み取る
    ///
    /// タグバイトと値スライスのペアを返す。
    /// カーソルはTLVの直後に進む。
    pub fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.read_tag()?;
        let length = self.read_length()?;
        if self.pos + length > self.data.len() {
            return None;
        }
        let value = &self.data[self.pos..self.pos + length];
        self.pos += length;
        Some((tag, value))
    }

    /// SEQUENCEを読み取り、内容のスライスを返す
    ///
    /// タグが0x30（SEQUENCE）であることを検証する。
    pub fn read_sequence(&mut self) -> Option<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x30 {
            return None;
        }
        Some(value)
    }

    /// INTEGERを読み取り、値バイト列を返す
    ///
    /// タグが0x02（INTEGER）であることを検証する。
    /// 値バイト列はDERそのままを返す（先頭0x00符号バイトを含む場合がある）。
    pub fn read_integer(&mut self) -> Option<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x02 {
            return None;
        }
        Some(value)
    }

    /// OIDを読み取り、値バイト列を返す
    ///
    /// タグが0x06（OBJECT IDENTIFIER）であることを検証する。
    pub fn read_oid(&mut self) -> Option<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x06 {
            return None;
        }
        Some(value)
    }

    /// BIT STRINGを読み取り、データバイト列を返す
    ///
    /// タグが0x03（BIT STRING）であることを検証する。
    /// 先頭の未使用ビット数バイトをスキップし、実データのみ返す。
    pub fn read_bitstring(&mut self) -> Option<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x03 || value.is_empty() {
            return None;
        }
        // 先頭バイトは未使用ビット数（通常0）
        Some(&value[1..])
    }

    /// OCTET STRINGを読み取り、値バイト列を返す
    ///
    /// タグが0x04（OCTET STRING）であることを検証する。
    pub fn read_octet_string(&mut self) -> Option<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x04 {
            return None;
        }
        Some(value)
    }

    /// 1つのTLVを読み飛ばす
    pub fn skip_tlv(&mut self) -> Option<()> {
        let _tag = self.read_tag()?;
        let length = self.read_length()?;
        if self.pos + length > self.data.len() {
            return None;
        }
        self.pos += length;
        Some(())
    }
}

// ============================================================================
// X.509 Certificate Parser
// ============================================================================

/// X.509v3証明書をDERバイト列からパースする
///
/// ## 構造
/// ```text
/// Certificate ::= SEQUENCE {
///     tbsCertificate      TBSCertificate,
///     signatureAlgorithm  AlgorithmIdentifier,
///     signatureValue      BIT STRING
/// }
/// ```
///
/// TBSCertificateから以下を抽出する:
/// - 署名アルゴリズム（TBS内のAlgorithmIdentifier）
/// - 発行者（生DER）
/// - サブジェクト（生DER）
/// - 公開鍵情報（RSA / ECDSA P-256）
///
/// `raw_tbs` には署名検証用にTBSCertificateの完全なDER
/// （タグ+長さ+値）を保持する。
/// TBSプリアンブル（Version, Serial, SigAlg）を解析
fn parse_tbs_preamble(tbs: &mut DerParser<'_>) -> Option<SignatureAlgorithmId> {
    // Version [0] EXPLICIT（オプション）
    if tbs.remaining().first() == Some(&0xA0) {
        let (_tag, _version_content) = tbs.read_tlv()?;
    }

    // Serial Number — スキップ
    tbs.skip_tlv()?;

    // Signature Algorithm（TBS内）
    let sig_alg_content = tbs.read_sequence()?;
    let mut sig_alg_parser = DerParser::new(sig_alg_content);
    let sig_oid = sig_alg_parser.read_oid()?;
    Some(parse_signature_algorithm_id(sig_oid))
}

/// TBSCertificateフィールドを解析
fn parse_tbs_fields<'a>(tbs_content: &'a [u8]) -> Option<(SignatureAlgorithmId, usize, usize, usize, usize, SubjectPublicKeyInfo<'a>)> {
    let mut tbs = DerParser::new(tbs_content);

    let signature_algorithm = parse_tbs_preamble(&mut tbs)?;

    // Issuer — 生DERをキャプチャ
    let issuer_start = tbs.position();
    tbs.skip_tlv()?;
    let issuer_end = tbs.position();

    // Validity — スキップ
    tbs.skip_tlv()?;

    // Subject — 生DERをキャプチャ
    let subject_start = tbs.position();
    tbs.skip_tlv()?;
    let subject_end = tbs.position();

    // SubjectPublicKeyInfo
    let spki_content = tbs.read_sequence()?;
    let subject_public_key_info = parse_spki(spki_content)?;

    Some((signature_algorithm, issuer_start, issuer_end, subject_start, subject_end, subject_public_key_info))
}

pub fn parse_x509<'a>(der: &'a [u8]) -> Option<X509Certificate<'a>> {
    // 外側SEQUENCE
    let mut outer = DerParser::new(der);
    let cert_content = outer.read_sequence()?;

    let mut parser = DerParser::new(cert_content);

    // TBSCertificate SEQUENCE — 生DERバイト列をキャプチャ
    let tbs_start = parser.position();
    let tbs_content = parser.read_sequence()?;
    let tbs_end = parser.position();
    let raw_tbs = &cert_content[tbs_start..tbs_end];

    let (signature_algorithm, issuer_start, issuer_end, subject_start, subject_end, subject_public_key_info) =
        parse_tbs_fields(tbs_content)?;

    let issuer_raw = &tbs_content[issuer_start..issuer_end];
    let subject_raw = &tbs_content[subject_start..subject_end];

    // 外側SignatureAlgorithm — スキップ
    parser.skip_tlv()?;

    // SignatureValue (BIT STRING)
    let signature_value = parser.read_bitstring()?;

    Some(X509Certificate {
        raw_tbs,
        signature_algorithm,
        issuer_raw,
        subject_raw,
        subject_public_key_info,
        signature_value,
    })
}

/// SubjectPublicKeyInfoをパースする
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm        AlgorithmIdentifier,
///     subjectPublicKey BIT STRING
/// }
/// ```
///
/// RSAの場合、BIT STRING内のSEQUENCE { modulus INTEGER, exponent INTEGER }
/// を解析し、モジュラスの先頭0x00符号バイトを除去する。
/// ECDSA P-256の場合、アルゴリズムパラメータのsecp256r1 OIDを検証し、
/// BIT STRINGの内容（非圧縮ポイント）を返す。
/// RSA 公開鍵を BIT STRING から解析する
fn parse_rsa_spki<'a>(pubkey_bits: &'a [u8]) -> Option<SubjectPublicKeyInfo<'a>> {
    let mut rsa_parser = DerParser::new(pubkey_bits);
    let rsa_content = rsa_parser.read_sequence()?;
    let mut rsa_inner = DerParser::new(rsa_content);
    let mut modulus = rsa_inner.read_integer()?;
    if modulus.len() > 1 && modulus[0] == 0x00 {
        modulus = &modulus[1..];
    }
    let exponent = rsa_inner.read_integer()?;
    Some(SubjectPublicKeyInfo::Rsa { modulus, exponent })
}

/// ECDSA 公開鍵をアルゴリズムパラメータから解析する
fn parse_ec_spki<'a>(
    alg_parser: &mut DerParser<'a>,
    pubkey_bits: &'a [u8],
) -> Option<SubjectPublicKeyInfo<'a>> {
    let curve_oid = alg_parser.read_oid()?;
    if curve_oid == OID_SECP256R1 {
        Some(SubjectPublicKeyInfo::EcdsaP256 { public_key: pubkey_bits })
    } else if curve_oid == OID_SECP384R1 {
        Some(SubjectPublicKeyInfo::EcdsaP384 { public_key: pubkey_bits })
    } else {
        Some(SubjectPublicKeyInfo::Unknown(pubkey_bits))
    }
}

fn parse_spki<'a>(spki_content: &'a [u8]) -> Option<SubjectPublicKeyInfo<'a>> {
    let mut parser = DerParser::new(spki_content);
    let alg_content = parser.read_sequence()?;
    let mut alg_parser = DerParser::new(alg_content);
    let alg_oid = alg_parser.read_oid()?;
    let pubkey_bits = parser.read_bitstring()?;

    if alg_oid == OID_RSA_ENCRYPTION {
        parse_rsa_spki(pubkey_bits)
    } else if alg_oid == OID_EC_PUBLIC_KEY {
        parse_ec_spki(&mut alg_parser, pubkey_bits)
    } else {
        Some(SubjectPublicKeyInfo::Unknown(pubkey_bits))
    }
}

// ============================================================================
// Synthetic Test Certificate (DER)
// ============================================================================

/// テスト用合成X.509v3証明書（DERエンコード、154バイト）
///
/// 構造:
/// - Version: v3 (INTEGER 2)
/// - Serial: 1
/// - Signature Algorithm: sha256WithRSAEncryption
/// - Issuer: CN=Test
/// - Validity: 2020-01-01 ~ 2030-01-01
/// - Subject: CN=Test
/// - SPKI: RSA (8バイトダミーモジュラス 0xFF x 8, exponent 65537)
/// - Signature: ダミー4バイト (0xDEADBEEF)
const TEST_CERT_DER: [u8; 154] = [
    // === Certificate SEQUENCE (tag 0x30, long-form length 151) ===
    0x30, 0x81, 0x97,
    // === TBS Certificate SEQUENCE (tag 0x30, length 127) ===
    0x30, 0x7F,
    // -- Version [0] EXPLICIT: v3 (INTEGER 2) --
    0xA0, 0x03, 0x02, 0x01, 0x02,
    // -- Serial Number: INTEGER 1 --
    0x02, 0x01, 0x01,
    // -- Signature Algorithm: sha256WithRSAEncryption --
    0x30, 0x0D,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    0x05, 0x00,
    // -- Issuer: CN=Test --
    0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x04, 0x54, 0x65, 0x73, 0x74,
    // -- Validity: 2020-01-01 ~ 2030-01-01 --
    0x30, 0x1E,
    0x17, 0x0D, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
    0x17, 0x0D, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
    // -- Subject: CN=Test --
    0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x04, 0x54, 0x65, 0x73, 0x74,
    // -- SubjectPublicKeyInfo: RSA --
    0x30, 0x24,
    // Algorithm: rsaEncryption
    0x30, 0x0D,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x05, 0x00,
    // BIT STRING (public key, 0 unused bits)
    0x03, 0x13, 0x00,
    // RSA public key SEQUENCE
    0x30, 0x10,
    // Modulus INTEGER (leading 0x00 + 8 bytes of 0xFF)
    0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // Exponent INTEGER (65537 = 0x010001)
    0x02, 0x03, 0x01, 0x00, 0x01,
    // === Outer Signature Algorithm: sha256WithRSAEncryption ===
    0x30, 0x0D,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    0x05, 0x00,
    // === Signature Value: BIT STRING (0 unused bits, dummy 4 bytes) ===
    0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
];

// ============================================================================
// Certificate Chain Validation
// ============================================================================

/// 証明書チェーンの検証
///
/// `chain` はリーフ証明書(chain[0])からルートCA(chain[last])の順序。
/// - chain[i]のissuerとchain[i+1]のsubjectが一致することを確認
/// - chain[i]の署名をchain[i+1]の公開鍵で検証
/// - リーフ証明書の公開鍵を返す
///
/// `server_name` が指定されている場合、リーフ証明書のsubjectにその名前を含むか
/// 簡易チェックする（完全なSAN/CN照合ではない）。
///
/// # Returns
/// リーフ証明書のSubjectPublicKeyInfo
/// 証明書チェーン内のリンク（issuer一致 + 署名）を検証
fn verify_chain_links(certs: &[Option<X509Certificate<'_>>], chain_len: usize) -> Option<()> {
    for i in 0..chain_len - 1 {
        let current = certs[i].as_ref()?;
        let issuer = certs[i + 1].as_ref()?;

        if current.issuer_raw != issuer.subject_raw {
            return None;
        }
        if !verify_signature(current, &issuer.subject_public_key_info) {
            return None;
        }
    }
    Some(())
}

/// リーフ証明書のsubjectにサーバー名が含まれるか簡易チェック
fn check_server_name_in_leaf(leaf: &X509Certificate<'_>, server_name: Option<&str>) -> Option<()> {
    if let Some(name) = server_name {
        if !contains_bytes(leaf.subject_raw, name.as_bytes()) {
            return None;
        }
    }
    Some(())
}

/// 証明書チェーンをパースして配列に格納
fn parse_chain_to_array<'a>(
    chain: &[&'a [u8]],
    certs: &mut [Option<X509Certificate<'a>>; 8],
) -> Option<()> {
    for (i, &der) in chain.iter().enumerate() {
        certs[i] = Some(parse_x509(der)?);
    }
    Some(())
}

pub fn validate_certificate_chain<'a>(
    chain: &[&'a [u8]],
    server_name: Option<&str>,
) -> Option<SubjectPublicKeyInfo<'a>> {
    if chain.is_empty() || chain.len() > 8 {
        return None;
    }

    let mut certs: [Option<X509Certificate<'_>>; 8] = [None, None, None, None, None, None, None, None];
    parse_chain_to_array(chain, &mut certs)?;

    let leaf = certs[0].as_ref()?;
    check_server_name_in_leaf(leaf, server_name)?;

    if chain.len() > 1 {
        verify_chain_links(&certs, chain.len())?;
    }

    Some(leaf.subject_public_key_info)
}

/// バイト列の中に部分列が含まれるかチェック（簡易バイト検索）
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
    }
    false
}

/// 証明書の署名を発行者の公開鍵で検証する
fn verify_signature(cert: &X509Certificate<'_>, issuer_pubkey: &SubjectPublicKeyInfo<'_>) -> bool {
    use crate::net::rsa::{rsa_pkcs1_verify, rsa_pss_verify, RsaPublicKey, HashAlgorithm};

    match cert.signature_algorithm {
        SignatureAlgorithmId::Sha256WithRsa => {
            if let SubjectPublicKeyInfo::Rsa { modulus, exponent } = issuer_pubkey {
                let digest = crate::loader::sha256::compute(cert.raw_tbs);
                let key = RsaPublicKey { modulus, exponent };
                rsa_pkcs1_verify(&key, HashAlgorithm::Sha256, &digest, cert.signature_value).is_ok()
            } else {
                false
            }
        }
        SignatureAlgorithmId::Sha384WithRsa => {
            if let SubjectPublicKeyInfo::Rsa { modulus, exponent } = issuer_pubkey {
                let digest = crate::loader::sha384::compute(cert.raw_tbs);
                let key = RsaPublicKey { modulus, exponent };
                rsa_pkcs1_verify(&key, HashAlgorithm::Sha384, &digest, cert.signature_value).is_ok()
            } else {
                false
            }
        }
        SignatureAlgorithmId::Sha512WithRsa => {
            // SHA-512 RSA: 現時点ではSHA-384で代替（SHA-512ハッシュ実装待ち）
            // TODO: crate::loader::sha512::compute が利用可能になったら更新
            false
        }
        SignatureAlgorithmId::RsaPss => {
            if let SubjectPublicKeyInfo::Rsa { modulus, exponent } = issuer_pubkey {
                // RSA-PSSはデフォルトでSHA-256を使用
                let digest = crate::loader::sha256::compute(cert.raw_tbs);
                let key = RsaPublicKey { modulus, exponent };
                rsa_pss_verify(&key, HashAlgorithm::Sha256, &digest, cert.signature_value).is_ok()
            } else {
                false
            }
        }
        SignatureAlgorithmId::EcdsaWithSha256 => {
            if let SubjectPublicKeyInfo::EcdsaP256 { public_key } = issuer_pubkey {
                let digest = crate::loader::sha256::compute(cert.raw_tbs);
                crate::net::ecdh::p256::ecdsa_p256_verify(
                    public_key,
                    &digest,
                    cert.signature_value,
                ).is_ok()
            } else {
                false
            }
        }
        SignatureAlgorithmId::EcdsaWithSha384 => {
            if let SubjectPublicKeyInfo::EcdsaP384 { public_key } = issuer_pubkey {
                let digest = crate::loader::sha384::compute(cert.raw_tbs);
                crate::net::ecdh::p384::ecdsa_p384_verify(
                    public_key,
                    &digest,
                    cert.signature_value,
                ).is_ok()
            } else {
                false
            }
        }
        SignatureAlgorithmId::Unknown => false,
    }
}

// ============================================================================
// QEMU Tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    /// DERパーサー基本テスト: タグ・長さ読み取り
    ///
    /// 手動構築したDERバイト列でタグ・長さの読み取りを検証する。
    pub fn x509_der_parse_tag_length_smoke() -> bool {
        // INTEGER (0x02), length 1, value 0x2A
        let data = [0x02, 0x01, 0x2A];
        let mut parser = DerParser::new(&data);
        let tag = parser.read_tag();
        let len = parser.read_length();

        tag == Some(0x02)
            && len == Some(1)
            && parser.remaining() == &[0x2A]
            && parser.remaining().len() == 1
    }

    /// DERパーサーINTEGER読み取りテスト
    ///
    /// 先頭0x00符号バイト付きINTEGERの読み取りを検証する。
    pub fn x509_der_parse_integer_smoke() -> bool {
        // INTEGER with leading 0x00 sign byte: 02 02 00 FF
        let data = [0x02, 0x02, 0x00, 0xFF];
        let mut parser = DerParser::new(&data);
        let value = parser.read_integer();

        // read_integer returns raw value bytes (including leading 0x00)
        value == Some(&[0x00, 0xFF][..]) && parser.is_empty()
    }

    /// DERパーサーSEQUENCEトラバーサルテスト
    ///
    /// SEQUENCE内の複数INTEGERを順次読み取れることを検証する。
    pub fn x509_der_parse_sequence_smoke() -> bool {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        // 30 06 02 01 01 02 01 02
        let data = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut parser = DerParser::new(&data);
        let content = match parser.read_sequence() {
            Some(c) => c,
            None => return false,
        };

        let mut inner = DerParser::new(content);
        let a = inner.read_integer();
        let b = inner.read_integer();

        a == Some(&[0x01][..]) && b == Some(&[0x02][..]) && inner.is_empty()
    }

    /// X.509証明書パース基本テスト
    ///
    /// 合成テスト証明書をパースし、基本フィールドを検証する。
    pub fn x509_parse_self_signed_smoke() -> bool {
        let cert = match parse_x509(&super::TEST_CERT_DER) {
            Some(c) => c,
            None => return false,
        };

        cert.raw_tbs.len() == 129
            && cert.raw_tbs[0] == 0x30
            && cert.raw_tbs[1] == 0x7F
            && cert.signature_algorithm == SignatureAlgorithmId::Sha256WithRsa
            && cert.signature_value == &[0xDE, 0xAD, 0xBE, 0xEF]
    }

    /// RSA公開鍵抽出テスト
    ///
    /// 合成テスト証明書からRSAモジュラスと公開指数を正しく抽出できることを検証する。
    pub fn x509_extract_rsa_pubkey_smoke() -> bool {
        let cert = match parse_x509(&super::TEST_CERT_DER) {
            Some(c) => c,
            None => return false,
        };

        match cert.subject_public_key_info {
            SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                // モジュラス: 先頭0x00除去後、8バイトの0xFF
                modulus.len() == 8
                    && modulus.iter().all(|&b| b == 0xFF)
                    && exponent == &[0x01, 0x00, 0x01]
            }
            _ => false,
        }
    }

    /// 署名アルゴリズムOIDマッピングテスト
    ///
    /// 既知のOIDが正しいSignatureAlgorithmIdにマッピングされることを検証する。
    pub fn x509_signature_algorithm_oid_smoke() -> bool {
        parse_signature_algorithm_id(OID_SHA256_WITH_RSA)
            == SignatureAlgorithmId::Sha256WithRsa
            && parse_signature_algorithm_id(OID_SHA384_WITH_RSA)
                == SignatureAlgorithmId::Sha384WithRsa
            && parse_signature_algorithm_id(OID_ECDSA_WITH_SHA256)
                == SignatureAlgorithmId::EcdsaWithSha256
            && parse_signature_algorithm_id(&[0x01, 0x02, 0x03])
                == SignatureAlgorithmId::Unknown
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
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
}
