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

/// Basic Constraints (2.5.29.19)
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];

/// Subject Alternative Name (2.5.29.17)
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];

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
    /// 有効期間開始（UNIXタイムスタンプ秒、パース失敗時は0）
    pub not_before: u64,
    /// 有効期間終了（UNIXタイムスタンプ秒、パース失敗時はu64::MAX）
    pub not_after: u64,
    /// CA（Certificate Authority）ビットがセットされているか
    pub is_ca: bool,
    /// Subject Alternative Name (SAN) 拡張の生データ
    pub san_raw: Option<&'a [u8]>,
}

impl<'a> X509Certificate<'a> {
    /// 証明書が指定時刻で有効かチェック（unix_secs = UNIXタイムスタンプ秒）
    pub fn is_valid_at(&self, unix_secs: u64) -> bool {
        unix_secs >= self.not_before && unix_secs <= self.not_after
    }
}

// ============================================================================
// ASN.1 Time Parsing (UTCTime / GeneralizedTime → UNIX timestamp)
// ============================================================================

/// ASCII数字2桁を数値に変換
fn parse_two_digits(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 2 > data.len() {
        return None;
    }
    let d1 = data[offset].wrapping_sub(b'0') as u32;
    let d2 = data[offset + 1].wrapping_sub(b'0') as u32;
    if d1 > 9 || d2 > 9 {
        return None;
    }
    Some(d1 * 10 + d2)
}

/// ASCII数字4桁を数値に変換
fn parse_four_digits(data: &[u8], offset: usize) -> Option<u32> {
    let hi = parse_two_digits(data, offset)?;
    let lo = parse_two_digits(data, offset + 2)?;
    Some(hi * 100 + lo)
}

/// 月の日数（うるう年考慮なし）
const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// うるう年判定
fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// 年月日時分秒からUNIXタイムスタンプ（秒）を計算
///
/// 簡易実装: 1970年基準。2000-2099年程度の範囲を想定。
fn datetime_to_unix(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<u64> {
    if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59 {
        return None;
    }

    let mut days: u64 = 0;

    // 1970年から当該年までの日数
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // 当該年の1月から当該月前月までの日数
    for m in 0..(month - 1) as usize {
        days += DAYS_IN_MONTH[m] as u64;
        if m == 1 && is_leap_year(year) {
            days += 1; // 2月のうるう日
        }
    }

    days += (day - 1) as u64;

    Some(days * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64)
}

/// ASN.1 UTCTime を解析してUNIXタイムスタンプに変換
///
/// フォーマット: YYMMDDHHMMSSZ (13 bytes)
/// YY < 50 → 2000+YY, YY >= 50 → 1900+YY (RFC 5280)
fn parse_utctime(data: &[u8]) -> Option<u64> {
    // 最小13バイト (YYMMDDHHMMSSZ)
    if data.len() < 13 {
        return None;
    }

    let yy = parse_two_digits(data, 0)?;
    let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
    let month = parse_two_digits(data, 2)?;
    let day = parse_two_digits(data, 4)?;
    let hour = parse_two_digits(data, 6)?;
    let min = parse_two_digits(data, 8)?;
    let sec = parse_two_digits(data, 10)?;

    datetime_to_unix(year, month, day, hour, min, sec)
}

/// ASN.1 GeneralizedTime を解析してUNIXタイムスタンプに変換
///
/// フォーマット: YYYYMMDDHHMMSSZ (15 bytes)
fn parse_generalizedtime(data: &[u8]) -> Option<u64> {
    if data.len() < 15 {
        return None;
    }

    let year = parse_four_digits(data, 0)?;
    let month = parse_two_digits(data, 4)?;
    let day = parse_two_digits(data, 6)?;
    let hour = parse_two_digits(data, 8)?;
    let min = parse_two_digits(data, 10)?;
    let sec = parse_two_digits(data, 12)?;

    datetime_to_unix(year, month, day, hour, min, sec)
}

/// ASN.1 Time (UTCTime | GeneralizedTime) をDerParserから読み取る
///
/// UTCTime tag = 0x17, GeneralizedTime tag = 0x18
fn parse_asn1_time(parser: &mut DerParser<'_>) -> Option<u64> {
    let (tag, value) = parser.read_tlv()?;
    match tag {
        0x17 => parse_utctime(value),    // UTCTime
        0x18 => parse_generalizedtime(value), // GeneralizedTime
        _ => None,
    }
}

/// Validity SEQUENCE { notBefore Time, notAfter Time } を解析
fn parse_validity(tbs: &mut DerParser<'_>) -> (u64, u64) {
    let result = (|| -> Option<(u64, u64)> {
        let validity_content = tbs.read_sequence()?;
        let mut vp = DerParser::new(validity_content);
        let not_before = parse_asn1_time(&mut vp)?;
        let not_after = parse_asn1_time(&mut vp)?;
        Some((not_before, not_after))
    })();

    // パース失敗時は安全なデフォルト（常に無効）として
    // (u64::MAX, 0) を返す
    result.unwrap_or((u64::MAX, 0))
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
    /// Parse a DER long-form length from `data` starting at `pos`.
    fn parse_long_form_length(data: &[u8], pos: &mut usize, num_bytes: usize) -> Option<usize> {
        if num_bytes > 4 || *pos + num_bytes > data.len() {
            return None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = length.checked_shl(8)?;
            length = length.checked_add(data[*pos + i] as usize)?;
        }
        *pos += num_bytes;
        Some(length)
    }

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
            Self::parse_long_form_length(self.data, &mut self.pos, (first & 0x7F) as usize)
        }
    }

    /// TLV（Tag-Length-Value）を読み取る
    ///
    /// タグバイトと値スライスのペアを返す。
    /// カーソルはTLVの直後に進む。
    pub fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.read_tag()?;
        let length = self.read_length()?;
        let end_pos = self.pos.checked_add(length)?;
        if end_pos > self.data.len() {
            return None;
        }
        let value = &self.data[self.pos..end_pos];
        self.pos = end_pos;
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
fn parse_tbs_fields<'a>(
    tbs_content: &'a [u8],
) -> Option<(
    SignatureAlgorithmId,
    usize,
    usize,
    usize,
    usize,
    SubjectPublicKeyInfo<'a>,
    u64,
    u64,
    bool, // is_ca
    Option<&'a [u8]>, // san_raw
)> {
    let mut tbs = DerParser::new(tbs_content);

    let signature_algorithm = parse_tbs_preamble(&mut tbs)?;

    // Issuer — 生DERをキャプチャ
    let issuer_start = tbs.position();
    tbs.skip_tlv()?;
    let issuer_end = tbs.position();

    // Validity — notBefore / notAfter を解析
    let (not_before, not_after) = parse_validity(&mut tbs);

    // Subject — 生DERをキャプチャ
    let subject_start = tbs.position();
    tbs.skip_tlv()?;
    let subject_end = tbs.position();

    // SubjectPublicKeyInfo
    let spki_content = tbs.read_sequence()?;
    let subject_public_key_info = parse_spki(spki_content)?;

    // Extensions [3] EXPLICIT SEQUENCE (optional)
    let mut is_ca = false;
    let mut san_raw = None;
    while let Some((tag, content)) = tbs.read_tlv() {
        // Tag 0xA3 = [3] Context-specific EXPLICIT
        if tag == 0xA3 {
            let mut ext_parser = DerParser::new(content);
            if let Some(ext_seq_content) = ext_parser.read_sequence() {
                let mut seq_parser = DerParser::new(ext_seq_content);
                while let Some(ext_item_content) = seq_parser.read_sequence() {
                    let mut item_parser = DerParser::new(ext_item_content);
                    let oid = item_parser.read_oid()?;
                    
                    // Skip optional BOOLEAN critical field if present
                    if let Some(peek_tag) = item_parser.read_tag() {
                        if peek_tag == 0x01 { // BOOLEAN
                            let _len = item_parser.read_length()?;
                            item_parser.pos += _len;
                        } else {
                            // Rewind if it was actually the OCTET STRING tag (0x04)
                            item_parser.pos -= 1;
                        }
                    }

                    if let Some(val) = item_parser.read_octet_string() {
                        if oid == OID_BASIC_CONSTRAINTS {
                            let mut bc_parser = DerParser::new(val);
                            if let Some(bc_seq) = bc_parser.read_sequence() {
                                let mut bc_inner = DerParser::new(bc_seq);
                                if let Some(tag) = bc_inner.read_tag() {
                                    if tag == 0x01 { // cA BOOLEAN
                                        let len = bc_inner.read_length()?;
                                        if len == 1 {
                                            is_ca = bc_inner.remaining()[0] != 0;
                                        }
                                    }
                                }
                            }
                        } else if oid == OID_SUBJECT_ALT_NAME {
                            san_raw = Some(val);
                        }
                    }
                }
            }
        }
    }

    Some((
        signature_algorithm,
        issuer_start,
        issuer_end,
        subject_start,
        subject_end,
        subject_public_key_info,
        not_before,
        not_after,
        is_ca,
        san_raw,
    ))
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

    let (
        signature_algorithm,
        issuer_start,
        issuer_end,
        subject_start,
        subject_end,
        subject_public_key_info,
        not_before,
        not_after,
        is_ca,
        san_raw,
    ) = parse_tbs_fields(tbs_content)?;

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
        not_before,
        not_after,
        is_ca,
        san_raw,
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

        // Security: The issuer must be a CA to sign other certificates.
        if !issuer.is_ca {
            return None;
        }

        if current.issuer_raw != issuer.subject_raw {
            return None;
        }
        if !verify_signature(current, &issuer.subject_public_key_info) {
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
    trusted_roots: &[&[u8]],
) -> Option<SubjectPublicKeyInfo<'a>> {
    if chain.is_empty() || chain.len() > 8 {
        return None;
    }

    let mut certs: [Option<X509Certificate<'_>>; 8] = [None, None, None, None, None, None, None, None];
    parse_chain_to_array(chain, &mut certs)?;

    // Get current time for validity check
    let now = crate::time::now();

    // Verify all certificates in the chain are currently valid
    for i in 0..chain.len() {
        if let Some(ref cert) = certs[i] {
            if !cert.is_valid_at(now) {
                return None;
            }
        }
    }

    let leaf = certs[0].as_ref()?;
    
    // Security: Secure hostname verification (CN and SAN matching with wildcards)
    if let Some(name) = server_name {
        if !match_hostname(leaf, name) {
            return None;
        }
    }

    if chain.len() > 1 {
        verify_chain_links(&certs, chain.len())?;
        
        // Security: The root of the chain (last cert) must be trusted.
        let root = certs[chain.len() - 1].as_ref()?;
        
        // Check if the root is in the trusted_roots set
        let mut trusted = false;
        for &trust_der in trusted_roots {
            if let Some(trust_cert) = parse_x509(trust_der) {
                if root.subject_raw == trust_cert.subject_raw && 
                   root.subject_public_key_info == trust_cert.subject_public_key_info {
                    // Found a matching trust anchor. Now verify the root's signature
                    // (if it's not the same cert, though usually root CAs are self-signed).
                    if verify_signature(root, &trust_cert.subject_public_key_info) {
                        trusted = true;
                        break;
                    }
                }
            }
        }

        if !trusted {
            return None;
        }
    } else {
        // Security: Single certificate must be directly trusted
        let leaf_der = chain[0];
        let mut trusted = false;
        for &trust_der in trusted_roots {
            if leaf_der == trust_der {
                trusted = true;
                break;
            }
        }
        
        if !trusted {
            return None;
        }
    }

    Some(leaf.subject_public_key_info)
}

/// Common Name (CN) OID: 2.5.4.3 (06 03 55 04 03)
const OID_COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

/// Hostname verification (checks SAN first, then CN)
fn match_hostname(cert: &X509Certificate<'_>, hostname: &str) -> bool {
    // 1. Check SAN (Subject Alternative Name) first (preferred)
    if let Some(san_der) = cert.san_raw {
        if match_hostname_in_san(san_der, hostname) {
            return true;
        }
    }
    // 2. Fallback to CN (Common Name)
    match_hostname_in_subject(cert.subject_raw, hostname)
}

/// SAN (Subject Alternative Name) matching
fn match_hostname_in_san(san_der: &[u8], hostname: &str) -> bool {
    let mut parser = DerParser::new(san_der);
    let mut inner = match parser.read_sequence() {
        Some(c) => DerParser::new(c),
        None => return false,
    };

    while !inner.is_empty() {
        let tag = match inner.read_tag() {
            Some(t) => t,
            None => break,
        };
        let len = inner.read_length().unwrap_or(0);
        if len > inner.remaining().len() {
            break;
        }
        let value = &inner.remaining()[..len];
        inner.pos += len;

        // GeneralName [2] dNSName (Context-specific tag 0x82)
        if tag == 0x82 {
            if match_wildcard(value, hostname) {
                return true;
            }
        }
    }
    false
}

/// Wildcard matching (*.example.com)
fn match_wildcard(pattern: &[u8], hostname: &str) -> bool {
    if pattern == hostname.as_bytes() {
        return true;
    }

    // Handle *.domain.com (RFC 6125)
    if pattern.starts_with(b"*.") && pattern.len() > 2 {
        let suffix = &pattern[1..]; // ".domain.com"
        if hostname.as_bytes().ends_with(suffix) {
            // Ensure the * only matches one label (not subdomains)
            let prefix_len = hostname.len() - suffix.len();
            let prefix = &hostname.as_bytes()[..prefix_len];
            if prefix.len() > 0 && !prefix.contains(&b'.') {
                return true;
            }
        }
    }
    false
}

/// Subjectの生DERからCommon Name (CN) を探し、ホスト名が一致するか検証する
fn match_hostname_in_subject(subject_der: &[u8], hostname: &str) -> bool {
    let mut parser = DerParser::new(subject_der);
    let content = match parser.read_sequence() {
        Some(c) => c,
        None => return false,
    };

    let mut inner = DerParser::new(content);
    while !inner.is_empty() {
        // Name is a SEQUENCE of SETs
        let rdn_content = match inner.read_tag() {
            Some(0x31) => { // SET
                let len = inner.read_length().unwrap_or(0);
                if len > inner.remaining().len() { break; }
                &inner.remaining()[..len]
            }
            _ => break,
        };
        inner.skip_tlv(); // Skip the SET we just peeked into

        let mut rdn_parser = DerParser::new(rdn_content);
        while !rdn_parser.is_empty() {
            // RelativeDistinguishedName is a SEQUENCE of AttributeTypeAndValue
            let atv_content = match rdn_parser.read_sequence() {
                Some(c) => c,
                None => break,
            };
            let mut atv_parser = DerParser::new(atv_content);
            let oid = atv_parser.read_oid().unwrap_or(&[]);
            if oid == OID_COMMON_NAME {
                let (_tag, value) = atv_parser.read_tlv().unwrap_or((0, &[]));
                // Use wildcard matching for CN as well (legacy support)
                if match_wildcard(value, hostname) {
                    return true;
                }
            }
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
            if let SubjectPublicKeyInfo::Rsa { modulus, exponent } = issuer_pubkey {
                let digest = crate::loader::sha512::compute(cert.raw_tbs);
                let key = RsaPublicKey { modulus, exponent };
                rsa_pkcs1_verify(&key, HashAlgorithm::Sha512, &digest, cert.signature_value).is_ok()
            } else {
                false
            }
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
mod tests;
