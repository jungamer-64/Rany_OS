// ============================================================================
// kernel/src/net/security/x509/mod.rs - packet-backed X.509 parsing
// ============================================================================

use arrayvec::ArrayVec;

use crate::net::payload::PayloadSpanRef;

const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_SHA384_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
const OID_SHA512_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_SECP256R1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
const OID_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x1E];
const OID_EKU_SERVER_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_RSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithmId {
    Sha256WithRsa,
    Sha384WithRsa,
    Sha512WithRsa,
    EcdsaWithSha256,
    EcdsaWithSha384,
    RsaPss,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubjectPublicKeyInfo {
    Rsa {
        modulus: ArrayVec<u8, 1024>,
        exponent: ArrayVec<u8, 8>,
    },
    EcdsaP256 {
        public_key: ArrayVec<u8, 65>,
    },
    EcdsaP384 {
        public_key: ArrayVec<u8, 97>,
    },
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub key_encipherment: bool,
    pub key_cert_sign: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExtendedKeyUsage {
    pub server_auth: bool,
}

#[derive(Debug)]
pub struct X509Certificate<'a> {
    pub raw_tbs: PayloadSpanRef<'a>,
    pub signature_algorithm: SignatureAlgorithmId,
    pub issuer_raw: PayloadSpanRef<'a>,
    pub subject_raw: PayloadSpanRef<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub signature_value: PayloadSpanRef<'a>,
    pub not_before: u64,
    pub not_after: u64,
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
    pub san_raw: Option<PayloadSpanRef<'a>>,
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usage: Option<ExtendedKeyUsage>,
}

impl X509Certificate<'_> {
    pub fn is_valid_at(&self, unix_secs: u64) -> bool {
        unix_secs >= self.not_before && unix_secs <= self.not_after
    }
}

#[derive(Clone, Copy)]
struct DerTlv<'a> {
    tag: u8,
    value: PayloadSpanRef<'a>,
    full: PayloadSpanRef<'a>,
}

struct DerCursor<'a> {
    span: PayloadSpanRef<'a>,
    pos: usize,
}

impl<'a> DerCursor<'a> {
    const fn new(span: PayloadSpanRef<'a>) -> Self {
        Self { span, pos: 0 }
    }

    const fn position(&self) -> usize {
        self.pos
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.span.total_len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.span.read_u8(self.pos)
    }

    fn read_u8(&mut self) -> Option<u8> {
        let byte = self.span.read_u8(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn read_length(&mut self) -> Option<usize> {
        let first = self.read_u8()?;
        if first < 0x80 {
            return Some(first as usize);
        }
        if first == 0x80 {
            return None;
        }
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = length.checked_shl(8)?;
            length = length.checked_add(self.read_u8()? as usize)?;
        }
        Some(length)
    }

    fn read_tlv(&mut self) -> Option<DerTlv<'a>> {
        let start = self.pos;
        let tag = self.read_u8()?;
        let length = self.read_length()?;
        let value_start = self.pos;
        let end = value_start.checked_add(length)?;
        if end > self.span.total_len() {
            return None;
        }
        self.pos = end;
        Some(DerTlv {
            tag,
            value: self.span.subspan(value_start, length)?,
            full: self.span.subspan(start, end - start)?,
        })
    }

    fn read_tlv_tag(&mut self, expected: u8) -> Option<DerTlv<'a>> {
        let tlv = self.read_tlv()?;
        (tlv.tag == expected).then_some(tlv)
    }

    fn read_sequence(&mut self) -> Option<DerTlv<'a>> {
        self.read_tlv_tag(0x30)
    }

    fn read_integer(&mut self) -> Option<PayloadSpanRef<'a>> {
        Some(self.read_tlv_tag(0x02)?.value)
    }

    fn read_oid(&mut self) -> Option<PayloadSpanRef<'a>> {
        Some(self.read_tlv_tag(0x06)?.value)
    }

    fn read_bitstring(&mut self) -> Option<PayloadSpanRef<'a>> {
        let value = self.read_tlv_tag(0x03)?.value;
        if value.is_empty() {
            return None;
        }
        value.subspan(1, value.total_len() - 1)
    }

    fn read_octet_string(&mut self) -> Option<PayloadSpanRef<'a>> {
        Some(self.read_tlv_tag(0x04)?.value)
    }

    fn skip_tlv(&mut self) -> Option<()> {
        self.read_tlv()?;
        Some(())
    }
}

fn span_to_arrayvec<const N: usize>(span: PayloadSpanRef<'_>) -> Option<ArrayVec<u8, N>> {
    let mut out = ArrayVec::new();
    let mut ok = true;
    span.for_each_chunk(|chunk| {
        for byte in chunk {
            if out.try_push(*byte).is_err() {
                ok = false;
                break;
            }
        }
    });
    ok.then_some(out)
}

fn parse_signature_algorithm_id(oid: PayloadSpanRef<'_>) -> SignatureAlgorithmId {
    if oid.eq_bytes(OID_SHA256_WITH_RSA) {
        SignatureAlgorithmId::Sha256WithRsa
    } else if oid.eq_bytes(OID_SHA384_WITH_RSA) {
        SignatureAlgorithmId::Sha384WithRsa
    } else if oid.eq_bytes(OID_SHA512_WITH_RSA) {
        SignatureAlgorithmId::Sha512WithRsa
    } else if oid.eq_bytes(OID_ECDSA_WITH_SHA256) {
        SignatureAlgorithmId::EcdsaWithSha256
    } else if oid.eq_bytes(OID_ECDSA_WITH_SHA384) {
        SignatureAlgorithmId::EcdsaWithSha384
    } else if oid.eq_bytes(OID_RSA_PSS) {
        SignatureAlgorithmId::RsaPss
    } else {
        SignatureAlgorithmId::Unknown
    }
}

fn is_der_null(tlv: DerTlv<'_>) -> bool {
    tlv.tag == 0x05 && tlv.value.is_empty()
}

fn parse_signature_algorithm(value: PayloadSpanRef<'_>) -> Option<SignatureAlgorithmId> {
    let mut cursor = DerCursor::new(value);
    let oid = cursor.read_oid()?;
    let algorithm = parse_signature_algorithm_id(oid);
    if matches!(algorithm, SignatureAlgorithmId::Unknown) {
        return None;
    }
    let params = if cursor.is_empty() {
        None
    } else {
        Some(cursor.read_tlv()?)
    };
    if !cursor.is_empty() {
        return None;
    }
    match algorithm {
        SignatureAlgorithmId::Sha256WithRsa
        | SignatureAlgorithmId::Sha384WithRsa
        | SignatureAlgorithmId::Sha512WithRsa => {
            if params.is_none() || params.is_some_and(is_der_null) {
                Some(algorithm)
            } else {
                None
            }
        }
        SignatureAlgorithmId::EcdsaWithSha256 | SignatureAlgorithmId::EcdsaWithSha384 => {
            params.is_none().then_some(algorithm)
        }
        SignatureAlgorithmId::RsaPss => None,
        SignatureAlgorithmId::Unknown => None,
    }
}

fn parse_two_digits(data: &[u8], offset: usize) -> Option<u32> {
    let d1 = data.get(offset)?.wrapping_sub(b'0') as u32;
    let d2 = data.get(offset + 1)?.wrapping_sub(b'0') as u32;
    if d1 > 9 || d2 > 9 {
        return None;
    }
    Some(d1 * 10 + d2)
}

fn parse_four_digits(data: &[u8], offset: usize) -> Option<u32> {
    Some(parse_two_digits(data, offset)? * 100 + parse_two_digits(data, offset + 2)?)
}

const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn datetime_to_unix(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<u64> {
    if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 1..month {
        days += DAYS_IN_MONTH[(m - 1) as usize] as u64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    days += (day - 1) as u64;
    Some(days * 86_400 + hour as u64 * 3_600 + min as u64 * 60 + sec as u64)
}

fn parse_time_value(tag: u8, value: PayloadSpanRef<'_>) -> Option<u64> {
    let bytes = value.read_fixed_bytes::<32>(value.total_len())?;
    let data = bytes.as_slice();
    match tag {
        0x17 => {
            if data.len() < 13 || data[12] != b'Z' {
                return None;
            }
            let yy = parse_two_digits(data, 0)?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            datetime_to_unix(
                year,
                parse_two_digits(data, 2)?,
                parse_two_digits(data, 4)?,
                parse_two_digits(data, 6)?,
                parse_two_digits(data, 8)?,
                parse_two_digits(data, 10)?,
            )
        }
        0x18 => {
            if data.len() < 15 || data[14] != b'Z' {
                return None;
            }
            datetime_to_unix(
                parse_four_digits(data, 0)?,
                parse_two_digits(data, 4)?,
                parse_two_digits(data, 6)?,
                parse_two_digits(data, 8)?,
                parse_two_digits(data, 10)?,
                parse_two_digits(data, 12)?,
            )
        }
        _ => None,
    }
}

fn parse_validity(tbs: &mut DerCursor<'_>) -> Option<(u64, u64)> {
    let validity = tbs.read_sequence()?;
    let mut cursor = DerCursor::new(validity.value);
    let not_before = cursor
        .read_tlv()
        .and_then(|tlv| parse_time_value(tlv.tag, tlv.value))?;
    let not_after = cursor
        .read_tlv()
        .and_then(|tlv| parse_time_value(tlv.tag, tlv.value))?;
    Some((not_before, not_after))
}

fn parse_spki(spki: PayloadSpanRef<'_>) -> Option<SubjectPublicKeyInfo> {
    let mut cursor = DerCursor::new(spki);
    let alg = cursor.read_sequence()?.value;
    let mut alg_cursor = DerCursor::new(alg);
    let alg_oid = alg_cursor.read_oid()?;
    let pubkey_bits = cursor.read_bitstring()?;

    if alg_oid.eq_bytes(OID_RSA_ENCRYPTION) {
        if !alg_cursor.is_empty() {
            let params = alg_cursor.read_tlv()?;
            if !is_der_null(params) || !alg_cursor.is_empty() {
                return None;
            }
        }
        let mut rsa = DerCursor::new(pubkey_bits);
        let rsa_seq = rsa.read_sequence()?.value;
        let mut rsa_inner = DerCursor::new(rsa_seq);
        let mut modulus = rsa_inner.read_integer()?;
        if modulus.total_len() > 1 && modulus.byte_at(0) == Some(0) {
            modulus = modulus.subspan(1, modulus.total_len() - 1)?;
        }
        let exponent = rsa_inner.read_integer()?;
        return Some(SubjectPublicKeyInfo::Rsa {
            modulus: span_to_arrayvec(modulus)?,
            exponent: span_to_arrayvec(exponent)?,
        });
    }

    if alg_oid.eq_bytes(OID_EC_PUBLIC_KEY) {
        let curve_oid = alg_cursor.read_oid()?;
        if !alg_cursor.is_empty() {
            return None;
        }
        if curve_oid.eq_bytes(OID_SECP256R1) {
            return Some(SubjectPublicKeyInfo::EcdsaP256 {
                public_key: span_to_arrayvec(pubkey_bits)?,
            });
        }
        if curve_oid.eq_bytes(OID_SECP384R1) {
            return Some(SubjectPublicKeyInfo::EcdsaP384 {
                public_key: span_to_arrayvec(pubkey_bits)?,
            });
        }
    }

    Some(SubjectPublicKeyInfo::Unknown)
}

fn parse_tbs_preamble(tbs: &mut DerCursor<'_>) -> Option<SignatureAlgorithmId> {
    if tbs.peek_tag() == Some(0xA0) {
        tbs.skip_tlv()?;
    }
    tbs.skip_tlv()?;
    let sig_alg = tbs.read_sequence()?.value;
    parse_signature_algorithm(sig_alg)
}

fn parse_basic_constraints(value: PayloadSpanRef<'_>) -> (bool, Option<u32>) {
    let Some(seq) = DerCursor::new(value).read_sequence() else {
        return (false, None);
    };
    let mut inner = DerCursor::new(seq.value);
    let mut is_ca = false;
    if inner.peek_tag() == Some(0x01) {
        if let Some(boolean) = inner.read_tlv() {
            is_ca = boolean.value.byte_at(0).unwrap_or(0) != 0;
        }
    }
    let path_len = if inner.peek_tag() == Some(0x02) {
        let mut value = 0u32;
        let integer = inner.read_integer();
        if let Some(integer) = integer {
            for index in 0..integer.total_len() {
                value = (value << 8) | integer.byte_at(index).unwrap_or(0) as u32;
            }
            Some(value)
        } else {
            None
        }
    } else {
        None
    };
    (is_ca, path_len)
}

fn parse_key_usage(value: PayloadSpanRef<'_>) -> Option<KeyUsage> {
    let bits = DerCursor::new(value).read_bitstring()?;
    let first = bits.byte_at(0).unwrap_or(0);
    Some(KeyUsage {
        digital_signature: (first & 0x80) != 0,
        key_encipherment: (first & 0x20) != 0,
        key_cert_sign: (first & 0x04) != 0,
    })
}

fn parse_extended_key_usage(value: PayloadSpanRef<'_>) -> Option<ExtendedKeyUsage> {
    let seq = DerCursor::new(value).read_sequence()?;
    let mut cursor = DerCursor::new(seq.value);
    let mut usage = ExtendedKeyUsage::default();
    while !cursor.is_empty() {
        let oid = cursor.read_oid()?;
        if oid.eq_bytes(OID_EKU_SERVER_AUTH) {
            usage.server_auth = true;
        }
    }
    Some(usage)
}

#[derive(Default)]
struct ParsedExtensions<'a> {
    is_ca: bool,
    path_len_constraint: Option<u32>,
    san_raw: Option<PayloadSpanRef<'a>>,
    key_usage: Option<KeyUsage>,
    extended_key_usage: Option<ExtendedKeyUsage>,
}

fn parse_extensions<'a>(tbs: &mut DerCursor<'a>) -> Option<ParsedExtensions<'a>> {
    let mut parsed = ParsedExtensions::default();
    while !tbs.is_empty() {
        let tlv = tbs.read_tlv()?;
        if tlv.tag != 0xA3 {
            continue;
        }
        let ext_seq = DerCursor::new(tlv.value).read_sequence()?;
        let mut extensions = DerCursor::new(ext_seq.value);
        while !extensions.is_empty() {
            let ext = extensions.read_sequence()?;
            let mut item = DerCursor::new(ext.value);
            let oid = item.read_oid()?;
            let critical = if item.peek_tag() == Some(0x01) {
                let value = item.read_tlv()?;
                value.value.byte_at(0).unwrap_or(0) != 0
            } else {
                false
            };
            let value = item.read_octet_string()?;
            if !item.is_empty() {
                return None;
            }
            if oid.eq_bytes(OID_BASIC_CONSTRAINTS) {
                let constraints = parse_basic_constraints(value);
                parsed.is_ca = constraints.0;
                parsed.path_len_constraint = constraints.1;
            } else if oid.eq_bytes(OID_SUBJECT_ALT_NAME) {
                parsed.san_raw = Some(value);
            } else if oid.eq_bytes(OID_KEY_USAGE) {
                parsed.key_usage = Some(parse_key_usage(value)?);
            } else if oid.eq_bytes(OID_EXTENDED_KEY_USAGE) {
                parsed.extended_key_usage = Some(parse_extended_key_usage(value)?);
            } else if critical || oid.eq_bytes(OID_NAME_CONSTRAINTS) {
                return None;
            }
        }
    }
    Some(parsed)
}

fn parse_tbs_fields<'a>(
    tbs_content: PayloadSpanRef<'a>,
) -> Option<(
    SignatureAlgorithmId,
    PayloadSpanRef<'a>,
    PayloadSpanRef<'a>,
    SubjectPublicKeyInfo,
    u64,
    u64,
    bool,
    Option<u32>,
    Option<PayloadSpanRef<'a>>,
    Option<KeyUsage>,
    Option<ExtendedKeyUsage>,
)> {
    let mut tbs = DerCursor::new(tbs_content);
    let signature_algorithm = parse_tbs_preamble(&mut tbs)?;
    let issuer_raw = tbs.read_tlv()?.full;
    let (not_before, not_after) = parse_validity(&mut tbs)?;
    let subject_raw = tbs.read_tlv()?.full;
    let spki = tbs.read_sequence()?.value;
    let subject_public_key_info = parse_spki(spki)?;

    let extensions = parse_extensions(&mut tbs)?;

    Some((
        signature_algorithm,
        issuer_raw,
        subject_raw,
        subject_public_key_info,
        not_before,
        not_after,
        extensions.is_ca,
        extensions.path_len_constraint,
        extensions.san_raw,
        extensions.key_usage,
        extensions.extended_key_usage,
    ))
}

pub fn parse_x509_certificate<'a>(der: PayloadSpanRef<'a>) -> Option<X509Certificate<'a>> {
    let outer = DerCursor::new(der).read_sequence()?;
    let mut cert = DerCursor::new(outer.value);
    let tbs = cert.read_sequence()?;
    let (
        signature_algorithm,
        issuer_raw,
        subject_raw,
        subject_public_key_info,
        not_before,
        not_after,
        is_ca,
        path_len_constraint,
        san_raw,
        key_usage,
        extended_key_usage,
    ) = parse_tbs_fields(tbs.value)?;
    let outer_signature_algorithm = parse_signature_algorithm(cert.read_sequence()?.value)?;
    if outer_signature_algorithm != signature_algorithm {
        return None;
    }
    let signature_value = cert.read_bitstring()?;

    Some(X509Certificate {
        raw_tbs: tbs.full,
        signature_algorithm,
        issuer_raw,
        subject_raw,
        subject_public_key_info,
        signature_value,
        not_before,
        not_after,
        is_ca,
        path_len_constraint,
        san_raw,
        key_usage,
        extended_key_usage,
    })
}

fn span_eq(a: PayloadSpanRef<'_>, b: PayloadSpanRef<'_>) -> bool {
    a.total_len() == b.total_len()
        && (0..a.total_len()).all(|index| a.byte_at(index) == b.byte_at(index))
}

fn verify_chain_links(certs: &[X509Certificate<'_>]) -> Option<()> {
    for index in 0..certs.len().saturating_sub(1) {
        let current = &certs[index];
        let issuer = &certs[index + 1];
        if !issuer.is_ca || !span_eq(current.issuer_raw, issuer.subject_raw) {
            return None;
        }
        if let Some(key_usage) = issuer.key_usage {
            if !key_usage.key_cert_sign {
                return None;
            }
        }
        if let Some(path_len) = issuer.path_len_constraint {
            let subordinate_ca_count =
                certs[..=index].iter().filter(|cert| cert.is_ca).count() as u32;
            if subordinate_ca_count > path_len {
                return None;
            }
        }
        if !verify_signature(current, &issuer.subject_public_key_info) {
            return None;
        }
    }
    Some(())
}

pub fn validate_certificate_chain<'a, 'b>(
    chain: &[PayloadSpanRef<'a>],
    server_name: Option<&str>,
    trusted_roots: &[PayloadSpanRef<'b>],
) -> Option<SubjectPublicKeyInfo> {
    if chain.is_empty() || chain.len() > 8 {
        return None;
    }

    let mut certs = ArrayVec::<X509Certificate<'a>, 8>::new();
    for cert in chain {
        certs.try_push(parse_x509_certificate(*cert)?).ok()?;
    }

    let now = crate::drivers::time::unix_timestamp();
    for cert in &certs {
        if !cert.is_valid_at(now) {
            return None;
        }
    }

    let leaf = certs.first()?;
    if let Some(key_usage) = leaf.key_usage {
        if !key_usage.digital_signature && !key_usage.key_encipherment {
            return None;
        }
    }
    if let Some(eku) = leaf.extended_key_usage {
        if !eku.server_auth {
            return None;
        }
    }
    if let Some(name) = server_name {
        if !match_hostname(leaf, name) {
            return None;
        }
    }

    if certs.len() > 1 {
        verify_chain_links(certs.as_slice())?;
    }

    let chain_tip = certs.last()?;
    let mut trusted = false;
    for trust in trusted_roots {
        let trust_cert = parse_x509_certificate(*trust)?;
        let issued_by_trust = span_eq(chain_tip.issuer_raw, trust_cert.subject_raw)
            && verify_signature(chain_tip, &trust_cert.subject_public_key_info);
        let exact_trust = span_eq(chain_tip.subject_raw, trust_cert.subject_raw)
            && chain_tip.subject_public_key_info == trust_cert.subject_public_key_info;
        if issued_by_trust || exact_trust {
            trusted = true;
            break;
        }
    }
    if trusted {
        Some(certs.remove(0).subject_public_key_info)
    } else {
        None
    }
}

fn match_hostname(cert: &X509Certificate<'_>, hostname: &str) -> bool {
    if let Some(san) = cert.san_raw {
        return match_hostname_in_san(san, hostname);
    }
    match_hostname_in_subject(cert.subject_raw, hostname)
}

fn match_hostname_in_san(san_der: PayloadSpanRef<'_>, hostname: &str) -> bool {
    let Some(seq) = DerCursor::new(san_der).read_sequence() else {
        return false;
    };
    let mut names = DerCursor::new(seq.value);
    while let Some(name) = names.read_tlv() {
        if name.tag == 0x82 && match_dns_name(name.value, hostname) {
            return true;
        }
        if name.tag == 0x87 && match_ip_address(name.value, hostname) {
            return true;
        }
    }
    false
}

fn match_hostname_in_subject(subject_der: PayloadSpanRef<'_>, hostname: &str) -> bool {
    let Some(seq) = DerCursor::new(subject_der).read_sequence() else {
        return false;
    };
    let mut rdns = DerCursor::new(seq.value);
    while let Some(rdn) = rdns.read_tlv() {
        if rdn.tag != 0x31 {
            return false;
        }
        let mut attrs = DerCursor::new(rdn.value);
        while let Some(attr) = attrs.read_sequence() {
            let mut attr = DerCursor::new(attr.value);
            let oid = attr.read_oid();
            let value = attr.read_tlv();
            if let (Some(oid), Some(value)) = (oid, value) {
                if oid.eq_bytes(OID_COMMON_NAME) && match_dns_name(value.value, hostname) {
                    return true;
                }
            }
        }
    }
    false
}

fn match_dns_name(pattern: PayloadSpanRef<'_>, hostname: &str) -> bool {
    let Some(bytes) = span_to_arrayvec::<253>(pattern) else {
        return false;
    };
    match_wildcard(bytes.as_slice(), hostname)
}

fn match_wildcard(pattern: &[u8], hostname: &str) -> bool {
    if ascii_eq_ignore_case(pattern, hostname.as_bytes()) {
        return true;
    }
    if !pattern.starts_with(b"*.") || pattern.len() <= 2 {
        return false;
    }
    let suffix = &pattern[1..];
    let Ok(suffix_str) = core::str::from_utf8(&suffix[1..]) else {
        return false;
    };
    if suffix_str.split('.').count() < 2 {
        return false;
    }
    if ascii_ends_with_ignore_case(hostname.as_bytes(), suffix) {
        let prefix_len = hostname.len() - suffix.len();
        let prefix = &hostname.as_bytes()[..prefix_len];
        return !prefix.is_empty() && !prefix.contains(&b'.');
    }
    false
}

fn ascii_eq_ignore_case(lhs: &[u8], rhs: &[u8]) -> bool {
    lhs.len() == rhs.len()
        && lhs
            .iter()
            .zip(rhs.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn ascii_ends_with_ignore_case(value: &[u8], suffix: &[u8]) -> bool {
    value.len() >= suffix.len()
        && ascii_eq_ignore_case(&value[value.len() - suffix.len()..], suffix)
}

fn parse_ipv4_literal(hostname: &str) -> Option<[u8; 4]> {
    let mut parts = [0u8; 4];
    let mut index = 0usize;
    for part in hostname.split('.') {
        if index == 4 || part.is_empty() || part.len() > 3 {
            return None;
        }
        let mut value = 0u16;
        for byte in part.as_bytes() {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + u16::from(byte - b'0');
            if value > 255 {
                return None;
            }
        }
        parts[index] = value as u8;
        index += 1;
    }
    (index == 4).then_some(parts)
}

fn match_ip_address(value: PayloadSpanRef<'_>, hostname: &str) -> bool {
    if value.total_len() == 4 {
        if let Some(ipv4) = parse_ipv4_literal(hostname) {
            return (0..4).all(|index| value.byte_at(index) == Some(ipv4[index]));
        }
    }
    false
}

fn sha256_span(span: PayloadSpanRef<'_>) -> [u8; 32] {
    let mut hasher = crate::crypto::sha256::Sha256::new();
    span.for_each_chunk(|chunk| hasher.update(chunk));
    hasher.finalize()
}

fn sha384_span(span: PayloadSpanRef<'_>) -> [u8; 48] {
    let mut hasher = crate::crypto::sha384::Sha384::new();
    span.for_each_chunk(|chunk| hasher.update(chunk));
    hasher.finalize()
}

fn sha512_span(span: PayloadSpanRef<'_>) -> [u8; 64] {
    let mut hasher = crate::crypto::sha512::Sha512::new();
    span.for_each_chunk(|chunk| hasher.update(chunk));
    hasher.finalize()
}

fn verify_signature(cert: &X509Certificate<'_>, issuer_pubkey: &SubjectPublicKeyInfo) -> bool {
    use crate::net::security::rsa::{
        HashAlgorithm, RsaPublicKey, rsa_pkcs1_verify, rsa_pss_verify,
    };
    let Some(signature) = span_to_arrayvec::<1024>(cert.signature_value) else {
        return false;
    };

    match (cert.signature_algorithm, issuer_pubkey) {
        (SignatureAlgorithmId::Sha256WithRsa, SubjectPublicKeyInfo::Rsa { modulus, exponent }) => {
            let digest = sha256_span(cert.raw_tbs);
            let key = RsaPublicKey {
                modulus: modulus.as_slice(),
                exponent: exponent.as_slice(),
            };
            rsa_pkcs1_verify(&key, HashAlgorithm::Sha256, &digest, signature.as_slice()).is_ok()
        }
        (SignatureAlgorithmId::Sha384WithRsa, SubjectPublicKeyInfo::Rsa { modulus, exponent }) => {
            let digest = sha384_span(cert.raw_tbs);
            let key = RsaPublicKey {
                modulus: modulus.as_slice(),
                exponent: exponent.as_slice(),
            };
            rsa_pkcs1_verify(&key, HashAlgorithm::Sha384, &digest, signature.as_slice()).is_ok()
        }
        (SignatureAlgorithmId::Sha512WithRsa, SubjectPublicKeyInfo::Rsa { modulus, exponent }) => {
            let digest = sha512_span(cert.raw_tbs);
            let key = RsaPublicKey {
                modulus: modulus.as_slice(),
                exponent: exponent.as_slice(),
            };
            rsa_pkcs1_verify(&key, HashAlgorithm::Sha512, &digest, signature.as_slice()).is_ok()
        }
        (SignatureAlgorithmId::RsaPss, SubjectPublicKeyInfo::Rsa { modulus, exponent }) => {
            let digest = sha256_span(cert.raw_tbs);
            let key = RsaPublicKey {
                modulus: modulus.as_slice(),
                exponent: exponent.as_slice(),
            };
            rsa_pss_verify(&key, HashAlgorithm::Sha256, &digest, signature.as_slice()).is_ok()
        }
        (SignatureAlgorithmId::EcdsaWithSha256, SubjectPublicKeyInfo::EcdsaP256 { public_key }) => {
            let digest = sha256_span(cert.raw_tbs);
            crate::net::security::ecdh::p256::ecdsa_p256_verify(
                public_key.as_slice(),
                &digest,
                signature.as_slice(),
            )
            .is_ok()
        }
        (SignatureAlgorithmId::EcdsaWithSha384, SubjectPublicKeyInfo::EcdsaP384 { public_key }) => {
            let digest = sha384_span(cert.raw_tbs);
            crate::net::security::ecdh::p384::ecdsa_p384_verify(
                public_key.as_slice(),
                &digest,
                signature.as_slice(),
            )
            .is_ok()
        }
        _ => false,
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
const TEST_CERT_DER: [u8; 154] = [
    0x30, 0x81, 0x97, 0x30, 0x7F, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x0F, 0x31, 0x0D,
    0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 0x54, 0x65, 0x73, 0x74, 0x30, 0x1E, 0x17,
    0x0D, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D,
    0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x0F, 0x31,
    0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x04, 0x54, 0x65, 0x73, 0x74, 0x30, 0x24,
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
    0x13, 0x00, 0x30, 0x10, 0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02,
    0x03, 0x01, 0x00, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x0B, 0x05, 0x00, 0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
];

#[cfg(any(test, feature = "qemu-test-export"))]
fn test_cert_payload() -> kernel_api::resource::net::PacketPayload {
    let mut packet =
        crate::net::payload::alloc_packet_with_headroom(TEST_CERT_DER.len(), 0).unwrap();
    packet.data_mut().copy_from_slice(&TEST_CERT_DER);
    kernel_api::resource::net::PacketPayload::single(packet)
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn x509_der_parse_tag_length_smoke() -> bool {
        let payload = test_cert_payload();
        let span = PayloadSpanRef::from_payload(&payload);
        let Some(tlv) = DerCursor::new(span).read_tlv() else {
            return false;
        };
        tlv.tag == 0x30 && tlv.value.total_len() == 151
    }

    pub fn x509_der_parse_integer_smoke() -> bool {
        let payload = test_cert_payload();
        let span = PayloadSpanRef::from_payload(&payload);
        let Some(cert) = parse_x509_certificate(span) else {
            return false;
        };
        matches!(
            cert.subject_public_key_info,
            SubjectPublicKeyInfo::Rsa { ref modulus, .. } if modulus.len() == 8
        )
    }

    pub fn x509_der_parse_sequence_smoke() -> bool {
        let payload = test_cert_payload();
        parse_x509_certificate(PayloadSpanRef::from_payload(&payload)).is_some()
    }

    pub fn x509_parse_self_signed_smoke() -> bool {
        let payload = test_cert_payload();
        let Some(cert) = parse_x509_certificate(PayloadSpanRef::from_payload(&payload)) else {
            return false;
        };
        cert.raw_tbs.total_len() == 129
            && cert.signature_algorithm == SignatureAlgorithmId::Sha256WithRsa
            && cert.signature_value.eq_bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
    }

    pub fn x509_extract_rsa_pubkey_smoke() -> bool {
        let payload = test_cert_payload();
        let Some(cert) = parse_x509_certificate(PayloadSpanRef::from_payload(&payload)) else {
            return false;
        };
        match cert.subject_public_key_info {
            SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                modulus.len() == 8
                    && modulus.iter().all(|byte| *byte == 0xFF)
                    && exponent.as_slice() == [0x01, 0x00, 0x01]
            }
            _ => false,
        }
    }

    pub fn x509_signature_algorithm_oid_smoke() -> bool {
        let payload = test_cert_payload();
        let Some(cert) = parse_x509_certificate(PayloadSpanRef::from_payload(&payload)) else {
            return false;
        };
        cert.signature_algorithm == SignatureAlgorithmId::Sha256WithRsa
    }
}

#[cfg(test)]
mod tests;
