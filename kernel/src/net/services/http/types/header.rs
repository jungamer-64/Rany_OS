use crate::net::payload::{PayloadRange, PayloadSpanRef};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use kernel_api::resource::net::PacketPayload;

fn payload_span_to_string(span: PayloadSpanRef<'_>) -> Option<String> {
    let mut bytes = Vec::new();
    bytes.resize(span.total_len(), 0);
    if span.copy_into(&mut bytes) != bytes.len() {
        return None;
    }
    let text = core::str::from_utf8(&bytes).ok()?;
    Some(String::from(text))
}

fn is_http_token_char(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' |
            b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

fn is_valid_header_name(value: &str) -> bool {
    !value.is_empty() && value.as_bytes().iter().copied().all(is_http_token_char)
}

fn is_valid_header_value(value: &str) -> bool {
    !value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
}

fn is_valid_header_name_span(span: PayloadSpanRef<'_>) -> bool {
    if span.is_empty() {
        return false;
    }

    for index in 0..span.total_len() {
        let Some(byte) = span.byte_at(index) else {
            return false;
        };
        if !is_http_token_char(byte) {
            return false;
        }
    }

    true
}

fn is_valid_header_value_span(span: PayloadSpanRef<'_>) -> bool {
    for index in 0..span.total_len() {
        let Some(byte) = span.byte_at(index) else {
            return false;
        };
        if byte == b'\r' || byte == b'\n' || byte == 0 {
            return false;
        }
    }

    true
}

fn parse_known_header_name(value: &str) -> Option<HttpHeaderName> {
    match value.to_ascii_lowercase().as_str() {
        "host" => Some(HttpHeaderName::Host),
        "connection" => Some(HttpHeaderName::Connection),
        "content-type" => Some(HttpHeaderName::ContentType),
        "content-length" => Some(HttpHeaderName::ContentLength),
        "transfer-encoding" => Some(HttpHeaderName::TransferEncoding),
        "accept" => Some(HttpHeaderName::Accept),
        "user-agent" => Some(HttpHeaderName::UserAgent),
        _ => None,
    }
}

/// HTTPヘッダー名
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpHeaderName {
    Host,
    Connection,
    ContentType,
    ContentLength,
    TransferEncoding,
    Accept,
    UserAgent,
    Custom(String),
}

impl HttpHeaderName {
    pub fn parse(value: &str) -> Option<Self> {
        if !is_valid_header_name(value) {
            return None;
        }

        Some(parse_known_header_name(value).unwrap_or_else(|| Self::Custom(value.to_string())))
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Host => "Host",
            Self::Connection => "Connection",
            Self::ContentType => "Content-Type",
            Self::ContentLength => "Content-Length",
            Self::TransferEncoding => "Transfer-Encoding",
            Self::Accept => "Accept",
            Self::UserAgent => "User-Agent",
            Self::Custom(value) => value.as_str(),
        }
    }

    pub fn eq_ignore_ascii_case(&self, value: &str) -> bool {
        self.as_str().eq_ignore_ascii_case(value)
    }

    pub fn eq_name(&self, other: &Self) -> bool {
        self == other || self.eq_ignore_ascii_case(other.as_str())
    }
}

/// HTTPヘッダー値
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeaderValue(String);

impl HttpHeaderValue {
    pub fn parse(value: &str) -> Option<Self> {
        is_valid_header_value(value).then_some(Self(value.to_string()))
    }

    pub fn from_string(value: String) -> Option<Self> {
        is_valid_header_value(&value).then_some(Self(value))
    }

    pub fn from_static(value: &'static str) -> Self {
        debug_assert!(is_valid_header_value(value));
        Self(String::from(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HttpHeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: HttpHeaderName,
    pub value: HttpHeaderValue,
}

impl HttpHeader {
    pub fn new(name: HttpHeaderName, value: HttpHeaderValue) -> Self {
        Self { name, value }
    }

    pub fn try_new(name: &str, value: &str) -> Option<Self> {
        Some(Self {
            name: HttpHeaderName::parse(name)?,
            value: HttpHeaderValue::parse(value)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HttpHeaderView {
    pub name: PayloadRange,
    pub value: PayloadRange,
}

impl HttpHeaderView {
    pub fn try_new(name: PayloadSpanRef<'_>, value: PayloadSpanRef<'_>) -> Option<Self> {
        if !is_valid_header_name_span(name) || !is_valid_header_value_span(value) {
            return None;
        }

        Some(Self {
            name: name.range(),
            value: value.range(),
        })
    }

    pub fn name_span<'a>(&self, payload: &'a PacketPayload) -> Option<PayloadSpanRef<'a>> {
        self.name.span(payload)
    }

    pub fn value_span<'a>(&self, payload: &'a PacketPayload) -> Option<PayloadSpanRef<'a>> {
        self.value.span(payload)
    }

    pub fn name_eq(&self, payload: &PacketPayload, name: &str) -> bool {
        self.name_span(payload)
            .is_some_and(|span| span.eq_ignore_ascii_case(name.as_bytes()))
    }

    pub fn typed_name(&self, payload: &PacketPayload) -> Option<HttpHeaderName> {
        HttpHeaderName::parse(&payload_span_to_string(self.name_span(payload)?)?)
    }

    pub fn typed_value(&self, payload: &PacketPayload) -> Option<HttpHeaderValue> {
        HttpHeaderValue::parse(&payload_span_to_string(self.value_span(payload)?)?)
    }
}
