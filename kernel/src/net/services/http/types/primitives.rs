// ============================================================================
// kernel/src/net/services/http/types/primitives.rs - サービス / HTTP / 型定義 / プリミティブ型
// ============================================================================

use crate::net::payload::PayloadSpanRef;
use core::fmt;
use core::str::FromStr;

/// HTTPメソッド
///
/// /// - カーネル内蔵 HTTP サービスの公開面を最小化するため、
///   現時点では TRACE / CONNECT はサポートしない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
}

impl HttpMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
        }
    }

    fn parse_str(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "DELETE" => Some(Self::Delete),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            "PATCH" => Some(Self::Patch),
            _ => None,
        }
    }

    pub fn parse_span_ref(span: PayloadSpanRef<'_>) -> Option<Self> {
        if span.eq_ignore_ascii_case(b"GET") {
            Some(Self::Get)
        } else if span.eq_ignore_ascii_case(b"POST") {
            Some(Self::Post)
        } else if span.eq_ignore_ascii_case(b"PUT") {
            Some(Self::Put)
        } else if span.eq_ignore_ascii_case(b"DELETE") {
            Some(Self::Delete)
        } else if span.eq_ignore_ascii_case(b"HEAD") {
            Some(Self::Head)
        } else if span.eq_ignore_ascii_case(b"OPTIONS") {
            Some(Self::Options)
        } else if span.eq_ignore_ascii_case(b"PATCH") {
            Some(Self::Patch)
        } else {
            None
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for HttpMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HttpMethod::parse_str(s).ok_or(())
    }
}

/// HTTPバージョン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
}

impl HttpVersion {
    pub fn parse_span_ref(span: PayloadSpanRef<'_>) -> Option<Self> {
        if span.eq_bytes(b"HTTP/1.0") {
            Some(Self::Http1_0)
        } else if span.eq_bytes(b"HTTP/1.1") {
            Some(Self::Http1_1)
        } else {
            None
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVersion::Http1_0 => write!(f, "HTTP/1.0"),
            HttpVersion::Http1_1 => write!(f, "HTTP/1.1"),
        }
    }
}

impl FromStr for HttpVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HTTP/1.0" => Ok(HttpVersion::Http1_0),
            "HTTP/1.1" => Ok(HttpVersion::Http1_1),
            _ => Err(()),
        }
    }
}

/// HTTPステータスコード
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HttpStatusCode(u16);

impl HttpStatusCode {
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const BAD_REQUEST: Self = Self(400);
    pub const NOT_FOUND: Self = Self(404);
    pub const REQUEST_TIMEOUT: Self = Self(408);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);

    pub fn new(code: u16) -> Option<Self> {
        (100..=599).contains(&code).then_some(Self(code))
    }

    pub fn parse_span_ref(span: PayloadSpanRef<'_>) -> Option<Self> {
        let code = span.trim_ascii_whitespace().parse_ascii_usize()?;
        if code > u16::MAX as usize {
            return None;
        }
        Self::new(code as u16)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub const fn reason_phrase(self) -> &'static str {
        match self.0 {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            404 => "Not Found",
            408 => "Request Timeout",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for HttpStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<u16> for HttpStatusCode {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(())
    }
}

/// Connectionヘッダーの制御値
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirective {
    KeepAlive,
    Close,
}

impl ConnectionDirective {
    pub fn parse_span_ref(span: PayloadSpanRef<'_>) -> Option<Self> {
        if span.eq_ignore_ascii_case(b"keep-alive") {
            Some(Self::KeepAlive)
        } else if span.eq_ignore_ascii_case(b"close") {
            Some(Self::Close)
        } else {
            None
        }
    }

    pub const fn as_header_value(self) -> &'static str {
        match self {
            Self::KeepAlive => "keep-alive",
            Self::Close => "close",
        }
    }
}

/// URIスキーム
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    pub const fn is_https(self) -> bool {
        matches!(self, Self::Https)
    }

    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

impl fmt::Display for HttpScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
        }
    }
}

/// HTTPポート番号
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct HttpPort(u16);

impl HttpPort {
    /// HTTP文脈ではポート0を「未指定」と見なすため受け付けない。
    pub fn new(port: u16) -> Option<Self> {
        (port != 0).then_some(Self(port))
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}
