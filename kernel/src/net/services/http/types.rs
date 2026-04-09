// ============================================================================
// kernel/src/net/services/http/types.rs
// ============================================================================

use crate::net::payload::{PacketPayloadBuilder, PayloadSpan};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use kernel_api::resource::net::PacketPayload;

fn payload_span_to_string(span: &PayloadSpan) -> Option<String> {
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

fn is_valid_request_target(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if value != "*" && !value.starts_with('/') {
        return false;
    }
    !value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
}

fn parse_http_port(value: &str) -> Option<HttpPort> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let parsed: u16 = value.parse().ok()?;
    HttpPort::new(parsed)
}

fn parse_bracketed_host(value: &str) -> Option<HttpHost> {
    if !value.ends_with(']') || value.len() <= 2 {
        return None;
    }
    let inner = &value[1..value.len() - 1];
    if inner.is_empty() {
        return None;
    }
    if inner.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || byte == b'/'
            || byte == b'?'
            || byte == b'#'
    }) {
        return None;
    }
    Some(HttpHost(value.to_string()))
}

fn parse_plain_host(value: &str) -> Option<HttpHost> {
    if value.is_empty() || value.contains(':') {
        return None;
    }
    if value.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || byte == b'/'
            || byte == b'?'
            || byte == b'#'
    }) {
        return None;
    }
    Some(HttpHost(value.to_string()))
}

fn parse_bracketed_authority(
    authority: &str,
    default_port: HttpPort,
) -> Option<(HttpHost, HttpPort)> {
    let end = authority.find(']')?;
    let host = HttpHost::parse(&authority[..=end])?;
    if end + 1 == authority.len() {
        return Some((host, default_port));
    }

    let suffix = &authority[end + 1..];
    if !suffix.starts_with(':') {
        return None;
    }
    let port = parse_http_port(&suffix[1..])?;
    Some((host, port))
}

fn parse_plain_authority(authority: &str, default_port: HttpPort) -> Option<(HttpHost, HttpPort)> {
    if let Some((host_part, port_part)) = authority.rsplit_once(':') {
        if host_part.contains(':') {
            return None;
        }
        let host = HttpHost::parse(host_part)?;
        let port = parse_http_port(port_part)?;
        Some((host, port))
    } else {
        Some((HttpHost::parse(authority)?, default_port))
    }
}

fn parse_host_and_port(authority: &str, default_port: HttpPort) -> Option<(HttpHost, HttpPort)> {
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        return parse_bracketed_authority(authority, default_port);
    }

    parse_plain_authority(authority, default_port)
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

/// HTTPメソッド
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
    pub fn parse_span(span: &PayloadSpan) -> Option<Self> {
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
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Patch => write!(f, "PATCH"),
        }
    }
}

impl FromStr for HttpMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "PATCH" => Ok(HttpMethod::Patch),
            _ => Err(()),
        }
    }
}

/// HTTPバージョン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
}

impl HttpVersion {
    pub fn parse_span(span: &PayloadSpan) -> Option<Self> {
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

    pub fn parse_span(span: &PayloadSpan) -> Option<Self> {
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
    pub fn parse_span(span: &PayloadSpan) -> Option<Self> {
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
    pub fn new(port: u16) -> Option<Self> {
        (port != 0).then_some(Self(port))
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// HTTPホスト
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpHost(String);

impl HttpHost {
    pub fn parse(value: &str) -> Option<Self> {
        if value.starts_with('[') {
            return parse_bracketed_host(value);
        }

        parse_plain_host(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HttpHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// HTTP request-target (origin-form)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpRequestTarget(String);

impl HttpRequestTarget {
    pub fn parse(value: &str) -> Option<Self> {
        is_valid_request_target(value).then_some(Self(value.to_string()))
    }

    pub fn root() -> Self {
        Self(String::from("/"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HttpRequestTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// HTTP request URI (client向け)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpRequestUri {
    OriginForm(HttpRequestTarget),
    Absolute {
        scheme: HttpScheme,
        host: HttpHost,
        port: HttpPort,
        target: HttpRequestTarget,
    },
}

impl HttpRequestUri {
    pub fn parse(value: &str) -> Option<Self> {
        if let Some(rest) = value.strip_prefix("https://") {
            return Self::parse_absolute(HttpScheme::Https, rest);
        }
        if let Some(rest) = value.strip_prefix("http://") {
            return Self::parse_absolute(HttpScheme::Http, rest);
        }
        Self::origin_form(value)
    }

    pub fn origin_form(value: &str) -> Option<Self> {
        Some(Self::OriginForm(HttpRequestTarget::parse(value)?))
    }

    pub fn absolute(
        scheme: HttpScheme,
        host: HttpHost,
        port: HttpPort,
        target: HttpRequestTarget,
    ) -> Self {
        Self::Absolute {
            scheme,
            host,
            port,
            target,
        }
    }

    pub fn as_request_target(&self) -> &HttpRequestTarget {
        match self {
            Self::OriginForm(target) => target,
            Self::Absolute { target, .. } => target,
        }
    }

    pub fn into_request_target(self) -> HttpRequestTarget {
        match self {
            Self::OriginForm(target) => target,
            Self::Absolute { target, .. } => target,
        }
    }

    pub fn as_absolute(&self) -> Option<(HttpScheme, &HttpHost, HttpPort, &HttpRequestTarget)> {
        match self {
            Self::Absolute {
                scheme,
                host,
                port,
                target,
            } => Some((*scheme, host, *port, target)),
            Self::OriginForm(_) => None,
        }
    }

    fn parse_absolute(scheme: HttpScheme, rest: &str) -> Option<Self> {
        let slash_idx = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..slash_idx];
        let target = if slash_idx == rest.len() {
            HttpRequestTarget::root()
        } else {
            HttpRequestTarget::parse(&rest[slash_idx..])?
        };

        let default_port = HttpPort::new(scheme.default_port())?;
        let (host, port) = parse_host_and_port(authority, default_port)?;

        Some(Self::Absolute {
            scheme,
            host,
            port,
            target,
        })
    }
}

impl fmt::Display for HttpRequestUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OriginForm(target) => write!(f, "{}", target),
            Self::Absolute {
                scheme,
                host,
                port,
                target,
            } => write!(f, "{}://{}:{}{}", scheme, host, port.as_u16(), target),
        }
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
    pub name: PayloadSpan,
    pub value: PayloadSpan,
}

impl HttpHeaderView {
    pub fn name_eq(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }

    pub fn typed_name(&self) -> Option<HttpHeaderName> {
        HttpHeaderName::parse(&payload_span_to_string(&self.name)?)
    }

    pub fn typed_value(&self) -> Option<HttpHeaderValue> {
        HttpHeaderValue::parse(&payload_span_to_string(&self.value)?)
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: HttpRequestUri,
    pub version: HttpVersion,
    pub headers: Vec<HttpHeader>,
    pub body: Option<PacketPayload>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, uri: impl AsRef<str>) -> Option<Self> {
        Some(Self {
            method,
            uri: HttpRequestUri::parse(uri.as_ref())?,
            version: HttpVersion::Http1_1,
            headers: Vec::new(),
            body: None,
        })
    }

    pub fn get(uri: impl AsRef<str>) -> Option<Self> {
        Self::new(HttpMethod::Get, uri)
    }

    pub fn post(uri: impl AsRef<str>) -> Option<Self> {
        Self::new(HttpMethod::Post, uri)
    }

    pub fn header(mut self, name: &str, value: &str) -> Option<Self> {
        self.headers.push(HttpHeader::try_new(name, value)?);
        Some(self)
    }

    pub fn header_typed(mut self, name: HttpHeaderName, value: HttpHeaderValue) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    pub fn body_payload(mut self, payload: PacketPayload) -> Option<Self> {
        let value = HttpHeaderValue::from_string(payload.total_len().to_string())?;
        self.headers
            .push(HttpHeader::new(HttpHeaderName::ContentLength, value));
        self.body = Some(payload);
        Some(self)
    }

    pub fn body_bytes(self, data: &[u8]) -> Option<Self> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_bytes(data)?;
        self.body_payload(builder.build())
    }

    pub fn get_header(&self, name: HttpHeaderName) -> Option<&HttpHeaderValue> {
        self.headers.iter().find_map(|header| {
            if header.name.eq_ignore_ascii_case(name.as_str()) {
                Some(&header.value)
            } else {
                None
            }
        })
    }

    pub fn has_header_name(&self, name: HttpHeaderName) -> bool {
        self.headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(name.as_str()))
    }

    pub fn into_payload(self) -> Option<PacketPayload> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_str(&alloc::format!(
            "{} {} {}\r\n",
            self.method,
            self.uri.as_request_target(),
            self.version
        ))?;
        for header in &self.headers {
            builder.push_str(header.name.as_str())?;
            builder.push_str(": ")?;
            builder.push_str(header.value.as_str())?;
            builder.push_str("\r\n")?;
        }
        builder.push_str("\r\n")?;
        if let Some(body) = self.body {
            builder.push_payload(body);
        }
        Some(builder.build())
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequestView {
    pub method: HttpMethod,
    pub uri: PayloadSpan,
    pub version: HttpVersion,
    pub headers: Vec<HttpHeaderView>,
    pub body: Option<PayloadSpan>,
}

impl HttpRequestView {
    pub fn get_header(&self, name: &str) -> Option<&PayloadSpan> {
        self.headers.iter().find_map(|header| {
            if header.name_eq(name) {
                Some(&header.value)
            } else {
                None
            }
        })
    }

    pub fn uri_eq(&self, uri: &str) -> bool {
        self.uri.eq_bytes(uri.as_bytes())
    }

    pub fn connection_is(&self, value: &str) -> bool {
        if let Some(directive) = self.connection_directive() {
            return directive
                .as_header_value()
                .eq_ignore_ascii_case(value);
        }

        self.get_header("Connection").is_some_and(|span| {
            span.eq_ignore_ascii_case(value.as_bytes())
        })
    }

    pub fn connection_directive(&self) -> Option<ConnectionDirective> {
        self.get_header("Connection")
            .and_then(ConnectionDirective::parse_span)
    }

    pub fn content_type(&self) -> Option<PayloadSpan> {
        self.get_header("Content-Type").cloned()
    }

    pub fn body_payload(&self) -> Option<PacketPayload> {
        self.body.as_ref().and_then(PayloadSpan::to_payload)
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status_code: HttpStatusCode,
    pub reason_phrase: String,
    pub headers: Vec<HttpHeader>,
    pub body: PacketPayload,
}

impl HttpResponse {
    pub fn new(status_code: HttpStatusCode, reason_phrase: impl ToString) -> Self {
        Self {
            version: HttpVersion::Http1_1,
            status_code,
            reason_phrase: reason_phrase.to_string(),
            headers: Vec::new(),
            body: PacketPayload::default(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Option<Self> {
        self.headers.push(HttpHeader::try_new(name, value)?);
        Some(self)
    }

    pub fn header_typed(mut self, name: HttpHeaderName, value: HttpHeaderValue) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    pub fn body_payload(mut self, payload: PacketPayload) -> Option<Self> {
        let value = HttpHeaderValue::from_string(payload.total_len().to_string())?;
        self.headers
            .push(HttpHeader::new(HttpHeaderName::ContentLength, value));
        self.body = payload;
        Some(self)
    }

    pub fn body_bytes(self, data: &[u8]) -> Option<Self> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_bytes(data)?;
        self.body_payload(builder.build())
    }

    pub fn into_payload(self) -> Option<PacketPayload> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_str(&alloc::format!(
            "{} {} {}\r\n",
            self.version,
            self.status_code.as_u16(),
            self.reason_phrase
        ))?;
        for header in &self.headers {
            builder.push_str(header.name.as_str())?;
            builder.push_str(": ")?;
            builder.push_str(header.value.as_str())?;
            builder.push_str("\r\n")?;
        }
        builder.push_str("\r\n")?;
        builder.push_payload(self.body);
        Some(builder.build())
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponseView {
    pub version: HttpVersion,
    pub status_code: HttpStatusCode,
    pub reason_phrase: PayloadSpan,
    pub headers: Vec<HttpHeaderView>,
    pub body: PayloadSpan,
}

impl HttpResponseView {
    pub fn get_header(&self, name: &str) -> Option<&PayloadSpan> {
        self.headers.iter().find_map(|header| {
            if header.name_eq(name) {
                Some(&header.value)
            } else {
                None
            }
        })
    }

    pub fn body_payload(&self) -> Option<PacketPayload> {
        self.body.to_payload()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_uri_parses_and_preserves_target() {
        let uri = HttpRequestUri::parse("https://example.com:8443/path?q=1")
            .expect("absolute URI should parse");

        let (scheme, host, port, target) = uri.as_absolute().expect("absolute form expected");
        assert!(scheme.is_https());
        assert_eq!(host.as_str(), "example.com");
        assert_eq!(port.as_u16(), 8443);
        assert_eq!(target.as_str(), "/path?q=1");
        assert_eq!(uri.as_request_target().as_str(), "/path?q=1");
    }

    #[test]
    fn uri_rejects_invalid_host() {
        assert!(HttpRequestUri::parse("http://exa mple.com/").is_none());
        assert!(HttpRequestUri::parse("http:///path").is_none());
    }

    #[test]
    fn status_code_is_validated() {
        assert!(HttpStatusCode::new(99).is_none());
        assert!(HttpStatusCode::new(600).is_none());

        let ok = HttpStatusCode::new(200).expect("200 must be valid");
        assert_eq!(ok.as_u16(), 200);
        assert_eq!(ok.reason_phrase(), "OK");
    }

    #[test]
    fn header_name_and_value_are_validated() {
        assert!(HttpHeader::try_new("Content-Length", "10").is_some());
        assert!(HttpHeader::try_new("X-Custom", "abc").is_some());

        assert!(HttpHeader::try_new("Bad Header", "10").is_none());
        assert!(HttpHeader::try_new("X-Test", "bad\r\nvalue").is_none());
    }
}
