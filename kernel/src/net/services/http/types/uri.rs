// ============================================================================
// kernel/src/net/services/http/types/uri.rs - サービス / HTTP / 型定義 / uri
// ============================================================================

use super::{HttpPort, HttpScheme};
use alloc::string::{String, ToString};
use core::fmt;

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

fn contains_disallowed_host_chars(value: &str) -> bool {
    value.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || byte == b'/'
            || byte == b'?'
            || byte == b'#'
    })
}

fn parse_bracketed_host(value: &str) -> Option<HttpHost> {
    if !value.ends_with(']') || value.len() <= 2 {
        return None;
    }
    let inner = &value[1..value.len() - 1];
    if inner.is_empty() || contains_disallowed_host_chars(inner) {
        return None;
    }
    Some(HttpHost(value.to_string()))
}

fn parse_plain_host(value: &str) -> Option<HttpHost> {
    if value.is_empty() || value.contains(':') {
        return None;
    }
    if contains_disallowed_host_chars(value) {
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

/// HTTPホスト
#[derive(Debug, PartialEq, Eq, Hash)]
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
#[derive(Debug, PartialEq, Eq, Hash)]
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
#[derive(Debug, PartialEq, Eq)]
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
