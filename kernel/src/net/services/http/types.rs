// ============================================================================
// kernel/src/net/services/http/types.rs
// ============================================================================

use crate::net::payload::{PacketPayloadBuilder, PayloadSpan};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use kernel_api::resource::net::PacketPayload;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl HttpHeader {
    pub fn new(name: impl ToString, value: impl ToString) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
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
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
    pub headers: Vec<HttpHeader>,
    pub body: Option<PacketPayload>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, uri: impl ToString) -> Self {
        Self {
            method,
            uri: uri.to_string(),
            version: HttpVersion::Http1_1,
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn get(uri: impl ToString) -> Self {
        Self::new(HttpMethod::Get, uri)
    }

    pub fn post(uri: impl ToString) -> Self {
        Self::new(HttpMethod::Post, uri)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    pub fn body_payload(mut self, payload: PacketPayload) -> Self {
        self.headers
            .push(HttpHeader::new("Content-Length", payload.total_len().to_string()));
        self.body = Some(payload);
        self
    }

    pub fn body_bytes(self, data: &[u8]) -> Option<Self> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_bytes(data)?;
        Some(self.body_payload(builder.build()))
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|header| {
            if header.name.eq_ignore_ascii_case(name) {
                Some(header.value.as_str())
            } else {
                None
            }
        })
    }

    pub fn into_payload(self) -> Option<PacketPayload> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_str(&alloc::format!(
            "{} {} {}\r\n",
            self.method,
            self.uri,
            self.version
        ))?;
        for header in &self.headers {
            builder.push_str(&header.name)?;
            builder.push_str(": ")?;
            builder.push_str(&header.value)?;
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
        self.get_header("Connection")
            .is_some_and(|span| span.eq_ignore_ascii_case(value.as_bytes()))
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
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<HttpHeader>,
    pub body: PacketPayload,
}

impl HttpResponse {
    pub fn new(status_code: u16, reason_phrase: impl ToString) -> Self {
        Self {
            version: HttpVersion::Http1_1,
            status_code,
            reason_phrase: reason_phrase.to_string(),
            headers: Vec::new(),
            body: PacketPayload::default(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    pub fn body_payload(mut self, payload: PacketPayload) -> Self {
        self.headers
            .push(HttpHeader::new("Content-Length", payload.total_len().to_string()));
        self.body = payload;
        self
    }

    pub fn body_bytes(self, data: &[u8]) -> Option<Self> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_bytes(data)?;
        Some(self.body_payload(builder.build()))
    }

    pub fn into_payload(self) -> Option<PacketPayload> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_str(&alloc::format!(
            "{} {} {}\r\n",
            self.version,
            self.status_code,
            self.reason_phrase
        ))?;
        for header in &self.headers {
            builder.push_str(&header.name)?;
            builder.push_str(": ")?;
            builder.push_str(&header.value)?;
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
    pub status_code: u16,
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
