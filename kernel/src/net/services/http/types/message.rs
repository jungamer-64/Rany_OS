use super::{
    ConnectionDirective, HttpHeader, HttpHeaderName, HttpHeaderValue, HttpMethod, HttpRequestUri,
    HttpStatusCode, HttpVersion,
};
use crate::net::payload::{PacketPayloadBuilder, PayloadSpan};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kernel_api::resource::net::PacketPayload;

fn write_headers(builder: &mut PacketPayloadBuilder, headers: &[HttpHeader]) -> Option<()> {
    for header in headers {
        builder.push_str(header.name.as_str())?;
        builder.push_str(": ")?;
        builder.push_str(header.value.as_str())?;
        builder.push_str("\r\n")?;
    }

    Some(())
}

fn write_optional_body(builder: &mut PacketPayloadBuilder, body: Option<PacketPayload>) {
    if let Some(body) = body {
        builder.push_payload(body);
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
            if header.name.eq_name(&name) {
                Some(&header.value)
            } else {
                None
            }
        })
    }

    pub fn has_header_name(&self, name: HttpHeaderName) -> bool {
        self.headers.iter().any(|header| header.name.eq_name(&name))
    }

    pub fn into_payload(self) -> Option<PacketPayload> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_str(&alloc::format!(
            "{} {} {}\r\n",
            self.method,
            self.uri.as_request_target(),
            self.version
        ))?;
        write_headers(&mut builder, &self.headers)?;
        builder.push_str("\r\n")?;
        write_optional_body(&mut builder, self.body);
        Some(builder.build())
    }
}

#[derive(Debug, Clone)]
pub struct HttpInboundRequest {
    pub method: HttpMethod,
    pub uri: PayloadSpan,
    pub version: HttpVersion,
    pub headers: Vec<super::HttpHeaderView>,
    pub body: Option<PayloadSpan>,
}

impl HttpInboundRequest {
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
            return directive.as_header_value().eq_ignore_ascii_case(value);
        }

        self.get_header("Connection")
            .is_some_and(|span| span.eq_ignore_ascii_case(value.as_bytes()))
    }

    pub fn connection_directive(&self) -> Option<ConnectionDirective> {
        self.get_header("Connection")
            .and_then(ConnectionDirective::parse_span)
    }

    pub fn content_type(&self) -> Option<PayloadSpan> {
        self.get_header("Content-Type").cloned()
    }

    pub fn body_payload(&self) -> Option<PacketPayload> {
        self.body.clone().and_then(PayloadSpan::into_payload)
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
        write_headers(&mut builder, &self.headers)?;
        builder.push_str("\r\n")?;
        builder.push_payload(self.body);
        Some(builder.build())
    }
}

#[derive(Debug, Clone)]
pub struct HttpInboundResponse {
    pub version: HttpVersion,
    pub status_code: HttpStatusCode,
    pub reason_phrase: PayloadSpan,
    pub headers: Vec<super::HttpHeaderView>,
    pub body: Option<PayloadSpan>,
}

impl HttpInboundResponse {
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
        self.body.clone().and_then(PayloadSpan::into_payload)
    }
}
