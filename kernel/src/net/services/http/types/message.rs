// ============================================================================
// kernel/src/net/services/http/types/message.rs - サービス / HTTP / 型定義 / message
// ============================================================================

use super::{
    ConnectionDirective, HttpHeader, HttpHeaderName, HttpHeaderValue, HttpMethod, HttpRequestUri,
    HttpStatusCode, HttpVersion,
};
use crate::net::payload::{GeneratedPacketWriter, PayloadRange, PayloadSpanRef, append_payload};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

fn checked_add_len(total: usize, len: usize) -> Option<usize> {
    total.checked_add(len)
}

fn headers_wire_len(headers: &[HttpHeader]) -> Option<usize> {
    headers.iter().try_fold(0usize, |total, header| {
        checked_add_len(total, header.name.as_str().len())?
            .checked_add(2)?
            .checked_add(header.value.as_str().len())?
            .checked_add(2)
    })
}

fn write_headers(writer: &mut GeneratedPacketWriter, headers: &[HttpHeader]) -> Option<()> {
    for header in headers {
        writer.write_bytes(header.name.as_str().as_bytes())?;
        writer.write_bytes(b": ")?;
        writer.write_bytes(header.value.as_str().as_bytes())?;
        writer.write_bytes(b"\r\n")?;
    }
    Some(())
}

fn append_optional_body(target: &mut PacketPayload, body: Option<PacketPayload>) {
    if let Some(body) = body {
        append_payload(target, body);
    }
}

fn request_head_payload(request: &HttpRequest) -> Option<PacketPayload> {
    let method = request.method.as_str();
    let target = request.uri.as_request_target().as_str();
    let version = request.version.as_str();
    let head_len = checked_add_len(method.len(), 1)?
        .checked_add(target.len())?
        .checked_add(1)?
        .checked_add(version.len())?
        .checked_add(2)?
        .checked_add(headers_wire_len(&request.headers)?)?
        .checked_add(2)?;
    let mut writer = GeneratedPacketWriter::new(head_len, DEFAULT_PACKET_HEADROOM)?;
    writer.write_bytes(method.as_bytes())?;
    writer.write_bytes(b" ")?;
    writer.write_bytes(target.as_bytes())?;
    writer.write_bytes(b" ")?;
    writer.write_bytes(version.as_bytes())?;
    writer.write_bytes(b"\r\n")?;
    write_headers(&mut writer, &request.headers)?;
    writer.write_bytes(b"\r\n")?;
    writer.finish()
}

fn status_code_bytes(status_code: HttpStatusCode) -> [u8; 3] {
    let code = status_code.as_u16();
    [
        b'0' + (code / 100) as u8,
        b'0' + ((code / 10) % 10) as u8,
        b'0' + (code % 10) as u8,
    ]
}

fn response_head_payload(response: &HttpResponse) -> Option<PacketPayload> {
    let version = response.version.as_str();
    let status = status_code_bytes(response.status_code);
    let reason = response.reason_phrase.as_str();
    let head_len = checked_add_len(version.len(), 1)?
        .checked_add(status.len())?
        .checked_add(1)?
        .checked_add(reason.len())?
        .checked_add(2)?
        .checked_add(headers_wire_len(&response.headers)?)?
        .checked_add(2)?;
    let mut writer = GeneratedPacketWriter::new(head_len, DEFAULT_PACKET_HEADROOM)?;
    writer.write_bytes(version.as_bytes())?;
    writer.write_bytes(b" ")?;
    writer.write_bytes(&status)?;
    writer.write_bytes(b" ")?;
    writer.write_bytes(reason.as_bytes())?;
    writer.write_bytes(b"\r\n")?;
    write_headers(&mut writer, &response.headers)?;
    writer.write_bytes(b"\r\n")?;
    writer.finish()
}

#[derive(Debug)]
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
        let mut payload = request_head_payload(&self)?;
        append_optional_body(&mut payload, self.body);
        Some(payload)
    }
}

#[derive(Debug)]
pub struct HttpBodyView {
    pub ranges: Vec<PayloadRange>,
    total_len: usize,
}

impl HttpBodyView {
    pub fn from_range(range: PayloadRange) -> Self {
        Self {
            total_len: range.total_len(),
            ranges: alloc::vec![range],
        }
    }

    pub fn from_ranges(ranges: Vec<PayloadRange>) -> Self {
        let total_len = ranges.iter().map(PayloadRange::total_len).sum();
        Self { ranges, total_len }
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn spans<'a>(
        &'a self,
        payload: &'a PacketPayload,
    ) -> impl Iterator<Item = PayloadSpanRef<'a>> + 'a {
        self.ranges.iter().filter_map(|range| range.span(payload))
    }

    pub fn into_payload(self, payload: PacketPayload) -> Option<PacketPayload> {
        if self.ranges.len() != 1 {
            return None;
        }
        let range = self.ranges.into_iter().next()?;
        crate::net::payload::OwnedPayloadWindow::from_range(payload, range)
            .and_then(|window| window.into_payload().ok())
    }
}

#[derive(Debug)]
pub struct HttpInboundRequest {
    pub payload: PacketPayload,
    pub method: HttpMethod,
    pub uri: PayloadRange,
    pub version: HttpVersion,
    pub headers: Vec<super::HttpHeaderView>,
    pub body: Option<HttpBodyView>,
}

impl HttpInboundRequest {
    pub fn uri(&self) -> Option<PayloadSpanRef<'_>> {
        self.uri.span(&self.payload)
    }

    pub fn get_header(&self, name: &str) -> Option<PayloadSpanRef<'_>> {
        self.headers.iter().find_map(|header| {
            if header.name_eq(&self.payload, name) {
                header.value_span(&self.payload)
            } else {
                None
            }
        })
    }

    pub fn uri_eq(&self, uri: &str) -> bool {
        self.uri()
            .is_some_and(|request_uri| request_uri.eq_bytes(uri.as_bytes()))
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
            .and_then(ConnectionDirective::parse_span_ref)
    }

    pub fn content_type(&self) -> Option<PayloadSpanRef<'_>> {
        self.get_header("Content-Type")
    }

    pub fn into_body_payload(self) -> Option<PacketPayload> {
        self.body.and_then(|body| body.into_payload(self.payload))
    }
}

#[derive(Debug)]
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

    pub fn into_payload(self) -> Option<PacketPayload> {
        let mut payload = response_head_payload(&self)?;
        append_payload(&mut payload, self.body);
        Some(payload)
    }
}

#[derive(Debug)]
pub struct HttpInboundResponse {
    pub payload: PacketPayload,
    pub version: HttpVersion,
    pub status_code: HttpStatusCode,
    pub reason_phrase: PayloadRange,
    pub headers: Vec<super::HttpHeaderView>,
    pub body: Option<HttpBodyView>,
}

impl HttpInboundResponse {
    pub fn reason_phrase(&self) -> Option<PayloadSpanRef<'_>> {
        self.reason_phrase.span(&self.payload)
    }

    pub fn get_header(&self, name: &str) -> Option<PayloadSpanRef<'_>> {
        self.headers.iter().find_map(|header| {
            if header.name_eq(&self.payload, name) {
                header.value_span(&self.payload)
            } else {
                None
            }
        })
    }

    pub fn into_body_payload(self) -> Option<PacketPayload> {
        self.body.and_then(|body| body.into_payload(self.payload))
    }
}
