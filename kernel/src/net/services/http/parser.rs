// ============================================================================
// kernel/src/net/services/http/parser.rs
// ============================================================================

use super::types::{
    HttpHeaderView, HttpMethod, HttpRequestView, HttpResponseView, HttpStatusCode, HttpVersion,
};
use crate::net::payload::{append_payload, payload_range, PayloadSequence, PayloadSpan};
use alloc::vec::Vec;
use kernel_api::resource::net::PacketPayload;

#[derive(Debug)]
pub enum HttpParseError {
    InvalidFormat,
    IncompleteMessage,
    InvalidEncoding,
    UnsupportedVersion,
}

pub struct HttpParser {
    buffer: PacketPayload,
}

impl HttpParser {
    pub fn new() -> Self {
        Self {
            buffer: PacketPayload::default(),
        }
    }

    pub fn push_payload(&mut self, payload: PacketPayload) {
        append_payload(&mut self.buffer, payload);
    }

    pub fn try_parse_request(&mut self) -> Result<Option<HttpRequestView>, HttpParseError> {
        const MAX_TOTAL_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
        if self.buffer.total_len() > MAX_TOTAL_MESSAGE_SIZE {
            return Err(HttpParseError::InvalidFormat);
        }

        let full = PayloadSpan::from_payload(self.buffer.clone());
        let header_end = match full.find_bytes(b"\r\n\r\n") {
            Some(index) => index,
            None => {
                if full.total_len() > 8192 {
                    return Err(HttpParseError::InvalidFormat);
                }
                return Ok(None);
            }
        };

        let request_line_end = self
            .find_line_end(&full, 0)
            .ok_or(HttpParseError::IncompleteMessage)?;
        if request_line_end > header_end {
            return Err(HttpParseError::InvalidFormat);
        }

        let request_line = full
            .slice(0, request_line_end)
            .ok_or(HttpParseError::InvalidFormat)?;
        let first_space = request_line
            .find_bytes(b" ")
            .ok_or(HttpParseError::InvalidFormat)?;
        let second_space = request_line
            .find_bytes_from(b" ", first_space + 1)
            .ok_or(HttpParseError::InvalidFormat)?;

        let method = HttpMethod::parse_span(
            &request_line
                .slice(0, first_space)
                .ok_or(HttpParseError::InvalidFormat)?,
        )
        .ok_or(HttpParseError::InvalidFormat)?;
        let uri = request_line
            .slice(first_space + 1, second_space.saturating_sub(first_space + 1))
            .ok_or(HttpParseError::InvalidFormat)?;
        if uri.total_len() > 4096 {
            return Err(HttpParseError::InvalidFormat);
        }
        let version = HttpVersion::parse_span(
            &request_line
                .slice(
                    second_space + 1,
                    request_line.total_len().saturating_sub(second_space + 1),
                )
                .ok_or(HttpParseError::InvalidFormat)?
                .trim_ascii_whitespace(),
        )
        .ok_or(HttpParseError::UnsupportedVersion)?;

        let (headers, content_length, chunked) =
            self.parse_headers(&full, request_line_end + 2, header_end)?;
        if chunked && content_length.is_some() {
            return Err(HttpParseError::InvalidFormat);
        }

        let body_start = header_end + 4;
        let (body, consumed_len) = if chunked {
            let Some((payload, consumed_len)) = self.parse_chunked_body(&full, body_start)? else {
                return Ok(None);
            };
            (
                Some(PayloadSpan::from_payload(payload)),
                consumed_len,
            )
        } else if let Some(len) = content_length {
            if full.total_len() < body_start + len {
                return Ok(None);
            }
            (
                Some(
                    full.slice(body_start, len)
                        .ok_or(HttpParseError::InvalidFormat)?,
                ),
                body_start + len,
            )
        } else {
            (None, body_start)
        };

        self.consume_prefix(consumed_len);

        Ok(Some(HttpRequestView {
            method,
            uri,
            version,
            headers,
            body,
        }))
    }

    pub fn try_parse(&mut self) -> Result<Option<HttpResponseView>, HttpParseError> {
        const MAX_TOTAL_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
        if self.buffer.total_len() > MAX_TOTAL_MESSAGE_SIZE {
            return Err(HttpParseError::InvalidFormat);
        }

        let full = PayloadSpan::from_payload(self.buffer.clone());
        let header_end = match full.find_bytes(b"\r\n\r\n") {
            Some(index) => index,
            None => {
                if full.total_len() > 8192 {
                    return Err(HttpParseError::InvalidFormat);
                }
                return Ok(None);
            }
        };

        let status_line_end = self
            .find_line_end(&full, 0)
            .ok_or(HttpParseError::IncompleteMessage)?;
        if status_line_end > header_end {
            return Err(HttpParseError::InvalidFormat);
        }

        let status_line = full
            .slice(0, status_line_end)
            .ok_or(HttpParseError::InvalidFormat)?;
        let first_space = status_line
            .find_bytes(b" ")
            .ok_or(HttpParseError::InvalidFormat)?;
        let second_space = status_line
            .find_bytes_from(b" ", first_space + 1)
            .ok_or(HttpParseError::InvalidFormat)?;

        let version = HttpVersion::parse_span(
            &status_line
                .slice(0, first_space)
                .ok_or(HttpParseError::InvalidFormat)?,
        )
        .ok_or(HttpParseError::UnsupportedVersion)?;
        let status_code = HttpStatusCode::parse_span(
            &status_line
                .slice(first_space + 1, second_space.saturating_sub(first_space + 1))
                .ok_or(HttpParseError::InvalidFormat)?
                .trim_ascii_whitespace(),
        )
        .ok_or(HttpParseError::InvalidFormat)?;
        let reason_phrase = status_line
            .slice(
                second_space + 1,
                status_line.total_len().saturating_sub(second_space + 1),
            )
            .ok_or(HttpParseError::InvalidFormat)?
            .trim_ascii_whitespace();
        if reason_phrase.total_len() > 1024 {
            return Err(HttpParseError::InvalidFormat);
        }

        let (headers, content_length, chunked) =
            self.parse_headers(&full, status_line_end + 2, header_end)?;
        if chunked && content_length.is_some() {
            return Err(HttpParseError::InvalidFormat);
        }

        let body_start = header_end + 4;
        let (body, consumed_len) = if chunked {
            let Some((payload, consumed_len)) = self.parse_chunked_body(&full, body_start)? else {
                return Ok(None);
            };
            (PayloadSpan::from_payload(payload), consumed_len)
        } else if let Some(len) = content_length {
            if full.total_len() < body_start + len {
                return Ok(None);
            }
            (
                full.slice(body_start, len)
                    .ok_or(HttpParseError::InvalidFormat)?,
                body_start + len,
            )
        } else {
            (
                full.slice(body_start, 0)
                    .ok_or(HttpParseError::InvalidFormat)?,
                body_start,
            )
        };

        self.consume_prefix(consumed_len);

        Ok(Some(HttpResponseView {
            version,
            status_code,
            reason_phrase,
            headers,
            body,
        }))
    }

    pub fn try_parse_wrapped(&mut self) -> Result<Option<HttpResponseView>, HttpParseError> {
        self.try_parse()
    }

    fn consume_prefix(&mut self, consumed_len: usize) {
        let remaining = self.buffer.total_len().saturating_sub(consumed_len);
        self.buffer = if remaining == 0 {
            PacketPayload::default()
        } else {
            payload_range(&self.buffer, consumed_len, remaining).unwrap_or_default()
        };
    }

    fn find_line_end(&self, span: &PayloadSpan, start: usize) -> Option<usize> {
        span.find_bytes_from(b"\r\n", start)
    }

    fn parse_headers(
        &self,
        full: &PayloadSpan,
        mut cursor: usize,
        header_end: usize,
    ) -> Result<(Vec<HttpHeaderView>, Option<usize>, bool), HttpParseError> {
        let mut headers = Vec::new();
        let mut content_length = None;
        let mut chunked = false;

        while cursor < header_end {
            let line_end = self
                .find_line_end(full, cursor)
                .ok_or(HttpParseError::IncompleteMessage)?;
            if line_end > header_end {
                return Err(HttpParseError::InvalidFormat);
            }
            if line_end == cursor {
                break;
            }

            let line = full
                .slice(cursor, line_end - cursor)
                .ok_or(HttpParseError::InvalidFormat)?;
            let colon = line.find_bytes(b":").ok_or(HttpParseError::InvalidFormat)?;
            let name = line
                .slice(0, colon)
                .ok_or(HttpParseError::InvalidFormat)?
                .trim_ascii_whitespace();
            let value = line
                .slice(colon + 1, line.total_len().saturating_sub(colon + 1))
                .ok_or(HttpParseError::InvalidFormat)?
                .trim_ascii_whitespace();

            if headers.len() >= 100 || name.total_len() > 256 || value.total_len() > 4096 {
                return Err(HttpParseError::InvalidFormat);
            }

            if name.eq_ignore_ascii_case(b"Content-Length") {
                let len = value
                    .parse_ascii_usize()
                    .ok_or(HttpParseError::InvalidFormat)?;
                if len > 10 * 1024 * 1024 {
                    return Err(HttpParseError::InvalidFormat);
                }
                content_length = Some(len);
            } else if name.eq_ignore_ascii_case(b"Transfer-Encoding")
                && value.contains_ascii_case(b"chunked")
            {
                chunked = true;
            }

            let header = HttpHeaderView { name, value };
            if header.typed_name().is_none() || header.typed_value().is_none() {
                return Err(HttpParseError::InvalidFormat);
            }

            headers.push(header);
            cursor = line_end + 2;
        }

        Ok((headers, content_length, chunked))
    }

    fn parse_chunked_body(
        &self,
        full: &PayloadSpan,
        mut cursor: usize,
    ) -> Result<Option<(PacketPayload, usize)>, HttpParseError> {
        let mut body = PayloadSequence::new();

        loop {
            let chunk_len_end = match self.find_line_end(full, cursor) {
                Some(index) => index,
                None => return Ok(None),
            };
            let chunk_len = full
                .slice(cursor, chunk_len_end - cursor)
                .ok_or(HttpParseError::InvalidFormat)?
                .trim_ascii_whitespace();
            let chunk_size = chunk_len
                .parse_ascii_hex_usize()
                .ok_or(HttpParseError::InvalidFormat)?;
            cursor = chunk_len_end + 2;

            if chunk_size == 0 {
                let trailer_end = cursor.checked_add(2).ok_or(HttpParseError::InvalidFormat)?;
                if full.total_len() < trailer_end {
                    return Ok(None);
                }
                if !full
                    .slice(cursor, 2)
                    .ok_or(HttpParseError::InvalidFormat)?
                    .eq_bytes(b"\r\n")
                {
                    return Err(HttpParseError::InvalidFormat);
                }
                return Ok(Some((
                    body.into_payload().unwrap_or_default(),
                    trailer_end,
                )));
            }

            let data_end = cursor
                .checked_add(chunk_size)
                .and_then(|value| value.checked_add(2))
                .ok_or(HttpParseError::InvalidFormat)?;
            if full.total_len() < data_end {
                return Ok(None);
            }

            body.push(
                full.slice(cursor, chunk_size)
                    .ok_or(HttpParseError::InvalidFormat)?,
            );
            if !full
                .slice(cursor + chunk_size, 2)
                .ok_or(HttpParseError::InvalidFormat)?
                .eq_bytes(b"\r\n")
            {
                return Err(HttpParseError::InvalidFormat);
            }
            cursor = data_end;
        }
    }
}
