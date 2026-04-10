// ============================================================================
// kernel/src/net/services/http/parser.rs
// ============================================================================

use super::types::{
    HttpHeaderView, HttpInboundRequest, HttpInboundResponse, HttpMethod, HttpStatusCode,
    HttpVersion,
};
use crate::net::payload::{PayloadSpan, append_payload, payload_range};
use alloc::vec::Vec;
use kernel_api::resource::net::PacketPayload;

mod chunked;

const MAX_TOTAL_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
const MAX_PARTIAL_HEADER_SIZE: usize = 8192;
const MAX_URI_SIZE: usize = 4096;
const MAX_REASON_PHRASE_SIZE: usize = 1024;
const MAX_HEADER_COUNT: usize = 100;
const MAX_HEADER_NAME_SIZE: usize = 256;
const MAX_HEADER_VALUE_SIZE: usize = 4096;
const MAX_CONTENT_LENGTH: usize = 10 * 1024 * 1024;

#[derive(Debug)]
pub enum HttpParseError {
    InvalidFormat,
    IncompleteMessage,
    UnsupportedVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    SearchingHeaders { search_from: usize },
    HeaderFound { header_end: usize },
}

pub struct HttpParser {
    buffer: PacketPayload,
    state: ParseState,
}

impl HttpParser {
    pub fn new() -> Self {
        Self {
            buffer: PacketPayload::default(),
            state: ParseState::SearchingHeaders { search_from: 0 },
        }
    }

    pub fn push_payload(&mut self, payload: PacketPayload) {
        append_payload(&mut self.buffer, payload);
    }

    pub fn try_parse_request(&mut self) -> Result<Option<HttpInboundRequest>, HttpParseError> {
        let Some((full, header_end)) = self.read_message_span()? else {
            return Ok(None);
        };

        let (method, uri, version, request_line_end) =
            self.parse_request_line(&full, header_end)?;

        let Some((headers, body, consumed_len)) =
            self.parse_message_payload(&full, request_line_end, header_end, false)?
        else {
            return Ok(None);
        };

        self.consume_prefix(consumed_len);

        Ok(Some(HttpInboundRequest {
            method,
            uri,
            version,
            headers,
            body,
        }))
    }

    pub fn try_parse(&mut self) -> Result<Option<HttpInboundResponse>, HttpParseError> {
        self.try_parse_response_with_mode(false)
    }

    /// EOFでメッセージ終端が確定したレスポンスをパースする。
    ///
    /// Content-Length/Transfer-Encoding がない場合、ヘッダー終端以降の残り全体を
    /// close-delimited body として扱う。
    pub fn try_parse_response_on_eof(
        &mut self,
    ) -> Result<Option<HttpInboundResponse>, HttpParseError> {
        self.try_parse_response_with_mode(true)
    }

    fn try_parse_response_with_mode(
        &mut self,
        eof_terminates_body: bool,
    ) -> Result<Option<HttpInboundResponse>, HttpParseError> {
        let Some((full, header_end)) = self.read_message_span()? else {
            return Ok(None);
        };

        let (version, status_code, reason_phrase, status_line_end) =
            self.parse_status_line(&full, header_end)?;

        let Some((headers, body, consumed_len)) =
            self.parse_message_payload(&full, status_line_end, header_end, eof_terminates_body)?
        else {
            return Ok(None);
        };

        self.consume_prefix(consumed_len);

        Ok(Some(HttpInboundResponse {
            version,
            status_code,
            reason_phrase,
            headers,
            body,
        }))
    }

    fn read_message_span(&mut self) -> Result<Option<(PayloadSpan, usize)>, HttpParseError> {
        if self.buffer.total_len() > MAX_TOTAL_MESSAGE_SIZE {
            return Err(HttpParseError::InvalidFormat);
        }

        let full = PayloadSpan::from_payload(self.buffer.clone());

        match self.state {
            ParseState::HeaderFound { header_end } => Ok(Some((full, header_end))),
            ParseState::SearchingHeaders { search_from } => {
                let start = core::cmp::min(search_from, full.total_len());
                let Some(header_end) = full.find_bytes_from(b"\r\n\r\n", start) else {
                    if full.total_len() > MAX_PARTIAL_HEADER_SIZE {
                        return Err(HttpParseError::InvalidFormat);
                    }

                    let next_search_from = full.total_len().saturating_sub(3);
                    self.state = ParseState::SearchingHeaders {
                        search_from: next_search_from,
                    };
                    return Ok(None);
                };

                self.state = ParseState::HeaderFound { header_end };
                Ok(Some((full, header_end)))
            }
        }
    }

    fn parse_request_line(
        &self,
        full: &PayloadSpan,
        header_end: usize,
    ) -> Result<(HttpMethod, PayloadSpan, HttpVersion, usize), HttpParseError> {
        let (request_line, request_line_end) = self.parse_start_line(full, header_end)?;
        let (first_space, second_space) = self.find_first_two_spaces(&request_line)?;
        let method = self.parse_method_from_line(&request_line, first_space)?;
        let uri = self.parse_request_uri_from_line(&request_line, first_space, second_space)?;
        let version = self.parse_http_version_from_line(&request_line, second_space)?;
        Ok((method, uri, version, request_line_end))
    }

    fn parse_status_line(
        &self,
        full: &PayloadSpan,
        header_end: usize,
    ) -> Result<(HttpVersion, HttpStatusCode, PayloadSpan, usize), HttpParseError> {
        let (status_line, status_line_end) = self.parse_start_line(full, header_end)?;
        let (first_space, second_space) = self.find_first_two_spaces(&status_line)?;

        let version = HttpVersion::parse_span(
            &status_line
                .slice(0, first_space)
                .ok_or(HttpParseError::InvalidFormat)?,
        )
        .ok_or(HttpParseError::UnsupportedVersion)?;

        let status_code =
            self.parse_status_code_from_line(&status_line, first_space, second_space)?;
        let reason_phrase = self.parse_reason_phrase_from_line(&status_line, second_space)?;

        Ok((version, status_code, reason_phrase, status_line_end))
    }

    fn parse_start_line(
        &self,
        full: &PayloadSpan,
        header_end: usize,
    ) -> Result<(PayloadSpan, usize), HttpParseError> {
        let line_end = self
            .find_line_end(full, 0)
            .ok_or(HttpParseError::IncompleteMessage)?;
        if line_end > header_end {
            return Err(HttpParseError::InvalidFormat);
        }

        let line = full
            .slice(0, line_end)
            .ok_or(HttpParseError::InvalidFormat)?;
        Ok((line, line_end))
    }

    fn parse_method_from_line(
        &self,
        line: &PayloadSpan,
        first_space: usize,
    ) -> Result<HttpMethod, HttpParseError> {
        HttpMethod::parse_span(
            &line
                .slice(0, first_space)
                .ok_or(HttpParseError::InvalidFormat)?,
        )
        .ok_or(HttpParseError::InvalidFormat)
    }

    fn parse_request_uri_from_line(
        &self,
        line: &PayloadSpan,
        first_space: usize,
        second_space: usize,
    ) -> Result<PayloadSpan, HttpParseError> {
        let uri_offset = first_space
            .checked_add(1)
            .ok_or(HttpParseError::InvalidFormat)?;
        let uri_len = second_space.saturating_sub(uri_offset);
        if uri_len == 0 {
            return Err(HttpParseError::InvalidFormat);
        }

        let uri = line
            .slice(uri_offset, uri_len)
            .ok_or(HttpParseError::InvalidFormat)?;
        if uri.total_len() > MAX_URI_SIZE {
            return Err(HttpParseError::InvalidFormat);
        }

        Ok(uri)
    }

    fn parse_status_code_from_line(
        &self,
        line: &PayloadSpan,
        first_space: usize,
        second_space: usize,
    ) -> Result<HttpStatusCode, HttpParseError> {
        let status_start = first_space
            .checked_add(1)
            .ok_or(HttpParseError::InvalidFormat)?;
        let status_len = second_space
            .checked_sub(status_start)
            .ok_or(HttpParseError::InvalidFormat)?;

        HttpStatusCode::parse_span(
            &line
                .slice(status_start, status_len)
                .ok_or(HttpParseError::InvalidFormat)?
                .trim_ascii_whitespace(),
        )
        .ok_or(HttpParseError::InvalidFormat)
    }

    fn parse_reason_phrase_from_line(
        &self,
        line: &PayloadSpan,
        second_space: usize,
    ) -> Result<PayloadSpan, HttpParseError> {
        let phrase = line
            .slice(
                second_space + 1,
                line.total_len().saturating_sub(second_space + 1),
            )
            .ok_or(HttpParseError::InvalidFormat)?
            .trim_ascii_whitespace();

        if phrase.total_len() > MAX_REASON_PHRASE_SIZE {
            return Err(HttpParseError::InvalidFormat);
        }

        Ok(phrase)
    }

    fn parse_http_version_from_line(
        &self,
        line: &PayloadSpan,
        second_space: usize,
    ) -> Result<HttpVersion, HttpParseError> {
        let version_offset = second_space
            .checked_add(1)
            .ok_or(HttpParseError::InvalidFormat)?;
        let version = HttpVersion::parse_span(
            &line
                .slice(
                    version_offset,
                    line.total_len().saturating_sub(version_offset),
                )
                .ok_or(HttpParseError::InvalidFormat)?
                .trim_ascii_whitespace(),
        )
        .ok_or(HttpParseError::UnsupportedVersion)?;
        Ok(version)
    }

    fn find_first_two_spaces(&self, line: &PayloadSpan) -> Result<(usize, usize), HttpParseError> {
        let first_space = line.find_bytes(b" ").ok_or(HttpParseError::InvalidFormat)?;
        let second_space = line
            .find_bytes_from(b" ", first_space + 1)
            .ok_or(HttpParseError::InvalidFormat)?;
        Ok((first_space, second_space))
    }

    fn parse_message_payload(
        &self,
        full: &PayloadSpan,
        first_line_end: usize,
        header_end: usize,
        eof_terminates_body: bool,
    ) -> Result<Option<(Vec<HttpHeaderView>, Option<PayloadSpan>, usize)>, HttpParseError> {
        let header_start = first_line_end
            .checked_add(2)
            .ok_or(HttpParseError::InvalidFormat)?;
        let (headers, content_length, chunked) =
            self.parse_headers(full, header_start, header_end)?;
        if chunked && content_length.is_some() {
            return Err(HttpParseError::InvalidFormat);
        }

        let body_start = header_end
            .checked_add(4)
            .ok_or(HttpParseError::InvalidFormat)?;
        let Some((body, consumed_len)) = self.parse_optional_body(
            full,
            body_start,
            content_length,
            chunked,
            eof_terminates_body,
        )?
        else {
            return Ok(None);
        };

        Ok(Some((headers, body, consumed_len)))
    }

    fn parse_optional_body(
        &self,
        full: &PayloadSpan,
        body_start: usize,
        content_length: Option<usize>,
        chunked: bool,
        eof_terminates_body: bool,
    ) -> Result<Option<(Option<PayloadSpan>, usize)>, HttpParseError> {
        if chunked {
            return self.parse_chunked_optional_body(full, body_start);
        }

        if let Some(len) = content_length {
            return self.parse_fixed_length_body(full, body_start, len);
        }

        if eof_terminates_body {
            return self.parse_close_delimited_body(full, body_start);
        }

        Ok(Some((None, body_start)))
    }

    fn parse_chunked_optional_body(
        &self,
        full: &PayloadSpan,
        body_start: usize,
    ) -> Result<Option<(Option<PayloadSpan>, usize)>, HttpParseError> {
        let Some((payload, consumed_len)) = self.parse_chunked_body(full, body_start)? else {
            return Ok(None);
        };
        Ok(Some((
            Some(PayloadSpan::from_payload(payload)),
            consumed_len,
        )))
    }

    fn parse_fixed_length_body(
        &self,
        full: &PayloadSpan,
        body_start: usize,
        len: usize,
    ) -> Result<Option<(Option<PayloadSpan>, usize)>, HttpParseError> {
        let body_end = body_start
            .checked_add(len)
            .ok_or(HttpParseError::InvalidFormat)?;
        if full.total_len() < body_end {
            return Ok(None);
        }

        let body = full
            .slice(body_start, len)
            .ok_or(HttpParseError::InvalidFormat)?;
        Ok(Some((Some(body), body_end)))
    }

    fn parse_close_delimited_body(
        &self,
        full: &PayloadSpan,
        body_start: usize,
    ) -> Result<Option<(Option<PayloadSpan>, usize)>, HttpParseError> {
        if body_start > full.total_len() {
            return Err(HttpParseError::InvalidFormat);
        }

        let remaining_len = full.total_len().saturating_sub(body_start);
        if remaining_len == 0 {
            return Ok(Some((None, full.total_len())));
        }

        let body = full
            .slice(body_start, remaining_len)
            .ok_or(HttpParseError::InvalidFormat)?;
        Ok(Some((Some(body), full.total_len())))
    }

    fn consume_prefix(&mut self, consumed_len: usize) {
        let remaining = self.buffer.total_len().saturating_sub(consumed_len);
        self.buffer = if remaining == 0 {
            PacketPayload::default()
        } else {
            payload_range(&self.buffer, consumed_len, remaining).unwrap_or_default()
        };
        self.state = ParseState::SearchingHeaders { search_from: 0 };
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
            let Some(next_cursor) = self.parse_header_line(
                full,
                cursor,
                header_end,
                &mut headers,
                &mut content_length,
                &mut chunked,
            )?
            else {
                break;
            };
            cursor = next_cursor;
        }

        Ok((headers, content_length, chunked))
    }

    fn parse_header_line(
        &self,
        full: &PayloadSpan,
        cursor: usize,
        header_end: usize,
        headers: &mut Vec<HttpHeaderView>,
        content_length: &mut Option<usize>,
        chunked: &mut bool,
    ) -> Result<Option<usize>, HttpParseError> {
        let Some(line_end) = self.resolve_header_line_end(full, cursor, header_end)? else {
            return Ok(None);
        };

        let line = full
            .slice(cursor, line_end - cursor)
            .ok_or(HttpParseError::InvalidFormat)?;
        let (name, value) = self.parse_header_name_value(&line)?;
        self.validate_header_name_value(headers.len(), &name, &value)?;
        self.apply_content_headers(&name, &value, content_length, chunked)?;

        let header = HttpHeaderView::try_new(name, value).ok_or(HttpParseError::InvalidFormat)?;
        headers.push(header);

        line_end
            .checked_add(2)
            .ok_or(HttpParseError::InvalidFormat)
            .map(Some)
    }

    fn resolve_header_line_end(
        &self,
        full: &PayloadSpan,
        cursor: usize,
        header_end: usize,
    ) -> Result<Option<usize>, HttpParseError> {
        let line_end = self
            .find_line_end(full, cursor)
            .ok_or(HttpParseError::IncompleteMessage)?;
        if line_end > header_end {
            return Err(HttpParseError::InvalidFormat);
        }
        if line_end == cursor {
            return Ok(None);
        }
        Ok(Some(line_end))
    }

    fn parse_header_name_value(
        &self,
        line: &PayloadSpan,
    ) -> Result<(PayloadSpan, PayloadSpan), HttpParseError> {
        let colon = line.find_bytes(b":").ok_or(HttpParseError::InvalidFormat)?;
        let name = line
            .slice(0, colon)
            .ok_or(HttpParseError::InvalidFormat)?
            .trim_ascii_whitespace();
        let value = line
            .slice(colon + 1, line.total_len().saturating_sub(colon + 1))
            .ok_or(HttpParseError::InvalidFormat)?
            .trim_ascii_whitespace();
        Ok((name, value))
    }

    fn validate_header_name_value(
        &self,
        header_count: usize,
        name: &PayloadSpan,
        value: &PayloadSpan,
    ) -> Result<(), HttpParseError> {
        if header_count >= MAX_HEADER_COUNT
            || name.total_len() > MAX_HEADER_NAME_SIZE
            || value.total_len() > MAX_HEADER_VALUE_SIZE
        {
            return Err(HttpParseError::InvalidFormat);
        }
        Ok(())
    }

    fn apply_content_headers(
        &self,
        name: &PayloadSpan,
        value: &PayloadSpan,
        content_length: &mut Option<usize>,
        chunked: &mut bool,
    ) -> Result<(), HttpParseError> {
        if name.eq_ignore_ascii_case(b"Content-Length") {
            let len = value
                .parse_ascii_usize()
                .ok_or(HttpParseError::InvalidFormat)?;
            if len > MAX_CONTENT_LENGTH {
                return Err(HttpParseError::InvalidFormat);
            }
            *content_length = Some(len);
            return Ok(());
        }

        if name.eq_ignore_ascii_case(b"Transfer-Encoding") && value.contains_ascii_case(b"chunked")
        {
            *chunked = true;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
