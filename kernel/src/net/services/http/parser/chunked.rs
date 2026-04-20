// ============================================================================
// kernel/src/net/services/http/parser/chunked.rs - サービス / HTTP / パーサ / chunked
// ============================================================================

use super::{HttpBodyView, HttpParseError, HttpParser, MAX_CONTENT_LENGTH};
use crate::net::payload::{PayloadRange, PayloadSpanRef};

fn span_slice(
    span: PayloadSpanRef<'_>,
    offset: usize,
    len: usize,
) -> Option<PayloadSpanRef<'_>> {
    span.slice(offset, len)
}

impl HttpParser {
    fn parse_chunk_size(&self, line: &PayloadSpanRef<'_>) -> Option<usize> {
        let semicolon = line.find_bytes(b";").unwrap_or(line.total_len());
        let size_span = span_slice(*line, 0, semicolon)?;
        let size = size_span.trim_ascii_whitespace();
        size.parse_ascii_hex_usize()
    }

    pub(super) fn parse_chunked_body(
        &self,
        full: &PayloadSpanRef<'_>,
        mut cursor: usize,
    ) -> Result<Option<(HttpBodyView, usize)>, HttpParseError> {
        let mut body = alloc::vec::Vec::new();
        let mut total_len = 0usize;

        loop {
            let Some((chunk_size, next_cursor)) = self.read_chunk_header(full, cursor)? else {
                return Ok(None);
            };
            cursor = next_cursor;

            if chunk_size == 0 {
                return self.finish_chunked_body(full, cursor, body);
            }

            let Some(next_cursor) = self.append_chunk_data(
                full,
                &mut body,
                &mut total_len,
                cursor,
                chunk_size,
            )?
            else {
                return Ok(None);
            };
            cursor = next_cursor;
        }
    }

    fn read_chunk_header(
        &self,
        full: &PayloadSpanRef<'_>,
        cursor: usize,
    ) -> Result<Option<(usize, usize)>, HttpParseError> {
        let Some(chunk_len_end) = self.find_line_end(full, cursor) else {
            return Ok(None);
        };
        let chunk_len = span_slice(*full, cursor, chunk_len_end - cursor)
            .ok_or(HttpParseError::InvalidFormat)?;
        let chunk_size = self
            .parse_chunk_size(&chunk_len)
            .ok_or(HttpParseError::InvalidFormat)?;
        let next_cursor = chunk_len_end
            .checked_add(2)
            .ok_or(HttpParseError::InvalidFormat)?;
        Ok(Some((chunk_size, next_cursor)))
    }

    fn append_chunk_data(
        &self,
        full: &PayloadSpanRef<'_>,
        body: &mut alloc::vec::Vec<PayloadRange>,
        total_len: &mut usize,
        cursor: usize,
        chunk_size: usize,
    ) -> Result<Option<usize>, HttpParseError> {
        let next_body_len = total_len
            .checked_add(chunk_size)
            .ok_or(HttpParseError::InvalidFormat)?;
        if next_body_len > MAX_CONTENT_LENGTH {
            return Err(HttpParseError::InvalidFormat);
        }

        let data_end = cursor
            .checked_add(chunk_size)
            .and_then(|value| value.checked_add(2))
            .ok_or(HttpParseError::InvalidFormat)?;
        if full.total_len() < data_end {
            return Ok(None);
        }

        body.push(
            span_slice(*full, cursor, chunk_size)
                .ok_or(HttpParseError::InvalidFormat)?
                .range(),
        );
        *total_len = next_body_len;
        if !span_slice(*full, cursor + chunk_size, 2)
            .ok_or(HttpParseError::InvalidFormat)?
            .eq_bytes(b"\r\n")
        {
            return Err(HttpParseError::InvalidFormat);
        }

        Ok(Some(data_end))
    }

    fn finish_chunked_body(
        &self,
        full: &PayloadSpanRef<'_>,
        cursor: usize,
        body: alloc::vec::Vec<PayloadRange>,
    ) -> Result<Option<(HttpBodyView, usize)>, HttpParseError> {
        let Some(trailer_end) = self.parse_chunked_trailers(full, cursor)? else {
            return Ok(None);
        };
        Ok(Some((HttpBodyView::from_ranges(body), trailer_end)))
    }

    fn parse_chunked_trailers(
        &self,
        full: &PayloadSpanRef<'_>,
        mut cursor: usize,
    ) -> Result<Option<usize>, HttpParseError> {
        loop {
            let line_end = match self.find_line_end(full, cursor) {
                Some(index) => index,
                None => return Ok(None),
            };

            if line_end == cursor {
                let message_end = cursor.checked_add(2).ok_or(HttpParseError::InvalidFormat)?;
                return Ok(Some(message_end));
            }

            cursor = self.parse_non_empty_trailer_line(full, cursor, line_end)?;
        }
    }

    fn parse_non_empty_trailer_line(
        &self,
        full: &PayloadSpanRef<'_>,
        cursor: usize,
        line_end: usize,
    ) -> Result<usize, HttpParseError> {
        let line = span_slice(*full, cursor, line_end - cursor)
            .ok_or(HttpParseError::InvalidFormat)?;
        let (name, value) = self.parse_header_name_value(&line)?;
        self.validate_header_name_value(0, &name, &value)?;
        // Trailer ヘッダーは現時点では検証のみ行い、レスポンス構造体には保持しない。
        super::HttpHeaderView::try_new(name, value).ok_or(HttpParseError::InvalidFormat)?;

        line_end.checked_add(2).ok_or(HttpParseError::InvalidFormat)
    }
}
