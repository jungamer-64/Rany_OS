use super::{HttpParseError, HttpParser, MAX_CONTENT_LENGTH};
use crate::net::payload::{PayloadSequence, PayloadSpan};
use kernel_api::resource::net::PacketPayload;

impl HttpParser {
    fn parse_chunk_size(&self, line: &PayloadSpan) -> Option<usize> {
        let semicolon = line.find_bytes(b";").unwrap_or(line.total_len());
        let size = line.slice(0, semicolon)?.trim_ascii_whitespace();
        size.parse_ascii_hex_usize()
    }

    pub(super) fn parse_chunked_body(
        &self,
        full: &PayloadSpan,
        mut cursor: usize,
    ) -> Result<Option<(PacketPayload, usize)>, HttpParseError> {
        let mut body = PayloadSequence::new();

        loop {
            let Some((chunk_size, next_cursor)) = self.read_chunk_header(full, cursor)? else {
                return Ok(None);
            };
            cursor = next_cursor;

            if chunk_size == 0 {
                return self.finish_chunked_body(full, cursor, body);
            }

            let Some(next_cursor) = self.append_chunk_data(full, &mut body, cursor, chunk_size)?
            else {
                return Ok(None);
            };
            cursor = next_cursor;
        }
    }

    fn read_chunk_header(
        &self,
        full: &PayloadSpan,
        cursor: usize,
    ) -> Result<Option<(usize, usize)>, HttpParseError> {
        let Some(chunk_len_end) = self.find_line_end(full, cursor) else {
            return Ok(None);
        };
        let chunk_len = full
            .slice(cursor, chunk_len_end - cursor)
            .ok_or(HttpParseError::InvalidFormat)?
            .trim_ascii_whitespace();
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
        full: &PayloadSpan,
        body: &mut PayloadSequence,
        cursor: usize,
        chunk_size: usize,
    ) -> Result<Option<usize>, HttpParseError> {
        let next_body_len = body
            .total_len()
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

        Ok(Some(data_end))
    }

    fn finish_chunked_body(
        &self,
        full: &PayloadSpan,
        cursor: usize,
        body: PayloadSequence,
    ) -> Result<Option<(PacketPayload, usize)>, HttpParseError> {
        let Some(trailer_end) = self.parse_chunked_trailers(full, cursor)? else {
            return Ok(None);
        };
        Ok(Some((body.into_payload().unwrap_or_default(), trailer_end)))
    }

    fn parse_chunked_trailers(
        &self,
        full: &PayloadSpan,
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
        full: &PayloadSpan,
        cursor: usize,
        line_end: usize,
    ) -> Result<usize, HttpParseError> {
        let line = full
            .slice(cursor, line_end - cursor)
            .ok_or(HttpParseError::InvalidFormat)?;
        let (name, value) = self.parse_header_name_value(&line)?;
        self.validate_header_name_value(0, &name, &value)?;
        // Trailer ヘッダーは現時点では検証のみ行い、レスポンス構造体には保持しない。
        super::HttpHeaderView::try_new(name, value).ok_or(HttpParseError::InvalidFormat)?;

        line_end.checked_add(2).ok_or(HttpParseError::InvalidFormat)
    }
}
