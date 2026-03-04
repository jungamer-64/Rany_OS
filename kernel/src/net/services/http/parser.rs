// ============================================================================
// kernel/src/net/services/http/parser.rs
// ============================================================================

use alloc::vec::Vec;
use super::types::{HttpRequest, HttpResponse, HttpVersion, HttpMethod, HttpHeader};
use core::str;
use core::str::FromStr;

#[derive(Debug)]
pub enum HttpParseError {
    InvalidFormat,
    IncompleteMessage,
    InvalidEncoding,
    UnsupportedVersion,
}

pub struct HttpParser {
    buffer: Vec<u8>,
}

impl HttpParser {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    /// データをバッファに追加
    pub fn push_data(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// 完全なリクエストが受信されたか確認してパースする
    pub fn try_parse_request(&mut self) -> Result<Option<HttpRequest>, HttpParseError> {
        const MAX_TOTAL_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
        if self.buffer.len() > MAX_TOTAL_MESSAGE_SIZE {
            return Err(HttpParseError::InvalidFormat);
        }

        let header_end_idx = match self.find_header_end() {
            Some(idx) => idx,
            None => {
                if self.buffer.len() > 8192 {
                    return Err(HttpParseError::InvalidFormat);
                }
                return Ok(None);
            }
        };

        let header_bytes = &self.buffer[..header_end_idx];
        let header_str = str::from_utf8(header_bytes).map_err(|_| HttpParseError::InvalidEncoding)?;
        
        let mut lines = header_str.split("\r\n");
        
        // Request-Line
        let request_line = lines.next().ok_or(HttpParseError::InvalidFormat)?;
        let mut request_parts = request_line.splitn(3, ' ');
        
        let method_str = request_parts.next().ok_or(HttpParseError::InvalidFormat)?;
        let method = HttpMethod::from_str(method_str).map_err(|_| HttpParseError::InvalidFormat)?;
        
        let uri = request_parts.next().ok_or(HttpParseError::InvalidFormat)?.trim();
        if uri.len() > 4096 {
            return Err(HttpParseError::InvalidFormat);
        }
        let uri_string = alloc::string::String::from(uri);
        
        let version_str = request_parts.next().ok_or(HttpParseError::InvalidFormat)?;
        let version = HttpVersion::from_str(version_str).map_err(|_| HttpParseError::UnsupportedVersion)?;
        
        let mut headers = Vec::new();
        let mut content_length = None;
        let mut chunked = false;
        
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if headers.len() >= 100 {
                return Err(HttpParseError::InvalidFormat);
            }
            let mut parts = line.splitn(2, ':');
            let name = parts.next().ok_or(HttpParseError::InvalidFormat)?.trim();
            let value = parts.next().ok_or(HttpParseError::InvalidFormat)?.trim();
            if name.len() > 256 || value.len() > 4096 {
                return Err(HttpParseError::InvalidFormat);
            }
            headers.push(HttpHeader::new(name, value));
            
            if name.eq_ignore_ascii_case("Content-Length") {
                let len = value.parse::<usize>().map_err(|_| HttpParseError::InvalidFormat)?;
                if len > 10 * 1024 * 1024 {
                    return Err(HttpParseError::InvalidFormat);
                }
                content_length = Some(len);
            } else if name.eq_ignore_ascii_case("Transfer-Encoding") && value.to_lowercase().contains("chunked") {
                chunked = true;
            }
        }
        
        if chunked && content_length.is_some() {
            return Err(HttpParseError::InvalidFormat);
        }
        
        let body_start_idx = header_end_idx + 4;
        
        let (body, total_len) = if chunked {
            let res = self.parse_chunked(body_start_idx)?;
            if res.1 == 0 {
                return Ok(None);
            }
            (Some(res.0), res.1)
        } else if let Some(len) = content_length {
            if self.buffer.len() < body_start_idx + len {
                return Ok(None);
            }
            let body = self.buffer[body_start_idx..body_start_idx + len].to_vec();
            (Some(body), body_start_idx + len)
        } else {
            (None, body_start_idx)
        };
        
        self.buffer.drain(..total_len);

        Ok(Some(HttpRequest {
            method,
            uri: uri_string,
            version,
            headers,
            body,
        }))
    }

    /// 完全なレスポンスが受信されたか確認してパースする
    pub fn try_parse(&mut self) -> Result<Option<HttpResponse>, HttpParseError> {
        // Security: Overall message size limit (including headers) to prevent DoS
        const MAX_TOTAL_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MB
        if self.buffer.len() > MAX_TOTAL_MESSAGE_SIZE {
            return Err(HttpParseError::InvalidFormat);
        }

        // ヘッダの終わりを検索
        let header_end_idx = match self.find_header_end() {
            Some(idx) => idx,
            None => {
                // Security: Limit header size to prevent memory DoS
                if self.buffer.len() > 8192 {
                    return Err(HttpParseError::InvalidFormat);
                }
                return Ok(None); // まだヘッダが完了していない
            }
        };

        let header_bytes = &self.buffer[..header_end_idx];
        let header_str = str::from_utf8(header_bytes).map_err(|_| HttpParseError::InvalidEncoding)?;
        
        let mut lines = header_str.split("\r\n");
        
        // ステータス行のパース
        let status_line = lines.next().ok_or(HttpParseError::InvalidFormat)?;
        let mut status_parts = status_line.splitn(3, ' ');
        
        let version_str = status_parts.next().ok_or(HttpParseError::InvalidFormat)?;
        let version = match version_str {
            "HTTP/1.0" => HttpVersion::Http1_0,
            "HTTP/1.1" => HttpVersion::Http1_1,
            _ => return Err(HttpParseError::UnsupportedVersion),
        };
        
        let status_code_str = status_parts.next().ok_or(HttpParseError::InvalidFormat)?;
        let status_code: u16 = status_code_str.parse().map_err(|_| HttpParseError::InvalidFormat)?;
        
        // Security: Limit reason phrase length
        let reason_phrase_raw = status_parts.next().unwrap_or("").trim();
        if reason_phrase_raw.len() > 1024 {
            return Err(HttpParseError::InvalidFormat);
        }
        let reason_phrase = reason_phrase_raw.into();
        
        // ヘッダ行のパース
        let mut headers = Vec::new();
        let mut content_length = None;
        let mut chunked = false;
        
        for line in lines {
            if line.is_empty() {
                continue;
            }
            
            // Security: Limit number of headers to prevent memory DoS / HashDoS
            if headers.len() >= 100 {
                return Err(HttpParseError::InvalidFormat);
            }
            
            let mut parts = line.splitn(2, ':');
            let name = parts.next().ok_or(HttpParseError::InvalidFormat)?.trim();
            let value = parts.next().ok_or(HttpParseError::InvalidFormat)?.trim();
            
            // Security: Limit header name and value length
            if name.len() > 256 || value.len() > 4096 {
                return Err(HttpParseError::InvalidFormat);
            }
            
            headers.push(HttpHeader::new(name, value));
            
            if name.eq_ignore_ascii_case("Content-Length") {
                let len = value.parse::<usize>().map_err(|_| HttpParseError::InvalidFormat)?;
                // Security: Limit content length to 10MB
                if len > 10 * 1024 * 1024 {
                    return Err(HttpParseError::InvalidFormat);
                }
                content_length = Some(len);
            } else if name.eq_ignore_ascii_case("Transfer-Encoding") && value.to_lowercase().contains("chunked") {
                chunked = true;
            }
        }
        
        // Security: RFC 7230 - Request Smuggling / Response Splitting prevention
        if chunked && content_length.is_some() {
            return Err(HttpParseError::InvalidFormat);
        }
        
        let body_start_idx = header_end_idx + 4; // \r\n\r\n
        
        let (body, total_len) = if chunked {
            // chunked転送のパース
            let res = self.parse_chunked(body_start_idx)?;
            if res.1 == 0 {
                return Ok(None); // まだデータが完了していない
            }
            res
        } else if let Some(len) = content_length {
            if self.buffer.len() < body_start_idx + len {
                return Ok(None); // まだボディが完了していない
            }
            let body = self.buffer[body_start_idx..body_start_idx + len].to_vec();
            (body, body_start_idx + len)
        } else {
            // Content-Length も Transfer-Encoding: chunked もない場合
            // HTTP/1.1 ではボディなし、または接続終了まで読み込む
            // ここでは簡易的にボディなしとして扱う
            (Vec::new(), body_start_idx)
        };
        
        // パース済みのデータをバッファから削除
        self.buffer.drain(..total_len);

        Ok(Some(HttpResponse {
            version,
            status_code,
            reason_phrase,
            headers,
            body,
        }))
    }

    /// chunkedエンコーディングのパース
    fn parse_chunked(&self, start_idx: usize) -> Result<(Vec<u8>, usize), HttpParseError> {
        let mut body = Vec::new();
        let mut current_pos = start_idx;
        let mut chunk_count = 0;
        const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
        const MAX_CHUNKS: usize = 1024;

        loop {
            // Security: Limit number of chunks
            chunk_count += 1;
            if chunk_count > MAX_CHUNKS {
                return Err(HttpParseError::InvalidFormat);
            }

            // チャンクサイズの行を探す
            let line_end = self.find_line_end(current_pos);
            let end_idx = match line_end {
                Some(idx) => idx,
                None => return Ok((Vec::new(), 0)), // 不完全なデータ
            };

            let line = str::from_utf8(&self.buffer[current_pos..end_idx]).map_err(|_| HttpParseError::InvalidEncoding)?;
            // チャンクサイズは16進数。セミコロン以降のチャンク拡張は無視する。
            let line_trim = line.trim();
            let hex_part = line_trim.split(';').next().unwrap_or(line_trim).trim();
            let chunk_size = usize::from_str_radix(hex_part, 16).map_err(|_| HttpParseError::InvalidFormat)?;

            // Security: Check for integer overflow and body size limit
            if chunk_size > MAX_BODY_SIZE || body.len() + chunk_size > MAX_BODY_SIZE {
                return Err(HttpParseError::InvalidFormat);
            }

            current_pos = end_idx + 2; // \r\n を飛ばす

            if chunk_size == 0 {
                // 最後のチャンク (0\r\n\r\n)
                if self.buffer.len() < current_pos + 2 {
                    return Ok((Vec::new(), 0)); 
                }
                current_pos += 2; 
                break;
            }

            // Check if entire chunk + trailing CRLF is in buffer
            let chunk_end = current_pos.checked_add(chunk_size).and_then(|c| c.checked_add(2));
            let chunk_end_pos = match chunk_end {
                Some(pos) => pos,
                None => return Err(HttpParseError::InvalidFormat),
            };

            if self.buffer.len() < chunk_end_pos {
                return Ok((Vec::new(), 0)); // データ不足
            }

            body.extend_from_slice(&self.buffer[current_pos..current_pos + chunk_size]);
            current_pos = chunk_end_pos;
        }

        Ok((body, current_pos))
    }

    fn find_header_end(&self) -> Option<usize> {
        for i in 0..self.buffer.len().saturating_sub(3) {
            if &self.buffer[i..i+4] == b"\r\n\r\n" {
                return Some(i);
            }
        }
        None
    }

    fn find_line_end(&self, start: usize) -> Option<usize> {
        for i in start..self.buffer.len().saturating_sub(1) {
            if &self.buffer[i..i+2] == b"\r\n" {
                return Some(i);
            }
        }
        None
    }
}

// 修正後の try_parse 内での chunked 処理呼び出しの結果を適切に扱うようにラップ
impl HttpParser {
    pub fn try_parse_wrapped(&mut self) -> Result<Option<HttpResponse>, HttpParseError> {
        let res = self.try_parse()?;
        match res {
            Some(resp) => Ok(Some(resp)),
            None => Ok(None),
        }
    }
}
