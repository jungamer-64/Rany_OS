// ============================================================================
// kernel/src/net/services/http/parser.rs
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;
use super::types::{HttpResponse, HttpVersion, HttpHeader};
use core::str;

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

    /// 完全なレスポンスが受信されたか確認してパースする
    pub fn try_parse(&mut self) -> Result<Option<HttpResponse>, HttpParseError> {
        // ヘッダの終わりを検索
        let header_end_idx = match self.find_header_end() {
            Some(idx) => idx,
            None => return Ok(None), // まだヘッダが完了していない
        };

        let header_bytes = &self.buffer[..header_end_idx];
        let header_str = str::from_utf8(header_bytes).map_err(|_| HttpParseError::InvalidEncoding)?;
        
        let mut lines = header_str.split("
");
        
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
        
        let reason_phrase = status_parts.next().unwrap_or("").trim().into();
        
        // ヘッダ行のパース
        let mut headers = Vec::new();
        let mut content_length = 0usize;
        let mut chunked = false;
        
        for line in lines {
            if line.is_empty() {
                continue;
            }
            
            let mut parts = line.splitn(2, ':');
            let name = parts.next().ok_or(HttpParseError::InvalidFormat)?.trim();
            let value = parts.next().ok_or(HttpParseError::InvalidFormat)?.trim();
            
            headers.push(HttpHeader::new(name, value));
            
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.parse().map_err(|_| HttpParseError::InvalidFormat)?;
            } else if name.eq_ignore_ascii_case("Transfer-Encoding") && value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
        
        // ボディの抽出（簡易実装: 現在はContent-Lengthベースのみ対応、chunkedは非対応）
        // 実際のカーネルHTTPクライアントではchunked等の対応も将来必要
        let body_start_idx = header_end_idx + 4; // 


        
        if chunked {
            // TODO: chunked転送のパースを実装
            return Err(HttpParseError::InvalidFormat);
        }

        if self.buffer.len() < body_start_idx + content_length {
            return Ok(None); // まだボディが完了していない
        }
        
        let body = self.buffer[body_start_idx..body_start_idx + content_length].to_vec();
        
        // パース済みのデータをバッファから削除
        self.buffer.drain(..body_start_idx + content_length);

        Ok(Some(HttpResponse {
            version,
            status_code,
            reason_phrase,
            headers,
            body,
        }))
    }

    fn find_header_end(&self) -> Option<usize> {
        for i in 0..self.buffer.len().saturating_sub(3) {
            if &self.buffer[i..i+4] == b"

" {
                return Some(i);
            }
        }
        None
    }
}
