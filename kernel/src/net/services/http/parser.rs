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
        
        let reason_phrase = status_parts.next().unwrap_or("").trim().into();
        
        // ヘッダ行のパース
        let mut headers = Vec::new();
        let mut content_length = None;
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
                content_length = Some(value.parse::<usize>().map_err(|_| HttpParseError::InvalidFormat)?);
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

        loop {
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

            current_pos = end_idx + 2; // \r\n を飛ばす

            if chunk_size == 0 {
                // 最後のチャンク (0\r\n\r\n)
                if self.buffer.len() < current_pos + 2 {
                    // まだ最後の \r\n が来ていない可能性（またはフッタがある可能性）
                    // ここでは簡易的に \r\n があるか確認
                    return Ok((Vec::new(), 0)); 
                }
                // 実際にはフッタ（トレイラー）があるかもしれないが、ここでは無視
                current_pos += 2; 
                break;
            }

            if self.buffer.len() < current_pos + chunk_size + 2 {
                return Ok((Vec::new(), 0)); // データ不足
            }

            body.extend_from_slice(&self.buffer[current_pos..current_pos + chunk_size]);
            current_pos += chunk_size + 2; // データ本体 + \r\n
        }

        // 成功した場合、(ボディ, 消費した全バイト数)
        if current_pos == 0 {
             Ok((Vec::new(), 0))
        } else {
             Ok((body, current_pos))
        }
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
