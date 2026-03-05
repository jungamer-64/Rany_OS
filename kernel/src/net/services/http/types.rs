// ============================================================================
// kernel/src/net/services/http/types.rs
// ============================================================================

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

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

/// HTTPヘッダ
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

/// HTTPリクエストビルダー
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
    pub headers: Vec<HttpHeader>,
    pub body: Option<Vec<u8>>,
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

    pub fn body(mut self, data: Vec<u8>) -> Self {
        self.headers.push(HttpHeader::new("Content-Length", data.len().to_string().as_str()));
        self.body = Some(data);
        self
    }

    /// バイト列にシリアライズ
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(&alloc::format!("{} {} {}\r\n", self.method, self.uri, self.version));
        
        for header in &self.headers {
            out.push_str(&alloc::format!("{}: {}\r\n", header.name, header.value));
        }
        
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        
        if let Some(body) = &self.body {
            bytes.extend_from_slice(body);
        }
        
        bytes
    }
    
    /// 特定のヘッダの値を取得（大文字小文字を区別しない）
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|h| {
            if h.name.eq_ignore_ascii_case(name) {
                Some(h.value.as_str())
            } else {
                None
            }
        })
    }
}

/// HTTPレスポンス
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status_code: u16, reason_phrase: impl ToString) -> Self {
        Self {
            version: HttpVersion::Http1_1,
            status_code,
            reason_phrase: reason_phrase.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    pub fn body(mut self, data: impl Into<Vec<u8>>) -> Self {
        let body_data = data.into();
        self.headers.push(HttpHeader::new("Content-Length", body_data.len().to_string().as_str()));
        self.body = body_data;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(&alloc::format!("{} {} {}\r\n", self.version, self.status_code, self.reason_phrase));
        
        for header in &self.headers {
            out.push_str(&alloc::format!("{}: {}\r\n", header.name, header.value));
        }
        
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        
        if !self.body.is_empty() {
            bytes.extend_from_slice(&self.body);
        }
        
        bytes
    }

    /// 特定のヘッダの値を取得（大文字小文字を区別しない）
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|h| {
            if h.name.eq_ignore_ascii_case(name) {
                Some(h.value.as_str())
            } else {
                None
            }
        })
    }
}
