// ============================================================================
// kernel/src/net/services/http/client.rs
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;

use crate::net::l4::tcp::{TcpStream, SocketAddr, Ipv4Addr};
use crate::net::services::dns::resolve_ipv4;
use super::types::{HttpRequest, HttpResponse};
use super::parser::{HttpParser, HttpParseError};
use crate::net::security::tls::{TlsConnection, TlsConfig};

#[derive(Debug)]
pub enum HttpClientError {
    DnsResolutionFailed,
    ConnectionFailed,
    TlsHandshakeFailed,
    WriteError,
    ReadError,
    ParseError(HttpParseError),
}

/// HTTP/HTTPS クライアント
pub struct HttpClient {
    timeout_ms: u64,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            timeout_ms: 10000, // デフォルト 10秒
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// URLをパースして、ホスト名、ポート、パス、そしてHTTPSかどうかを返す
    fn parse_url(url: &str) -> Option<(String, u16, String, bool)> {
        let (is_https, rest) = if url.starts_with("https://") {
            (true, &url[8..])
        } else if url.starts_with("http://") {
            (false, &url[7..])
        } else {
            return None; // スキーム不正
        };

        let slash_idx = rest.find('/').unwrap_or(rest.len());
        let host_port_str = &rest[..slash_idx];
        let path_str = if slash_idx == rest.len() {
            "/"
        } else {
            &rest[slash_idx..]
        };

        let (host, port) = if let Some(colon_idx) = host_port_str.find(':') {
            let p: u16 = host_port_str[colon_idx + 1..].parse().ok()?;
            (String::from(&host_port_str[..colon_idx]), p)
        } else {
            (String::from(host_port_str), if is_https { 443 } else { 80 })
        };

        Some((host, port, String::from(path_str), is_https))
    }

    /// リクエストを非同期で送信し、レスポンスを取得する
    pub async fn send(&self, mut req: HttpRequest) -> Result<HttpResponse, HttpClientError> {
        let (host, port, path, is_https) = Self::parse_url(&req.uri)
            .unwrap_or((req.uri.clone(), 80, String::from("/"), false));
            
        // リクエストURIをホスト部を除いたパスに書き換える
        req.uri = path;
        
        // Hostヘッダが存在しなければ追加
        if !req.headers.iter().any(|h| h.name.eq_ignore_ascii_case("Host")) {
            req.headers.push(super::types::HttpHeader::new("Host", &host));
        }
        
        // Connection: close を追加（現在持続的接続は未対応のため）
        if !req.headers.iter().any(|h| h.name.eq_ignore_ascii_case("Connection")) {
            req.headers.push(super::types::HttpHeader::new("Connection", "close"));
        }

        // 1. DNS解決
        let ip_addr = resolve_ipv4(&host).await
            .ok_or(HttpClientError::DnsResolutionFailed)?;

        // 2. TCP接続確立
        let remote_addr = SocketAddr::new(ip_addr, port);
        // FIXME: 適当なローカルポートを選択するか、エフェメラルポートアロケータを使用
        // 今回は単純化のため、乱数等を使用するのが理想的だが、簡易的に固定またはスタック任せとする
        // 実際にはカーネルのバインドアロケータに依存
        let local_port = crate::task::timer::current_tick() as u16 % 16384 + 49152; 
        let local_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED, local_port);

        let mut stream = TcpStream::connect(local_addr, remote_addr).await
            .map_err(|_| HttpClientError::ConnectionFailed)?;

        let request_bytes = req.to_bytes();
        let mut parser = HttpParser::new();

        // 3. 通信 (TLS or 平文)
        if is_https {
            // HTTPS
            let mut tls_config = TlsConfig::default();
            tls_config.set_server_name(&host);
            let mut tls = Box::new(TlsConnection::new(tls_config));

            // ハンドシェイク
            while !tls.is_handshake_complete() {
                // 送信すべきデータがあればストリームへ
                let mut out_buf = [0u8; 4096];
                if let Ok(len) = tls.read_tls_output(&mut out_buf) {
                    if len > 0 {
                        stream.write_all(&out_buf[..len]).await.map_err(|_| HttpClientError::WriteError)?;
                    }
                }

                if tls.is_handshake_complete() {
                    break;
                }

                // ストリームからデータを受信してTLSに入力
                let mut in_buf = [0u8; 4096];
                let read_len = stream.read(&mut in_buf).await.map_err(|_| HttpClientError::ReadError)?;
                if read_len == 0 {
                    return Err(HttpClientError::TlsHandshakeFailed);
                }
                tls.process_tls_input(&in_buf[..read_len]).map_err(|_| HttpClientError::TlsHandshakeFailed)?;
            }

            // HTTPリクエストの暗号化と送信
            tls.write_application_data(&request_bytes).map_err(|_| HttpClientError::WriteError)?;
            let mut out_buf = [0u8; 4096];
            while let Ok(len) = tls.read_tls_output(&mut out_buf) {
                if len == 0 { break; }
                stream.write_all(&out_buf[..len]).await.map_err(|_| HttpClientError::WriteError)?;
            }

            // HTTPレスポンスの受信と復号
            loop {
                let mut in_buf = [0u8; 4096];
                let read_len = stream.read(&mut in_buf).await.map_err(|_| HttpClientError::ReadError)?;
                if read_len == 0 {
                    break; // EOF
                }
                tls.process_tls_input(&in_buf[..read_len]).map_err(|_| HttpClientError::ReadError)?;
                
                let mut app_data = [0u8; 4096];
                while let Ok(len) = tls.read_application_data(&mut app_data) {
                    if len == 0 { break; }
                    parser.push_data(&app_data[..len]);
                    
                    if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
                        return Ok(response);
                    }
                }
            }

        } else {
            // HTTP
            stream.write_all(&request_bytes).await.map_err(|_| HttpClientError::WriteError)?;

            loop {
                let mut in_buf = [0u8; 4096];
                let read_len = stream.read(&mut in_buf).await.map_err(|_| HttpClientError::ReadError)?;
                if read_len == 0 {
                    break; // EOF
                }
                
                parser.push_data(&in_buf[..read_len]);
                if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
                    return Ok(response);
                }
            }
        }

        // EOFまで読み切ってパース完了しなかった場合
        if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
             Ok(response)
        } else {
             Err(HttpClientError::ParseError(HttpParseError::IncompleteMessage))
        }
    }
}
