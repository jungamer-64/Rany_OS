// ============================================================================
// kernel/src/net/services/http/client.rs
// ============================================================================

use alloc::boxed::Box;
use alloc::string::String;

use super::parser::{HttpParseError, HttpParser};
use super::types::{HttpRequest, HttpResponseView};
use crate::net::l4::tcp::{EndpointAddr, TcpConnection};
use crate::net::security::tls::connection::TlsConnection;
use crate::net::security::tls::types::{TlsConfig, TlsState};
use crate::net::services::dns::resolve_ipv4;
use kernel_api::resource::net::PacketPayload;

async fn send_payload(
    connection: &mut TcpConnection,
    payload: PacketPayload,
) -> Result<(), HttpClientError> {
    connection
        .send_payload(payload)
        .await
        .map_err(|_| HttpClientError::WriteError)?;
    connection
        .drain_tx()
        .await
        .map_err(|_| HttpClientError::WriteError)
}


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
    pub timeout_ms: u64,
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
    pub async fn send(&self, mut req: HttpRequest) -> Result<HttpResponseView, HttpClientError> {
        let (host, port, path, is_https) =
            Self::parse_url(&req.uri).unwrap_or((req.uri.clone(), 80, String::from("/"), false));

        // リクエストURIをホスト部を除いたパスに書き換える
        req.uri = path;

        // Hostヘッダが存在しなければ追加
        if !req
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("Host"))
        {
            req.headers
                .push(super::types::HttpHeader::new("Host", &host));
        }

        // Connection: close を追加（現在持続的接続は未対応のため）
        if !req
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("Connection"))
        {
            req.headers
                .push(super::types::HttpHeader::new("Connection", "close"));
        }

        // 1. DNS解決（非同期Global APIを使用）
        let ip_addr = resolve_ipv4(&host)
            .await
            .ok_or(HttpClientError::DnsResolutionFailed)?;

        // 2. TCP接続確立
        let remote_addr = EndpointAddr::new(ip_addr.octets(), port);

        let mut connection =
            TcpConnection::dial_in(crate::net::runtime::default_runtime(), remote_addr)
                .await
                .map_err(|_| HttpClientError::ConnectionFailed)?;

        let request_payload = req.into_payload().ok_or(HttpClientError::WriteError)?;
        let mut parser = HttpParser::new();

        // 3. 通信 (TLS or 平文)
        if is_https {
            // HTTPS
            let tls_config = TlsConfig::default().with_server_name(&host);
            let mut tls = Box::new(TlsConnection::new(tls_config));

            // ClientHello 送信
            let client_hello = tls.build_client_hello();
            send_payload(&mut connection, client_hello).await?;

            // ハンドシェイク
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while tls.state() != TlsState::Established && tls.state() != TlsState::Error {
                let Some(in_payload) = connection.recv_payload().await else {
                    return Err(HttpClientError::TlsHandshakeFailed);
                };

                // 受信データを処理
                let _app_data = tls
                    .process_incoming_payload(&in_payload)
                    .map_err(|_| HttpClientError::TlsHandshakeFailed)?;

                // 状態遷移に応じた応答を構築して送信
                match tls.state() {
                    TlsState::Handshaking => {
                        // TLS 1.2: ServerHelloDone 受信後
                        if let Some(cke) = tls.build_client_key_exchange_payload() {
                            send_payload(&mut connection, cke).await?;
                        } else if let Some(cke_rsa) = tls.build_client_key_exchange_rsa_payload() {
                            send_payload(&mut connection, cke_rsa).await?;
                        }

                        let ccs = tls.build_change_cipher_spec_payload();
                        send_payload(&mut connection, ccs).await?;

                        if let Ok(fin) = tls.build_client_finished_tls12_payload() {
                            send_payload(&mut connection, fin).await?;
                        }
                    }
                    TlsState::Tls13ServerFinishedReceived => {
                        // TLS 1.3: Server Finished 受信後
                        if let Ok(fin) = tls.build_client_finished_tls13_payload() {
                            send_payload(&mut connection, fin).await?;
                        }
                    }
                    _ => {}
                }
            }

            if tls.state() != TlsState::Established {
                return Err(HttpClientError::TlsHandshakeFailed);
            }

            // HTTPリクエストの暗号化と送信
            let encrypted_request = tls
                .encrypt_application_payload(&request_payload)
                .map_err(|_| HttpClientError::WriteError)?;
            send_payload(&mut connection, encrypted_request).await?;

            // HTTPレスポンスの受信と復号
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                let Some(in_payload) = connection.recv_payload().await else {
                    break; // EOF
                };

                let app_data = tls
                    .process_incoming_payload(&in_payload)
                    .map_err(|_| HttpClientError::ReadError)?;

                // KeyUpdate 等のポストハンドシェイク応答があれば送信
                if let Some(resp) = tls.build_key_update_response_payload() {
                    send_payload(&mut connection, resp).await?;
                }

                if !app_data.is_empty() {
                    parser.push_payload(app_data);

                    if let Some(response) =
                        parser.try_parse().map_err(HttpClientError::ParseError)?
                    {
                        return Ok(response);
                    }
                }
            }
        } else {
            // HTTP
            send_payload(&mut connection, request_payload).await?;

            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                let Some(in_payload) = connection.recv_payload().await else {
                    break; // EOF
                };

                parser.push_payload(in_payload);
                if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
                    return Ok(response);
                }
            }
        }

        // EOFまで読み切ってパース完了しなかった場合
        if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
            Ok(response)
        } else {
            Err(HttpClientError::ParseError(
                HttpParseError::IncompleteMessage,
            ))
        }
    }
}
