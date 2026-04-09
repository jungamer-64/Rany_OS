// ============================================================================
// kernel/src/net/services/http/client.rs
// ============================================================================

use alloc::boxed::Box;

use super::parser::{HttpParseError, HttpParser};
use super::types::{
    ConnectionDirective, HttpHeader, HttpHeaderName, HttpHeaderValue, HttpRequest,
    HttpRequestTarget, HttpRequestUri, HttpResponseView,
};
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

async fn send_tls12_client_handshake_flight(
    tls: &mut TlsConnection,
    connection: &mut TcpConnection,
) -> Result<(), HttpClientError> {
    let key_exchange = tls
        .build_client_key_exchange_payload()
        .or_else(|| tls.build_client_key_exchange_rsa_payload())
        .ok_or(HttpClientError::TlsHandshakeFailed)?;
    send_payload(connection, key_exchange).await?;

    let ccs = tls.build_change_cipher_spec_payload();
    send_payload(connection, ccs).await?;

    let finished = tls
        .build_client_finished_tls12_payload()
        .map_err(|_| HttpClientError::TlsHandshakeFailed)?;
    send_payload(connection, finished).await
}


#[derive(Debug)]
pub enum HttpClientError {
    DnsResolutionFailed,
    ConnectionFailed,
    InvalidUrl,
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

    /// クライアント送信用 URI を分解する
    fn split_request_uri(
        uri: HttpRequestUri,
    ) -> Option<(alloc::string::String, u16, HttpRequestTarget, bool)> {
        match uri {
            HttpRequestUri::Absolute {
                scheme,
                host,
                port,
                target,
            } => Some((
                alloc::string::String::from(host.as_str()),
                port.as_u16(),
                target,
                scheme.is_https(),
            )),
            HttpRequestUri::OriginForm(_) => None,
        }
    }

    /// リクエストを非同期で送信し、レスポンスを取得する
    pub async fn send(&self, mut req: HttpRequest) -> Result<HttpResponseView, HttpClientError> {
        let original_uri = core::mem::replace(
            &mut req.uri,
            HttpRequestUri::OriginForm(HttpRequestTarget::root()),
        );
        let (host, port, path, is_https) =
            Self::split_request_uri(original_uri).ok_or(HttpClientError::InvalidUrl)?;

        // リクエストURIをホスト部を除いたパスに書き換える
        req.uri = HttpRequestUri::OriginForm(path);

        // Hostヘッダが存在しなければ追加
        if !req.has_header_name(HttpHeaderName::Host) {
            req.headers.push(HttpHeader::new(
                HttpHeaderName::Host,
                HttpHeaderValue::parse(&host).ok_or(HttpClientError::InvalidUrl)?,
            ));
        }

        // Connection: close を追加（現在持続的接続は未対応のため）
        if !req.has_header_name(HttpHeaderName::Connection) {
            req.headers.push(HttpHeader::new(
                HttpHeaderName::Connection,
                HttpHeaderValue::from_static(ConnectionDirective::Close.as_header_value()),
            ));
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
            let mut tls12_client_flight_sent = false;
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
                        // TLS 1.2: ServerHelloDone 受信後に送るクライアントフライトは1回のみ。
                        if !tls12_client_flight_sent && !tls.is_tls13() {
                            send_tls12_client_handshake_flight(&mut tls, &mut connection).await?;
                            tls12_client_flight_sent = true;
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
        } else if let Some(response) = parser
            .try_parse_response_on_eof()
            .map_err(HttpClientError::ParseError)?
        {
            Ok(response)
        } else {
            Err(HttpClientError::ParseError(
                HttpParseError::IncompleteMessage,
            ))
        }
    }
}
