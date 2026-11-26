// ============================================================================
// kernel/src/net/services/http/client.rs - サービス / HTTP / クライアント
// ============================================================================

use alloc::boxed::Box;

use super::parser::{HttpParseError, HttpParser, ResponseInput};
use super::types::{
    ConnectionDirective, HttpHeader, HttpHeaderName, HttpHeaderValue, HttpInboundResponse,
    HttpMethod, HttpRequest, HttpRequestTarget, HttpRequestUri,
};
use crate::net::l4::tcp::{EndpointAddr, TcpConnection};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::security::tls::{
    KeyUpdateAction, TlsClientConfig, TlsError, TlsEstablishedSession, TlsHandshake,
    TlsHandshakeStep, TlsTrustAnchors,
};
use crate::net::services::dns::resolve_ipv4_in;
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

async fn recv_tls_handshake_payload(
    connection: &mut TcpConnection,
) -> Result<PacketPayload, HttpClientError> {
    connection
        .recv_payload()
        .await
        .map_err(|_| HttpClientError::TlsHandshakeFailed)?
        .ok_or(HttpClientError::TlsHandshakeFailed)
}

async fn complete_tls_handshake(
    mut handshake: TlsHandshake,
    connection: &mut TcpConnection,
) -> Result<TlsEstablishedSession, HttpClientError> {
    // LOOP_PROOF: mode=event; reason=Each handshake step awaits incoming TCP data and any outgoing ClientHello, returning an established session or transport or TLS failure.;
    loop {
        let in_payload = recv_tls_handshake_payload(connection).await?;
        match handshake
            .process_incoming_payload(in_payload)
            .map_err(HttpClientError::TlsProtocol)?
        {
            TlsHandshakeStep::NeedMoreInput(next) => handshake = next,
            TlsHandshakeStep::SendClientHello {
                handshake: next,
                payload,
            } => {
                send_payload(connection, payload).await?;
                handshake = next;
            }
            TlsHandshakeStep::Established { session, payload } => {
                send_payload(connection, payload).await?;
                return Ok(session);
            }
        }
    }
}

async fn send_over_plain_transport(
    connection: &mut TcpConnection,
    request_payload: PacketPayload,
    method: HttpMethod,
) -> Result<HttpInboundResponse, HttpClientError> {
    let mut parser = HttpParser::new();
    send_payload(connection, request_payload).await?;
    // LOOP_PROOF: mode=event; reason=Each iteration awaits TCP receive and stops on a final response, EOF, or an error.;
    loop {
        let Some(payload) = connection
            .recv_payload()
            .await
            .map_err(|_| HttpClientError::ReadError)?
        else {
            return finish_response(&mut parser, method);
        };
        parser
            .push_payload(payload)
            .map_err(HttpClientError::ParseError)?;
        if let Some(response) = parser
            .next_final_response(method, ResponseInput::Open)
            .map_err(HttpClientError::ParseError)?
        {
            return Ok(response);
        }
    }
}

async fn send_over_tls_transport(
    host: &str,
    connection: &mut TcpConnection,
    request_payload: PacketPayload,
    method: HttpMethod,
) -> Result<HttpInboundResponse, HttpClientError> {
    let trust_anchors =
        TlsTrustAnchors::system_roots().map_err(|_| HttpClientError::TlsHandshakeFailed)?;
    let tls_config = TlsClientConfig::for_server_name(host, trust_anchors)
        .and_then(|config| config.with_alpn(&["http/1.1"]))
        .map_err(|_| HttpClientError::TlsHandshakeFailed)?;
    let (handshake, client_hello) =
        TlsHandshake::start(tls_config).map_err(HttpClientError::TlsProtocol)?;
    send_payload(connection, client_hello).await?;
    let mut tls = Box::new(complete_tls_handshake(handshake, connection).await?);

    let encrypted_request = tls
        .encrypt_payload(request_payload)
        .map_err(HttpClientError::TlsProtocol)?;
    send_payload(connection, encrypted_request).await?;

    let response = receive_tls_response(&mut tls, connection, method).await?;
    if let Ok(close_notify) = tls.send_close_notify() {
        // Graceful TCP close drains admitted bytes after this function returns.
        let _ = connection.send_payload(close_notify).await;
    }
    Ok(response)
}

async fn receive_tls_response(
    tls: &mut TlsEstablishedSession,
    connection: &mut TcpConnection,
    method: HttpMethod,
) -> Result<HttpInboundResponse, HttpClientError> {
    let mut parser = HttpParser::new();
    // LOOP_PROOF: mode=event; reason=Each iteration awaits a transport payload or terminates on a response boundary, closure, or an error.;
    loop {
        let payload = connection
            .recv_payload()
            .await
            .map_err(|_| HttpClientError::ReadError)?
            .ok_or(HttpClientError::ParseError(
                HttpParseError::IncompleteMessage,
            ))?;
        let inbound = tls
            .process_incoming_payload(payload)
            .map_err(HttpClientError::TlsProtocol)?;
        if let Some(data) = inbound.application_data {
            parser
                .push_payload(data)
                .map_err(HttpClientError::ParseError)?;
        }
        if inbound.peer_closed {
            return finish_response(&mut parser, method);
        }
        if let KeyUpdateAction::Send(payload) = inbound.key_update {
            send_payload(connection, payload).await?;
        }
        if let Some(response) = parser
            .next_final_response(method, ResponseInput::Open)
            .map_err(HttpClientError::ParseError)?
        {
            return Ok(response);
        }
    }
}

fn finish_response(
    parser: &mut HttpParser,
    method: HttpMethod,
) -> Result<HttpInboundResponse, HttpClientError> {
    parser
        .next_final_response(method, ResponseInput::Complete)
        .map_err(HttpClientError::ParseError)?
        .ok_or(HttpClientError::ParseError(
            HttpParseError::IncompleteMessage,
        ))
}

fn ensure_host_header(req: &mut HttpRequest, host: &str) -> Result<(), HttpClientError> {
    if req.has_header_name(HttpHeaderName::Host) {
        return Ok(());
    }

    let host_value = HttpHeaderValue::parse(host).ok_or(HttpClientError::InvalidUrl)?;
    req.headers
        .push(HttpHeader::new(HttpHeaderName::Host, host_value));
    Ok(())
}

fn ensure_connection_close_header(req: &mut HttpRequest) {
    if req.has_header_name(HttpHeaderName::Connection) {
        return;
    }

    req.headers.push(HttpHeader::new(
        HttpHeaderName::Connection,
        HttpHeaderValue::from_static(ConnectionDirective::Close.as_header_value()),
    ));
}

#[derive(Debug)]
pub enum HttpClientError {
    DnsResolutionFailed,
    ConnectionFailed,
    InvalidUrl,
    TlsHandshakeFailed,
    TlsProtocol(TlsError),
    WriteError,
    ReadError,
    ParseError(HttpParseError),
    /// The exchange did not finish within the client timeout.
    Timeout,
    /// The timeout timer could not be admitted.
    Timer(kernel_api::service::time::TimerError),
}

impl core::fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DnsResolutionFailed => f.write_str("DNS resolution failed"),
            Self::ConnectionFailed => f.write_str("TCP connection failed"),
            Self::InvalidUrl => f.write_str("invalid URL"),
            Self::TlsHandshakeFailed => f.write_str("TLS handshake failed"),
            Self::TlsProtocol(error) => write!(f, "TLS failed: {error}"),
            Self::WriteError => f.write_str("request write failed"),
            Self::ReadError => f.write_str("response read failed"),
            Self::ParseError(error) => write!(f, "response parse failed: {:?}", error),
            Self::Timeout => f.write_str("exchange timed out"),
            Self::Timer(cause) => write!(f, "timeout timer unavailable: {}", cause),
        }
    }
}

/// HTTP/HTTPS クライアント
pub struct HttpClient {
    runtime: NetRuntimeHandle,
    /// Deadline for one complete exchange, from DNS resolution to the response.
    timeout_ms: u64,
}

impl HttpClient {
    pub fn new(runtime: NetRuntimeHandle) -> Self {
        Self {
            runtime,
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

    fn prepare_request(
        mut req: HttpRequest,
    ) -> Result<(HttpRequest, alloc::string::String, u16, bool), HttpClientError> {
        let original_uri = core::mem::replace(
            &mut req.uri,
            HttpRequestUri::OriginForm(HttpRequestTarget::root()),
        );
        let (host, port, path, is_https) =
            Self::split_request_uri(original_uri).ok_or(HttpClientError::InvalidUrl)?;

        req.uri = HttpRequestUri::OriginForm(path);
        ensure_host_header(&mut req, &host)?;
        ensure_connection_close_header(&mut req);

        Ok((req, host, port, is_https))
    }

    async fn connect(&self, host: &str, port: u16) -> Result<TcpConnection, HttpClientError> {
        let ip_addr = resolve_ipv4_in(self.runtime, host)
            .await
            .ok_or(HttpClientError::DnsResolutionFailed)?;
        let remote_addr = EndpointAddr::new(ip_addr.octets(), port);

        TcpConnection::dial_in(self.runtime, remote_addr)
            .await
            .map_err(|_| HttpClientError::ConnectionFailed)
    }

    /// リクエストを非同期で送信し、レスポンスを取得する
    ///
    /// # Errors
    /// Returns [`HttpClientError::Timeout`] when the exchange exceeds the
    /// client timeout, and the exchange failure otherwise.
    pub async fn send(&self, req: HttpRequest) -> Result<HttpInboundResponse, HttpClientError> {
        match crate::task::with_timeout(self.exchange(req), self.timeout_ms).await {
            crate::task::TimeoutResult::Completed(result) => result,
            crate::task::TimeoutResult::TimedOut => Err(HttpClientError::Timeout),
            crate::task::TimeoutResult::TimerFailed(cause) => Err(HttpClientError::Timer(cause)),
        }
    }

    async fn exchange(&self, req: HttpRequest) -> Result<HttpInboundResponse, HttpClientError> {
        let (req, host, port, is_https) = Self::prepare_request(req)?;
        let mut connection = self.connect(&host, port).await?;
        let method = req.method;
        let request_payload = req.into_payload().ok_or(HttpClientError::WriteError)?;
        let response = if is_https {
            send_over_tls_transport(&host, &mut connection, request_payload, method).await?
        } else {
            send_over_plain_transport(&mut connection, request_payload, method).await?
        };
        connection.close();
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::HttpClient;

    #[test]
    fn split_request_uri_accepts_absolute() {
        let Some(uri) = crate::net::services::http::types::HttpRequestUri::parse(
            "https://example.com:443/v1/health",
        ) else {
            panic!("absolute URI must be parsed");
        };

        let Some((host, port, target, is_https)) = HttpClient::split_request_uri(uri) else {
            panic!("absolute URI must be split");
        };

        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(target.as_str(), "/v1/health");
        assert!(is_https);
    }

    #[test]
    fn split_request_uri_rejects_origin_form() {
        let Some(uri) = crate::net::services::http::types::HttpRequestUri::origin_form("/") else {
            panic!("origin-form URI must be parsed");
        };

        assert!(HttpClient::split_request_uri(uri).is_none());
    }
    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn reports_the_peer_alert_number() {
        let error = super::HttpClientError::TlsProtocol(super::TlsError::Alert(40));
        assert_eq!(alloc::format!("{error}"), "TLS failed: peer alert 40");
    }
}
