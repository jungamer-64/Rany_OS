// ============================================================================
// kernel/src/net/services/http/client.rs - サービス / HTTP / クライアント
// ============================================================================

use alloc::boxed::Box;

use super::parser::{HttpParseError, HttpParser};
use super::types::{
    ConnectionDirective, HttpHeader, HttpHeaderName, HttpHeaderValue, HttpInboundResponse,
    HttpRequest, HttpRequestTarget, HttpRequestUri,
};
use crate::net::l4::tcp::{EndpointAddr, TcpConnection};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::security::tls::{
    KeyUpdateAction, TlsClientConfig, TlsEstablishedSession, TlsHandshake, TlsHandshakeStep,
    TlsTrustAnchors,
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
            .map_err(|_| HttpClientError::TlsHandshakeFailed)?
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

async fn receive_plain_response(
    connection: &mut TcpConnection,
    parser: &mut HttpParser,
) -> Result<Option<HttpInboundResponse>, HttpClientError> {
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        let Some(in_payload) = connection.recv_payload().await else {
            return Ok(None);
        };

        parser
            .push_payload(in_payload)
            .map_err(HttpClientError::ParseError)?;
        if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
            return Ok(Some(response));
        }
    }
}

async fn receive_tls_response(
    tls: &mut TlsEstablishedSession,
    connection: &mut TcpConnection,
    parser: &mut HttpParser,
) -> Result<Option<HttpInboundResponse>, HttpClientError> {
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        let Some(in_payload) = connection.recv_payload().await else {
            return Ok(None);
        };

        let inbound = tls
            .process_incoming_payload(in_payload)
            .map_err(|_| HttpClientError::ReadError)?;

        if let KeyUpdateAction::Send(payload) = inbound.key_update {
            send_payload(connection, payload).await?;
        }

        let Some(application_data) = inbound.application_data else {
            continue;
        };
        parser
            .push_payload(application_data)
            .map_err(HttpClientError::ParseError)?;
        if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
            return Ok(Some(response));
        }
    }
}

async fn send_over_plain_transport(
    connection: &mut TcpConnection,
    request_payload: PacketPayload,
    parser: &mut HttpParser,
) -> Result<Option<HttpInboundResponse>, HttpClientError> {
    send_payload(connection, request_payload).await?;
    receive_plain_response(connection, parser).await
}

async fn send_over_tls_transport(
    host: &str,
    connection: &mut TcpConnection,
    request_payload: PacketPayload,
    parser: &mut HttpParser,
) -> Result<Option<HttpInboundResponse>, HttpClientError> {
    let trust_anchors =
        TlsTrustAnchors::system_roots().map_err(|_| HttpClientError::TlsHandshakeFailed)?;
    // RFC 7301: this client speaks only HTTP/1.1 over the protected stream.
    let tls_config = TlsClientConfig::for_server_name(host, trust_anchors)
        .and_then(|config| config.with_alpn(&["http/1.1"]))
        .map_err(|_| HttpClientError::TlsHandshakeFailed)?;
    let (handshake, client_hello) =
        TlsHandshake::start(tls_config).map_err(|_| HttpClientError::TlsHandshakeFailed)?;
    send_payload(connection, client_hello).await?;
    let mut tls = Box::new(complete_tls_handshake(handshake, connection).await?);

    let encrypted_request = tls
        .encrypt_payload(request_payload)
        .map_err(|_| HttpClientError::WriteError)?;
    send_payload(connection, encrypted_request).await?;

    let response = receive_tls_response(&mut tls, connection, parser).await;
    // RFC 8446 Section 6.1: announce the end of our writes before closing TCP.
    // The response is already decided, so a failed alert only skips the notice.
    if let Ok(close_notify) = tls.send_close_notify() {
        let _ = send_payload(connection, close_notify).await;
    }
    response
}

fn finalize_response_after_eof(
    parser: &mut HttpParser,
) -> Result<HttpInboundResponse, HttpClientError> {
    if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
        return Ok(response);
    }

    if let Some(response) = parser
        .try_parse_response_on_eof()
        .map_err(HttpClientError::ParseError)?
    {
        return Ok(response);
    }

    Err(HttpClientError::ParseError(
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
        let request_payload = req.into_payload().ok_or(HttpClientError::WriteError)?;
        let mut parser = HttpParser::new();

        let response = if is_https {
            send_over_tls_transport(&host, &mut connection, request_payload, &mut parser).await?
        } else {
            send_over_plain_transport(&mut connection, request_payload, &mut parser).await?
        };

        connection.close();
        match response {
            Some(response) => Ok(response),
            None => finalize_response_after_eof(&mut parser),
        }
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
}
