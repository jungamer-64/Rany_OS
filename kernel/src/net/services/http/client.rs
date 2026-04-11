// ============================================================================
// kernel/src/net/services/http/client.rs
// ============================================================================

use alloc::boxed::Box;

use super::parser::{HttpParseError, HttpParser};
use super::types::{
    ConnectionDirective, HttpHeader, HttpHeaderName, HttpHeaderValue, HttpInboundResponse,
    HttpRequest, HttpRequestTarget, HttpRequestUri,
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

async fn recv_tls_handshake_payload(
    connection: &mut TcpConnection,
) -> Result<PacketPayload, HttpClientError> {
    connection
        .recv_payload()
        .await
        .ok_or(HttpClientError::TlsHandshakeFailed)
}

fn process_tls_handshake_payload(
    tls: &mut TlsConnection,
    in_payload: &PacketPayload,
) -> Result<(), HttpClientError> {
    let _ignored_app_data = tls
        .process_incoming_payload(in_payload)
        .map_err(|_| HttpClientError::TlsHandshakeFailed)?;
    Ok(())
}

async fn send_tls_handshake_followup(
    tls: &mut TlsConnection,
    connection: &mut TcpConnection,
    tls12_client_flight_sent: &mut bool,
) -> Result<(), HttpClientError> {
    match tls.state() {
        TlsState::Handshaking => {
            if !*tls12_client_flight_sent && !tls.is_tls13() {
                send_tls12_client_handshake_flight(tls, connection).await?;
                *tls12_client_flight_sent = true;
            }
        }
        TlsState::Tls13ServerFinishedReceived => {
            if let Ok(fin) = tls.build_client_finished_tls13_payload() {
                send_payload(connection, fin).await?;
            }
        }
        _ => {}
    }

    Ok(())
}

async fn complete_tls_handshake(
    tls: &mut TlsConnection,
    connection: &mut TcpConnection,
) -> Result<(), HttpClientError> {
    let mut tls12_client_flight_sent = false;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while tls.state() != TlsState::Established && tls.state() != TlsState::Error {
        let in_payload = recv_tls_handshake_payload(connection).await?;
        process_tls_handshake_payload(tls, &in_payload)?;
        send_tls_handshake_followup(tls, connection, &mut tls12_client_flight_sent).await?;
    }

    if tls.state() != TlsState::Established {
        return Err(HttpClientError::TlsHandshakeFailed);
    }

    Ok(())
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

        parser.push_payload(in_payload);
        if let Some(response) = parser.try_parse().map_err(HttpClientError::ParseError)? {
            return Ok(Some(response));
        }
    }
}

async fn receive_tls_response(
    tls: &mut TlsConnection,
    connection: &mut TcpConnection,
    parser: &mut HttpParser,
) -> Result<Option<HttpInboundResponse>, HttpClientError> {
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        let Some(in_payload) = connection.recv_payload().await else {
            return Ok(None);
        };

        let app_data = tls
            .process_incoming_payload(&in_payload)
            .map_err(|_| HttpClientError::ReadError)?;

        if let Some(resp) = tls.build_key_update_response_payload() {
            send_payload(connection, resp).await?;
        }

        if app_data.is_empty() {
            continue;
        }

        parser.push_payload(app_data);
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
    let tls_config = TlsConfig::default()
        .with_server_name(host)
        .map_err(|_| HttpClientError::TlsHandshakeFailed)?;
    let mut tls = Box::new(TlsConnection::new(tls_config));

    let client_hello = tls.build_client_hello_payload();
    send_payload(connection, client_hello).await?;
    complete_tls_handshake(&mut tls, connection).await?;

    let encrypted_request = tls
        .encrypt_application_payload(&request_payload)
        .map_err(|_| HttpClientError::WriteError)?;
    send_payload(connection, encrypted_request).await?;

    receive_tls_response(&mut tls, connection, parser).await
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

    async fn connect(host: &str, port: u16) -> Result<TcpConnection, HttpClientError> {
        let ip_addr = resolve_ipv4(host)
            .await
            .ok_or(HttpClientError::DnsResolutionFailed)?;
        let remote_addr = EndpointAddr::new(ip_addr.octets(), port);

        TcpConnection::dial_in(crate::net::runtime::default_runtime(), remote_addr)
            .await
            .map_err(|_| HttpClientError::ConnectionFailed)
    }

    /// リクエストを非同期で送信し、レスポンスを取得する
    pub async fn send(&self, req: HttpRequest) -> Result<HttpInboundResponse, HttpClientError> {
        let (req, host, port, is_https) = Self::prepare_request(req)?;
        let mut connection = Self::connect(&host, port).await?;
        let request_payload = req.into_payload().ok_or(HttpClientError::WriteError)?;
        let mut parser = HttpParser::new();

        let response = if is_https {
            send_over_tls_transport(&host, &mut connection, request_payload, &mut parser).await?
        } else {
            send_over_plain_transport(&mut connection, request_payload, &mut parser).await?
        };

        if let Some(response) = response {
            return Ok(response);
        }

        finalize_response_after_eof(&mut parser)
    }
}

#[cfg(test)]
mod tests {
    use super::HttpClient;
    use crate::net::services::http::types::{HttpHost, HttpPort, HttpRequestTarget, HttpScheme};

    #[test]
    fn split_request_uri_accepts_absolute() {
        let Some(host) = HttpHost::parse("example.com") else {
            panic!("valid host must be parsed");
        };
        let Some(port) = HttpPort::new(443) else {
            panic!("443 must be a valid HTTP port");
        };
        let Some(target) = HttpRequestTarget::parse("/v1/health") else {
            panic!("valid request target must be parsed");
        };

        let uri = crate::net::services::http::types::HttpRequestUri::absolute(
            HttpScheme::Https,
            host,
            port,
            target,
        );

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
