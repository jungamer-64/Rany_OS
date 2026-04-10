// ============================================================================
// kernel/src/net/services/http/types.rs
// ============================================================================

mod header;
mod message;
mod primitives;
mod uri;

pub use header::{HttpHeader, HttpHeaderName, HttpHeaderValue, HttpHeaderView};
pub use message::{HttpInboundRequest, HttpInboundResponse, HttpRequest, HttpResponse};
pub use primitives::{
    ConnectionDirective, HttpMethod, HttpPort, HttpScheme, HttpStatusCode, HttpVersion,
};
pub use uri::{HttpHost, HttpRequestTarget, HttpRequestUri};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::payload::{PayloadSpan, payload_from_bytes};

    fn parse_span_method(method: &str) -> Option<HttpMethod> {
        let payload =
            payload_from_bytes(method.as_bytes()).expect("method test payload must be allocated");
        let span = PayloadSpan::from_payload(payload);
        HttpMethod::parse_span(&span)
    }

    #[test]
    fn absolute_uri_parses_and_preserves_target() {
        let uri = HttpRequestUri::parse("https://example.com:8443/path?q=1")
            .expect("absolute URI should parse");

        let (scheme, host, port, target) = uri.as_absolute().expect("absolute form expected");
        assert!(scheme.is_https());
        assert_eq!(host.as_str(), "example.com");
        assert_eq!(port.as_u16(), 8443);
        assert_eq!(target.as_str(), "/path?q=1");
        assert_eq!(uri.as_request_target().as_str(), "/path?q=1");
    }

    #[test]
    fn uri_rejects_invalid_host() {
        assert!(HttpRequestUri::parse("http://exa mple.com/").is_none());
        assert!(HttpRequestUri::parse("http:///path").is_none());
    }

    #[test]
    fn status_code_is_validated() {
        assert!(HttpStatusCode::new(99).is_none());
        assert!(HttpStatusCode::new(600).is_none());

        let ok = HttpStatusCode::new(200).expect("200 must be valid");
        assert_eq!(ok.as_u16(), 200);
        assert_eq!(ok.reason_phrase(), "OK");
    }

    #[test]
    fn header_name_and_value_are_validated() {
        assert!(HttpHeader::try_new("Content-Length", "10").is_some());
        assert!(HttpHeader::try_new("X-Custom", "abc").is_some());

        assert!(HttpHeader::try_new("Bad Header", "10").is_none());
        assert!(HttpHeader::try_new("X-Test", "bad\r\nvalue").is_none());
    }

    #[test]
    fn request_header_lookup_matches_custom_name_case_insensitively() {
        let request = HttpRequest::get("/echo")
            .expect("request should be constructed")
            .header("x-custom-header", "abc")
            .expect("custom header should be accepted");

        let value = request
            .get_header(HttpHeaderName::Custom("X-CUSTOM-HEADER".into()))
            .map(HttpHeaderValue::as_str);
        assert_eq!(value, Some("abc"));
    }

    #[test]
    fn method_parse_span_supports_core_seven_methods() {
        assert_eq!(parse_span_method("GET"), Some(HttpMethod::Get));
        assert_eq!(parse_span_method("POST"), Some(HttpMethod::Post));
        assert_eq!(parse_span_method("PUT"), Some(HttpMethod::Put));
        assert_eq!(parse_span_method("DELETE"), Some(HttpMethod::Delete));
        assert_eq!(parse_span_method("HEAD"), Some(HttpMethod::Head));
        assert_eq!(parse_span_method("OPTIONS"), Some(HttpMethod::Options));
        assert_eq!(parse_span_method("PATCH"), Some(HttpMethod::Patch));
    }

    #[test]
    fn method_parse_span_rejects_trace_and_connect() {
        assert_eq!(parse_span_method("TRACE"), None);
        assert_eq!(parse_span_method("CONNECT"), None);
    }
}
