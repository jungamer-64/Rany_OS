use super::{HttpParseError, HttpParser};
use crate::net::payload::payload_from_bytes;
use alloc::vec;

#[test]
fn chunked_response_with_trailer_is_parsed() {
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n";

    let mut parser = HttpParser::new();
    parser.push_payload(payload_from_bytes(response).expect("test payload must be allocated"));

    let parsed = parser
        .try_parse()
        .expect("parse should not fail")
        .expect("response should be complete");
    let body = parsed.body.expect("chunked response must have body");
    let mut body_bytes = vec![0u8; body.total_len()];
    assert_eq!(body.copy_into(&mut body_bytes), body_bytes.len());
    assert_eq!(body_bytes, b"Wikipedia");
}

#[test]
fn chunked_trailer_waits_for_final_crlf() {
    let mut parser = HttpParser::new();

    let first =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-Test: 1\r\n";
    parser.push_payload(payload_from_bytes(first).expect("test payload must be allocated"));
    assert!(parser.try_parse().expect("parse should not fail").is_none());

    let second = b"\r\n";
    parser.push_payload(payload_from_bytes(second).expect("test payload must be allocated"));

    let parsed = parser
        .try_parse()
        .expect("parse should not fail")
        .expect("response should be complete");
    let body = parsed.body.expect("chunked response must have body");
    let mut body_bytes = vec![0u8; body.total_len()];
    assert_eq!(body.copy_into(&mut body_bytes), body_bytes.len());
    assert_eq!(body_bytes, b"a");
}

#[test]
fn response_without_length_or_chunked_has_no_body() {
    let response = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";

    let mut parser = HttpParser::new();
    parser.push_payload(payload_from_bytes(response).expect("test payload must be allocated"));

    let parsed = parser
        .try_parse()
        .expect("parse should not fail")
        .expect("response should be complete");
    assert!(parsed.body.is_none());
}

#[test]
fn request_with_unsupported_method_is_rejected() {
    let request = b"TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let mut parser = HttpParser::new();
    parser.push_payload(payload_from_bytes(request).expect("test payload must be allocated"));

    let err = parser
        .try_parse_request()
        .expect_err("unsupported method must be rejected");
    assert!(matches!(err, HttpParseError::InvalidFormat));
}

#[test]
fn request_with_content_length_and_chunked_is_rejected() {
    let request = b"POST /upload HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

    let mut parser = HttpParser::new();
    parser.push_payload(payload_from_bytes(request).expect("test payload must be allocated"));

    let err = parser
        .try_parse_request()
        .expect_err("conflicting content-length and chunked must be rejected");
    assert!(matches!(err, HttpParseError::InvalidFormat));
}

#[test]
fn request_waits_until_full_headers_arrive() {
    let mut parser = HttpParser::new();

    let first = b"GET / HTTP/1.1\r\nHost: examp";
    parser.push_payload(payload_from_bytes(first).expect("test payload must be allocated"));
    assert!(
        parser
            .try_parse_request()
            .expect("parse should not fail")
            .is_none()
    );

    let second = b"le.com\r\n\r\n";
    parser.push_payload(payload_from_bytes(second).expect("test payload must be allocated"));

    let parsed = parser
        .try_parse_request()
        .expect("parse should not fail")
        .expect("request should be complete");
    assert!(parsed.uri.eq_bytes(b"/"));
}
