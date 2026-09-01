//! Real loopback-TCP adversarial tests for [`LoopbackHttpTransport`]'s
//! strict HTTP/1.1 response parser.
//!
//! Each test binds a real `TcpListener` on an ephemeral loopback port,
//! serves exactly one hand-crafted raw response over one accepted
//! connection, and asserts the transport rejects it with the specific typed
//! error — or, for the well-formed case, that it decodes cleanly. This
//! exercises the actual `TcpStream` parsing code, not a fake `Transport`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::num::NonZeroUsize;
use std::thread;
use std::time::{Duration, Instant};

use sunrise_edge_client::{LoopbackHttpTransport, Method, Transport, TransportError, WireRequest};

fn serve_once(response_bytes: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 4096];
            // Drain (at most) one read of the request; every request this
            // test issues fits in a single 4 KiB read.
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&response_bytes);
            let _ = stream.flush();
        }
    });
    addr
}

fn transport(addr: SocketAddr) -> LoopbackHttpTransport {
    LoopbackHttpTransport::new(
        addr,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(8 * 1024).unwrap(),
    )
    .unwrap()
}

fn get_request() -> WireRequest {
    WireRequest {
        method: Method::Get,
        path: "/v1/context".to_string(),
        content_type: None,
        body: Vec::new(),
        deadline: None,
    }
}

#[test]
fn accepts_a_well_formed_response() {
    let body = b"hello world";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.sunrise-edge.query-result\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body);

    let addr = serve_once(bytes);
    let response = transport(addr).send(&get_request()).unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(
        response.content_type.as_deref(),
        Some("application/vnd.sunrise-edge.query-result")
    );
    assert_eq!(response.body, body);
}

#[test]
fn rejects_a_duplicate_content_length() {
    let addr = serve_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
    );
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::DuplicateContentLength));
}

#[test]
fn rejects_a_missing_content_length() {
    let addr = serve_once(b"HTTP/1.1 200 OK\r\n\r\nhello".to_vec());
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::MissingContentLength));
}

#[test]
fn rejects_a_non_numeric_content_length() {
    let addr = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: five\r\n\r\nhello".to_vec());
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::InvalidContentLength));
}

#[test]
fn rejects_transfer_encoding() {
    let addr = serve_once(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
    );
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::TransferEncodingUnsupported));
}

#[test]
fn rejects_a_truncated_body() {
    // Declares a 10-byte body but the connection closes after 5.
    let addr = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello".to_vec());
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(
        error,
        TransportError::TruncatedResponseBody {
            expected: 10,
            received: 5,
        }
    ));
}

#[test]
fn rejects_trailing_bytes_beyond_the_declared_length() {
    // Declares a 5-byte body but sends 5 extra bytes before closing.
    let addr = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA".to_vec());
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::TrailingResponseBytes));
}

#[test]
fn rejects_a_body_exceeding_the_configured_maximum() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n");
            let _ = stream.flush();
        }
    });

    let bounded = LoopbackHttpTransport::new(
        addr,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(1024).unwrap(),
    )
    .unwrap();
    let error = bounded.send(&get_request()).unwrap_err();
    assert!(matches!(
        error,
        TransportError::ResponseBodyTooLarge {
            declared: 1_000_000,
            maximum: 1024,
        }
    ));
}

#[test]
fn rejects_an_unsupported_http_version() {
    let addr = serve_once(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::UnsupportedHttpVersion));
}

#[test]
fn rejects_a_header_terminator_beyond_the_configured_bound() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nX-Padding: {}\r\nContent-Length: 0\r\n\r\n",
        "x".repeat(256)
    );
    let addr = serve_once(response.into_bytes());
    let bounded = LoopbackHttpTransport::new(
        addr,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(64).unwrap(),
        NonZeroUsize::new(1024).unwrap(),
    )
    .unwrap();
    let error = bounded.send(&get_request()).unwrap_err();
    assert!(matches!(
        error,
        TransportError::ResponseHeaderTooLarge { maximum: 64 }
    ));
}

#[test]
fn rejects_whitespace_before_a_header_colon() {
    let addr = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n".to_vec());
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::MalformedHeaderLine));
}

#[test]
fn rejects_a_non_three_digit_status_code() {
    let addr = serve_once(b"HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
    let error = transport(addr).send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::InvalidStatusCode));
}

#[test]
fn rejects_duplicate_content_type_and_non_utf8_headers() {
    let duplicate = serve_once(
        b"HTTP/1.1 200 OK\r\nContent-Type: a/b\r\nContent-Type: a/b\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
    );
    let duplicate_error = transport(duplicate).send(&get_request()).unwrap_err();
    assert!(matches!(
        duplicate_error,
        TransportError::DuplicateContentType
    ));

    let invalid_utf8 =
        serve_once(b"HTTP/1.1 200 OK\r\nX-Invalid: \xff\r\nContent-Length: 0\r\n\r\n".to_vec());
    let utf8_error = transport(invalid_utf8).send(&get_request()).unwrap_err();
    assert!(matches!(utf8_error, TransportError::MalformedHeaders));
}

#[test]
fn rejects_a_connection_close_response_that_does_not_close() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
            thread::sleep(Duration::from_millis(200));
        }
    });
    let bounded = LoopbackHttpTransport::new(
        addr,
        Duration::from_secs(1),
        Duration::from_millis(40),
        Duration::from_secs(1),
        NonZeroUsize::new(1024).unwrap(),
        NonZeroUsize::new(1024).unwrap(),
    )
    .unwrap();
    let error = bounded.send(&get_request()).unwrap_err();
    assert!(matches!(error, TransportError::ResponseDidNotClose));
}

#[test]
fn caller_deadline_stops_a_slow_drip_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 4096];
            let _ = stream.read(&mut buf);
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
            for byte in response {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                let _ = stream.flush();
                thread::sleep(Duration::from_millis(20));
            }
        }
    });
    let bounded = transport(addr);
    let mut request = get_request();
    request.deadline = Some(Instant::now() + Duration::from_millis(100));
    let started = Instant::now();
    let error = bounded.send(&request).unwrap_err();
    assert!(matches!(error, TransportError::RequestDeadlineExceeded));
    assert!(started.elapsed() < Duration::from_secs(1));
}
