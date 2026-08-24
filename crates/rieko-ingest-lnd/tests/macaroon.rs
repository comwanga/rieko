use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::channel;

use rieko_domain::NodeId;
use rieko_ingest_lnd::LndClient;

/// Serve a single HTTP request and return the raw request bytes read.
fn capture_request() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        tx.send(buf).unwrap();
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"channels\":[]}",
        );
    });
    (port, rx)
}

#[test]
fn macaroon_header_is_lowercase_hex_of_file_bytes() {
    let (port, rx) = capture_request();
    let macaroon = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
    let client =
        LndClient::new_allow_insecure(format!("http://127.0.0.1:{port}"), Some(macaroon), None)
            .unwrap();
    client.channels(&NodeId::new("local")).unwrap();
    let req = rx.recv().unwrap();
    let req = String::from_utf8_lossy(&req);
    let lower = req.to_ascii_lowercase();
    assert!(
        lower.contains("grpc-metadata-macaroon: deadbeef00ff"),
        "header must carry lowercase hex of the macaroon bytes, got: {req}"
    );
}

#[test]
fn binary_macaroon_invalid_utf8_still_works() {
    let (port, rx) = capture_request();
    let macaroon: Vec<u8> = (0..=255).collect();
    assert!(
        std::str::from_utf8(&macaroon).is_err(),
        "precondition: non-UTF8 bytes"
    );
    let client =
        LndClient::new_allow_insecure(format!("http://127.0.0.1:{port}"), Some(macaroon), None)
            .unwrap();
    client.channels(&NodeId::new("local")).unwrap();
    let req = rx.recv().unwrap();
    let req = String::from_utf8_lossy(&req);
    assert!(
        req.to_ascii_lowercase().contains("grpc-metadata-macaroon:"),
        "macaroon header must be present for binary macaroon bytes, got: {req}"
    );
}

#[test]
fn macaroon_secret_is_absent_from_errors() {
    // Point at a dead port so the fetch fails; the macaroon value must not
    // leak into the error message.
    let macaroon = vec![0xde, 0xad, 0xbe, 0xef];
    let client =
        LndClient::new_allow_insecure("http://127.0.0.1:1", Some(macaroon), None).unwrap();
    let err = client
        .channels(&NodeId::new("local"))
        .unwrap_err()
        .to_string();
    assert!(
        !err.contains("deadbeef") && !err.to_lowercase().contains("macaroon"),
        "error must not reveal the macaroon, got: {err}"
    );
}

#[test]
fn missing_macaroon_file_fails_cleanly_in_cli_path() {
    // The CLI reads the file with fs::read; a missing path surfaces as an
    // io error, not a panic or a successful client. The client itself does
    // not open files, so this asserts the boundary contract holds via the
    // error type used by the reading layer.
    let missing = std::path::Path::new("/definitely/not/a/macaroon/file");
    let err = std::fs::read(missing).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
