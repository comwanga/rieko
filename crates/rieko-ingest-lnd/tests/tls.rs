use std::sync::Arc;

use rieko_domain::NodeId;
use rieko_ingest_lnd::LndClient;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed identity for `localhost`.
fn cert_for_host() -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::DnsName("localhost".parse().unwrap())];
    let kp = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&kp).unwrap();
    (cert, kp)
}

/// Run a TLS server on a dedicated thread (so its runtime stays alive) and
/// return the port once it is listening. Serves one connection, answering
/// `GET /v1/channels` with `body`.
fn spawn_tls_server(cert: &rcgen::Certificate, key: &rcgen::KeyPair, body: String) -> u16 {
    install_provider();
    let certs = vec![cert.der().clone()];
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            certs,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let (tx, rx) = std::sync::mpsc::sync_channel::<u16>(1);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tx.send(port).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _n = tls.read(&mut buf).await.unwrap();
            let response =
                format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{body}");
            tls.write_all(response.as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
        });
    });
    rx.recv().unwrap()
}

fn channel_json() -> String {
    r#"{"channels":[]}"#.to_string()
}

#[test]
fn untrusted_self_signed_server_is_rejected() {
    let (cert, key) = cert_for_host();
    let port = spawn_tls_server(&cert, &key, channel_json());
    let client = LndClient::new(format!("https://localhost:{port}"), None, None).unwrap();
    let err = client.channels(&NodeId::new("local")).unwrap_err();
    assert!(
        matches!(err, rieko_ingest_lnd::LndClientError::Transport(_)),
        "self-signed without trust must fail TLS verification, got {err:?}"
    );
}

#[test]
fn exact_cert_configured_is_accepted() {
    let (cert, key) = cert_for_host();
    let port = spawn_tls_server(&cert, &key, channel_json());
    let client = LndClient::new(
        format!("https://localhost:{port}"),
        None,
        Some(cert.pem().into_bytes()),
    )
    .unwrap();
    let channels = client.channels(&NodeId::new("local")).unwrap();
    assert!(channels.is_empty());
}

#[test]
fn wrong_certificate_is_rejected() {
    let (cert, key) = cert_for_host();
    let (other, _) = cert_for_host();
    let port = spawn_tls_server(&cert, &key, channel_json());
    let client = LndClient::new(
        format!("https://localhost:{port}"),
        None,
        Some(other.pem().into_bytes()),
    )
    .unwrap();
    let err = client.channels(&NodeId::new("local")).unwrap_err();
    assert!(
        matches!(err, rieko_ingest_lnd::LndClientError::Transport(_)),
        "trusting a different cert must still fail verification, got {err:?}"
    );
}

#[test]
fn garbage_cert_bytes_produce_clear_error() {
    let bad_pem = b"this is definitely not a certificate in any format";
    let result = LndClient::new("https://localhost:8080", None, Some(bad_pem.to_vec()));
    let err = match result {
        Ok(_) => panic!("garbage cert should not build a client"),
        Err(e) => e,
    };
    assert!(
        matches!(err, rieko_ingest_lnd::LndClientError::Tls(_)),
        "garbage cert bytes should produce a clear TLS error"
    );
}
