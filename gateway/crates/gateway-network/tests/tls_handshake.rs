//! TLS 端到端握手测试：自签名证书 + tokio-rustls 客户端。
//!
//! 验证 `TlsRuntime` 生成的 acceptor 能完成 TLS 1.3 握手并承载 HTTP/1.1
//! 请求，覆盖证书解析、SNI 默认证书选择与握手路径。

use std::io::BufReader;
use std::sync::Arc;

use gateway_network::tls::{certificate, load_from_pem, TlsRuntime};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

fn self_signed() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed certificate");
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

#[tokio::test]
async fn tls_handshake_and_http_request() {
    let (cert_pem, key_pem) = self_signed();
    let key = load_from_pem(&cert_pem, &key_pem).expect("parse certificate");

    let runtime = TlsRuntime::new(None).expect("create tls runtime");
    runtime
        .update(
            vec![certificate("test-cert", vec!["localhost".to_string()], key)],
            Some("test-cert"),
        )
        .expect("install certificate");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = runtime.acceptor();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(stream).await.expect("tls handshake");

        let mut request = vec![0u8; 2048];
        let n = tls.read(&mut request).await.expect("read request");
        assert!(
            request[..n].starts_with(b"GET / HTTP/1.1"),
            "unexpected request bytes: {:?}",
            &request[..n]
        );

        tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .expect("write response");
        tls.flush().await.expect("flush");
    });

    // 客户端信任自签名证书
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(cert_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert.expect("parse client trust cert")).expect("add trusted cert");
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let domain = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(domain, tcp).await.expect("tls connect");

    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");
    let mut response = vec![0u8; 256];
    let n = tls.read(&mut response).await.expect("read response");
    assert!(
        response[..n].starts_with(b"HTTP/1.1 200"),
        "unexpected response bytes: {:?}",
        &response[..n]
    );

    server.await.expect("server task");
}
