/// OCSP client integration test.
///
/// Downloads the certificate chain from google.com via TLS and checks
/// revocation status of the leaf cert against its OCSP responder.
///
/// Run with: `cargo test --features ocsp -- ocsp`
#[cfg(feature = "ocsp")]
#[test]
fn ocsp_check_google_cert() {
    use ades::{ocsp::OcspClient, Certificate};

    // Fetch the Google leaf cert and its issuer via TLS handshake.
    // ureq exposes the peer certificate chain when the request succeeds.
    // We use rustls-native-certs-backed ureq to get the real chain.
    let (leaf_der, issuer_der) = fetch_cert_chain("www.google.com", 443)
        .expect("failed to fetch certificate chain from www.google.com");

    let cert = Certificate::from_der(&leaf_der).expect("leaf cert parse failed");
    let issuer = Certificate::from_der(&issuer_der).expect("issuer cert parse failed");

    println!("Leaf:   {}", cert.inner().tbs_certificate.subject);
    println!("Issuer: {}", issuer.inner().tbs_certificate.subject);

    let client = OcspClient::new();
    let status = client.check(&cert, &issuer).expect("OCSP check failed");

    println!("OCSP status: {status:?}");
    assert_eq!(
        status,
        ades::ocsp::OcspStatus::Good,
        "Google cert should be Good"
    );
}

/// Fetches the TLS certificate chain from `host:port` using a raw TLS handshake.
/// Returns `(leaf_der, issuer_der)`.
#[cfg(feature = "ocsp")]
fn fetch_cert_chain(host: &str, port: u16) -> Result<(Vec<u8>, Vec<u8>), String> {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        sync::Arc,
    };

    // We use rustls directly since ureq doesn't expose the peer cert chain.
    // Multiple rustls crypto providers may be linked (ureq brings aws-lc-rs, we add ring).
    // Install one explicitly to avoid the ambiguity panic.
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default(); // ignore error if already installed

    let mut root_store = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        root_store.add(cert).map_err(|e| format!("add cert: {e}"))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = host
        .to_owned()
        .try_into()
        .map_err(|e: rustls::pki_types::InvalidDnsNameError| e.to_string())?;
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;

    let mut tcp = TcpStream::connect(format!("{host}:{port}")).map_err(|e| e.to_string())?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    // Send a minimal HTTP request to force the handshake
    tls.write_all(b"GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut _buf = vec![0u8; 1024];
    let _ = tls.read(&mut _buf);

    let certs: Vec<Vec<u8>> = conn
        .peer_certificates()
        .ok_or("no peer certificates")?
        .iter()
        .map(|c| c.to_vec())
        .collect();

    if certs.len() < 2 {
        return Err(format!(
            "expected at least 2 certs in chain, got {}",
            certs.len()
        ));
    }

    Ok((certs[0].clone(), certs[1].clone()))
}
