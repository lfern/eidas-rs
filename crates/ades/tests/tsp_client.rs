/// TSP client integration test — calls FreeTSA over the network.
///
/// Run with: `cargo test --features tsp -- tsp`
#[cfg(feature = "tsp")]
#[test]
fn tsp_timestamp_freetsa() {
    use ades::{tsp::TspClient, DigestAlgorithm};

    let client = TspClient::new(ades::tsp::client::FREETSA_URL);
    let hash = DigestAlgorithm::Sha256.hash(b"hello world");
    let token = client
        .timestamp(&hash, DigestAlgorithm::Sha256)
        .expect("TSP request to FreeTSA failed");

    // TimeStampToken is a DER SEQUENCE (ContentInfo)
    assert!(!token.is_empty(), "token must not be empty");
    assert_eq!(token[0], 0x30, "TimeStampToken must be a DER SEQUENCE");

    // Sanity: token is at least a few hundred bytes
    assert!(
        token.len() > 100,
        "token suspiciously small: {} bytes",
        token.len()
    );

    println!("TimeStampToken: {} bytes", token.len());
}
