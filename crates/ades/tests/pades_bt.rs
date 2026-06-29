/// PAdES B-T roundtrip integration test.
#[cfg(feature = "tsp")]
#[test]
fn pades_bt_roundtrip() {
    use ades::{pades, signer::SoftSigner, tsp::TspClient};

    let pdf = include_bytes!("fixtures/sample.pdf");
    let signer = SoftSigner::generate(2048).expect("key generation failed");
    let tsa = TspClient::new(ades::tsp::client::FREETSA_URL);

    let signed = pades::sign_t(pdf, &signer, &tsa).expect("PAdES B-T signing failed");

    assert!(signed.starts_with(b"%PDF-"), "output must be a valid PDF");
    assert!(
        signed.len() > pdf.len(),
        "signed PDF must be larger than original"
    );

    let out = std::env::temp_dir().join("pades_bt_test.pdf");
    std::fs::write(&out, &signed).expect("write failed");
    println!("PAdES B-T: {} bytes → {}", signed.len(), out.display());
}
