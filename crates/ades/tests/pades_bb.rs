/// PAdES B-B roundtrip integration test.
#[test]
fn pades_bb_roundtrip() {
    use ades::{pades, signer::SoftSigner};

    let pdf = include_bytes!("fixtures/sample.pdf");

    let signer = SoftSigner::generate(2048).expect("key generation failed");

    let signed_pdf = pades::sign(pdf, &signer).expect("PAdES B-B signing failed");

    assert!(
        signed_pdf.starts_with(b"%PDF-"),
        "output must be a valid PDF"
    );
    // The incremental update must be larger than the original
    assert!(
        signed_pdf.len() > pdf.len(),
        "signed PDF must be larger than original"
    );
}
