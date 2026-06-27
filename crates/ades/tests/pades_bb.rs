/// PAdES B-B roundtrip integration test.
///
/// This test is ignored until M2 is implemented.
/// Run with: `cargo test -- --ignored`
#[test]
#[ignore = "M2: PAdES B-B not yet implemented"]
fn pades_bb_roundtrip() {
    use ades::{pades, signer::SoftSigner};

    // 1. Use a minimal valid PDF as input (place a real PDF at tests/fixtures/sample.pdf)
    let pdf = std::fs::read("tests/fixtures/sample.pdf")
        .expect("place a PDF at tests/fixtures/sample.pdf");
    let pdf = pdf.as_slice();

    // 2. Generate RSA 2048 key pair in memory
    let signer = SoftSigner::generate(2048).expect("key generation failed");

    // 3. Sign as PAdES B-B
    let signed_pdf = pades::sign(pdf, &signer).expect("PAdES B-B signing failed");

    // 4. Basic structural check: must be a valid PDF
    assert!(
        signed_pdf.starts_with(b"%PDF-"),
        "output must be a valid PDF"
    );

    // 5. TODO (M2): submit to DSS validator and assert acceptance
    //    See: https://dss.nowina.lu/validation
}
