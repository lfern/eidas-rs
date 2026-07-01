/// XAdES B-B test — generates a signature and writes it to a temp file for DSS inspection.
///
/// Run: cargo test --features "cades,pades,soft,tsp,ocsp,xades" --test xades_bb
#[cfg(feature = "xades")]
mod xades_bb_tests {
    use ades::{signer::SoftSigner, xades};

    #[test]
    fn xades_bb_roundtrip() {
        let signer = SoftSigner::generate(2048).expect("key generation failed");
        let data = b"hello from xades B-B test";

        let xml_bytes = xades::sign(data, &signer).expect("xades::sign failed");
        assert!(!xml_bytes.is_empty(), "XML must not be empty");

        let xml = std::str::from_utf8(&xml_bytes).expect("result must be valid UTF-8");
        assert!(xml.starts_with("<?xml"), "must start with XML declaration");
        assert!(xml.contains("<ds:Signature"), "must contain ds:Signature");
        assert!(
            xml.contains("<xades:SigningCertificateV2"),
            "must contain SigningCertificateV2"
        );

        let tmp = std::env::temp_dir();
        let path = tmp.join("xades_bb_test.xml");
        std::fs::write(&path, &xml_bytes).expect("write artifact failed");

        println!("XAdES B-B: {} bytes → {}", xml_bytes.len(), path.display());
        println!("validate: cargo run -p dss-client -- --no-trust sign-xades-bb");
    }
}
