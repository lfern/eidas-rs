/// XAdES B-T test — generates a B-T signature and writes it to a temp file for DSS inspection.
///
/// Run: cargo test --features "cades,pades,soft,tsp,ocsp,xades" --test xades_bt -- --ignored
#[cfg(all(feature = "xades", feature = "tsp"))]
mod xades_bt_tests {
    use ades::{signer::SoftSigner, tsp::TspClient, xades};

    #[test]
    #[ignore]
    fn xades_bt_roundtrip() {
        let signer = SoftSigner::generate(2048).expect("key generation failed");
        let tsa = TspClient::new(ades::tsp::client::FREETSA_URL);
        let data = b"hello from xades B-T test";

        let xml_bytes = xades::sign_t(data, &signer, &tsa).expect("xades::sign_t failed");
        assert!(!xml_bytes.is_empty(), "XML must not be empty");

        let xml = std::str::from_utf8(&xml_bytes).expect("result must be valid UTF-8");
        assert!(xml.starts_with("<?xml"), "must start with XML declaration");
        assert!(xml.contains("<ds:Signature"), "must contain ds:Signature");
        assert!(
            xml.contains("<xades:SignatureTimeStamp"),
            "must contain xades:SignatureTimeStamp"
        );
        assert!(
            xml.contains("<xades:EncapsulatedTimeStamp"),
            "must contain xades:EncapsulatedTimeStamp"
        );
        assert!(
            xml.contains("<xades:UnsignedProperties"),
            "must contain xades:UnsignedProperties"
        );

        let tmp = std::env::temp_dir();
        let path = tmp.join("xades_bt_test.xml");
        std::fs::write(&path, &xml_bytes).expect("write artifact failed");

        println!("XAdES B-T: {} bytes → {}", xml_bytes.len(), path.display());
        println!("validate: cargo run -p dss-client -- --no-trust sign-xades-t");
    }
}
