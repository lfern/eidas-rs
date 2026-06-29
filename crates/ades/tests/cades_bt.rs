/// CAdES B-T integration test — signs, timestamps via FreeTSA, validates with DSS.
#[cfg(all(feature = "tsp"))]
#[test]
fn cades_bt_roundtrip() {
    use ades::{cades, signer::SoftSigner, tsp::TspClient};

    let signer = SoftSigner::generate(2048).expect("key gen failed");
    let tsa = TspClient::new(ades::tsp::client::FREETSA_URL);

    let data = b"hello world cades-t";
    let signed = cades::sign_t(data, &signer, &tsa).expect("CAdES B-T signing failed");

    assert!(!signed.is_empty());
    assert_eq!(signed[0], 0x30, "must be DER SEQUENCE");

    // Write to disk so dss-client can pick it up
    std::fs::write("cades_bt_test.p7s", &signed).expect("write failed");
    std::fs::write("cades_bt_original.txt", data).expect("write failed");

    println!("CAdES B-T: {} bytes → cades_bt_test.p7s", signed.len());
}
