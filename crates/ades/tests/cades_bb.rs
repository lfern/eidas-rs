/// CAdES B-B roundtrip integration test.
#[test]
fn cades_bb_roundtrip() {
    use ades::{cades, signer::SoftSigner};

    // 1. Generate RSA 2048 key pair in memory
    let signer = SoftSigner::generate(2048).expect("key generation failed");

    // 2. Sign b"hello world" as CAdES B-B
    let data = b"hello world";
    let signed = cades::sign(data, &signer).expect("CAdES B-B signing failed");

    // 3. Basic structural check: must start with a DER SEQUENCE tag (0x30)
    assert!(!signed.is_empty(), "signature must not be empty");
    assert_eq!(signed[0], 0x30, "CMS ContentInfo must be a DER SEQUENCE");

    // 4. TODO (M1): verify CMS structure:
    //    - ContentType = id-signedData
    //    - DigestAlgorithm = SHA-256
    //    - SignedAttrs includes id-contentType and id-signingTime
    //    - SignatureValue verifies against the signer's public key

    // 5. TODO (M1): submit to DSS validator and assert acceptance
    //    See: https://dss.nowina.lu/validation
}
