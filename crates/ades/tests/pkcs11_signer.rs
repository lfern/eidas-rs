/// PKCS#11 integration test — requires SoftHSM2 + opensc.
///
/// # Setup (once per machine)
///
/// ```bash
/// softhsm2-util --init-token --free --label "ades-test" --pin 1234 --so-pin 5678
///
/// # RSA-2048 key + cert (label "ades-test", id 01)
/// openssl genrsa -out /tmp/test-key.pem 2048
/// openssl req -new -x509 -key /tmp/test-key.pem -out /tmp/test-cert.pem -days 3650 \
///   -subj "/CN=ades-test/O=eidas-rs/C=ES"
/// openssl x509 -in /tmp/test-cert.pem -outform DER -out /tmp/test-cert.der
/// pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
///   --write-object /tmp/test-key.pem --type privkey --label "ades-test" --id 01
/// pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
///   --write-object /tmp/test-cert.der --type cert --label "ades-test" --id 01
///
/// # P-256 (ECDSA) key + cert (label "ades-ec-test", id 02)
/// openssl ecparam -name prime256v1 -genkey -noout -out /tmp/ec-key.pem
/// openssl req -new -x509 -key /tmp/ec-key.pem -out /tmp/ec-cert.pem -days 3650 \
///   -subj "/CN=ades-ec-test/O=eidas-rs/C=ES"
/// openssl x509 -in /tmp/ec-cert.pem -outform DER -out /tmp/ec-cert.der
/// pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
///   --write-object /tmp/ec-key.pem --type privkey --label "ades-ec-test" --id 02
/// pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
///   --write-object /tmp/ec-cert.der --type cert --label "ades-ec-test" --id 02
/// ```
///
/// # Run
///
/// ```bash
/// cargo test --features "pkcs11,tsp" --test pkcs11_signer -- --ignored
/// ```
///
/// No se necesita `--test-threads=1`: los tests que tocan el token PKCS#11
/// se serializan internamente con `PKCS11_SERIAL`.
#[cfg(feature = "pkcs11")]
mod pkcs11_tests {
    use std::sync::{LazyLock, Mutex};

    use ades::{cades, pkcs11::Pkcs11Signer};

    const SOFTHSM2_LIB: &str = "/usr/lib/softhsm/libsofthsm2.so";
    const SLOT: u64 = 0;
    const PIN: &str = "1234";
    const LABEL: &str = "ades-test";
    const LABEL_EC: &str = "ades-ec-test";

    // C_Initialize no es reentrante: serializa todos los tests que abren el token.
    static PKCS11_SERIAL: LazyLock<Mutex<()>> = LazyLock::new(Mutex::default);

    #[test]
    #[ignore = "requires SoftHSM2 token (see module-level doc for setup)"]
    fn pkcs11_list_slots() {
        let _guard = PKCS11_SERIAL.lock().unwrap();
        let slots = Pkcs11Signer::list_slots(SOFTHSM2_LIB).expect("list_slots failed");
        assert!(!slots.is_empty(), "expected at least one slot with token");
        println!("slots with token: {slots:?}");
    }

    #[test]
    #[ignore = "requires SoftHSM2 token (see module-level doc for setup)"]
    fn pkcs11_signer_connect() {
        let _guard = PKCS11_SERIAL.lock().unwrap();
        let signer = Pkcs11Signer::new(SOFTHSM2_LIB, SLOT, PIN, Some(LABEL))
            .expect("Pkcs11Signer::new failed");

        use ades::signer::Signer as _;
        let cert = signer.certificate();
        println!(
            "certificate subject: {:?}",
            cert.inner().tbs_certificate.subject
        );
        assert!(
            !cert.to_der().is_empty(),
            "certificate DER must not be empty"
        );
    }

    #[test]
    #[ignore = "requires SoftHSM2 token (see module-level doc for setup)"]
    fn pkcs11_cades_bb() {
        let _guard = PKCS11_SERIAL.lock().unwrap();
        let signer = Pkcs11Signer::new(SOFTHSM2_LIB, SLOT, PIN, Some(LABEL))
            .expect("Pkcs11Signer::new failed");

        let data = b"hello from SoftHSM2 via Pkcs11Signer";
        let signed = cades::sign(data, &signer).expect("CAdES B-B signing failed");

        assert!(!signed.is_empty(), "signature must not be empty");
        assert_eq!(signed[0], 0x30, "CMS ContentInfo must be a DER SEQUENCE");

        let tmp = std::env::temp_dir();
        let sig_path = tmp.join("pkcs11_cades_bb.p7s");
        let orig_path = tmp.join("pkcs11_cades_bb_original.bin");
        std::fs::write(&sig_path, &signed).expect("write artifact failed");
        std::fs::write(&orig_path, data).expect("write original failed");

        println!(
            "CAdES B-B (PKCS#11): {} bytes → {}",
            signed.len(),
            sig_path.display()
        );
        println!(
            "validate: cargo run -p dss-client -- --no-trust cades {} {}",
            sig_path.display(),
            orig_path.display()
        );
    }

    #[cfg(feature = "tsp")]
    #[test]
    #[ignore = "requires SoftHSM2 token + network (FreeTSA) (see module-level doc for setup)"]
    fn pkcs11_cades_bt() {
        let _guard = PKCS11_SERIAL.lock().unwrap();
        let signer = Pkcs11Signer::new(SOFTHSM2_LIB, SLOT, PIN, Some(LABEL))
            .expect("Pkcs11Signer::new failed");
        let tsa = ades::tsp::TspClient::new(ades::tsp::client::FREETSA_URL);

        let data = b"hello from SoftHSM2 via PKCS#11 - nivel B-T";
        let signed = ades::cades::sign_t(data, &signer, &tsa).expect("CAdES B-T signing failed");

        assert!(!signed.is_empty());
        assert_eq!(signed[0], 0x30);

        let tmp = std::env::temp_dir();
        let sig_path = tmp.join("pkcs11_cades_bt.p7s");
        let orig_path = tmp.join("pkcs11_cades_bt_original.bin");
        std::fs::write(&sig_path, &signed).expect("write artifact failed");
        std::fs::write(&orig_path, data).expect("write original failed");

        println!(
            "CAdES B-T (PKCS#11): {} bytes → {}",
            signed.len(),
            sig_path.display()
        );
        println!(
            "validate: cargo run -p dss-client -- --no-trust cades {} {}",
            sig_path.display(),
            orig_path.display()
        );
    }

    #[test]
    #[ignore = "requires SoftHSM2 token with P-256 key (see module-level doc for setup)"]
    fn pkcs11_cades_bb_ecdsa() {
        let _guard = PKCS11_SERIAL.lock().unwrap();
        let signer = Pkcs11Signer::new(SOFTHSM2_LIB, SLOT, PIN, Some(LABEL_EC))
            .expect("Pkcs11Signer::new failed for EC key");

        let data = b"hello from SoftHSM2 via ECDSA P-256";
        let signed = cades::sign(data, &signer).expect("CAdES B-B ECDSA signing failed");

        assert!(!signed.is_empty(), "signature must not be empty");
        assert_eq!(signed[0], 0x30, "CMS ContentInfo must be a DER SEQUENCE");

        let tmp = std::env::temp_dir();
        let sig_path = tmp.join("pkcs11_cades_bb_ecdsa.p7s");
        let orig_path = tmp.join("pkcs11_cades_bb_ecdsa_original.bin");
        std::fs::write(&sig_path, &signed).expect("write artifact failed");
        std::fs::write(&orig_path, data).expect("write original failed");

        println!(
            "CAdES B-B (ECDSA P-256): {} bytes → {}",
            signed.len(),
            sig_path.display()
        );
        println!(
            "validate: cargo run -p dss-client -- --no-trust cades {} {}",
            sig_path.display(),
            orig_path.display()
        );
    }
}
