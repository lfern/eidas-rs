use std::sync::Mutex;

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};

use crate::{certificate::Certificate, digest::DigestAlgorithm, error::AdesError};

/// Algorithm family of the private key on the token.
#[cfg(feature = "pkcs11")]
enum Pkcs11KeyType {
    Rsa,
    Ec,
}

/// PKCS#11 signing backend — delegates signing to a hardware token or HSM.
///
/// Supports RSA (PKCS#1 v1.5 via `CKM_RSA_PKCS`) and EC (ECDSA via
/// `CKM_ECDSA`). The key type is detected automatically at connection time
/// by reading the `CKA_KEY_TYPE` attribute of the private key object.
///
/// The private key never leaves the device: `sign_digest` sends only the
/// pre-computed hash, and the token returns the raw signature bytes.
///
/// # Example
///
/// ```no_run
/// use ades::pkcs11::Pkcs11Signer;
///
/// let signer = Pkcs11Signer::new(
///     "/usr/lib/softhsm/libsofthsm2.so",
///     0,
///     "1234",
///     Some("my-key"),
/// ).unwrap();
/// ```
#[cfg(feature = "pkcs11")]
pub struct Pkcs11Signer {
    // Kept alive so C_Finalize is called AFTER C_CloseSession (Rust drops fields top-to-bottom).
    // Without this, C_Finalize would fire at the end of `new()` while the session is still open,
    // violating the PKCS#11 spec.
    _pkcs11: Pkcs11,
    session: Mutex<Session>,
    key_handle: ObjectHandle,
    certificate: Certificate,
    digest: DigestAlgorithm,
    key_type: Pkcs11KeyType,
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Signer {
    /// Connects to a PKCS#11 token and prepares a signing session.
    ///
    /// - `lib_path`: path to the PKCS#11 shared library (`.so` / `.dll`).
    /// - `slot`: slot index as reported by `pkcs11-tool --list-slots`.
    /// - `pin`: user PIN for the token.
    /// - `label`: optional key/certificate label; if `None`, the first found is used.
    ///
    /// # Errors
    ///
    /// Returns [`AdesError::Pkcs11`] if the library cannot be loaded, the slot
    /// does not exist, the PIN is wrong, no key/certificate is found, or the
    /// key type is not RSA or EC.
    pub fn new(
        lib_path: impl AsRef<std::path::Path>,
        slot: u64,
        pin: &str,
        label: Option<&str>,
    ) -> Result<Self, AdesError> {
        // 1. Load and initialise the PKCS#11 library
        let pkcs11 = Pkcs11::new(lib_path).map_err(pkcs11_err)?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(pkcs11_err)?;

        // 2. Resolve the slot
        let slots = pkcs11.get_slots_with_token().map_err(pkcs11_err)?;
        let slot = slots
            .into_iter()
            .nth(slot as usize)
            .ok_or_else(|| AdesError::Pkcs11(format!("slot {slot} not found")))?;

        // 3. Open an R/W session
        let session = pkcs11.open_rw_session(slot).map_err(pkcs11_err)?;

        // 4. Login with user PIN
        let auth_pin = AuthPin::new(pin.to_owned());
        session
            .login(UserType::User, Some(&auth_pin))
            .map_err(pkcs11_err)?;

        // 5. Find private key handle and detect its type
        let key_handle = find_object(&session, ObjectClass::PRIVATE_KEY, label)?;
        let key_type = detect_key_type(&session, key_handle)?;

        // 6. Find matching certificate and read its DER value
        let cert_handle = find_object(&session, ObjectClass::CERTIFICATE, label)?;
        let attrs = session
            .get_attributes(cert_handle, &[AttributeType::Value])
            .map_err(pkcs11_err)?;
        let cert_der = attrs
            .into_iter()
            .find_map(|a| {
                if let Attribute::Value(v) = a {
                    Some(v)
                } else {
                    None
                }
            })
            .ok_or_else(|| AdesError::Pkcs11("certificate object has no DER value".to_owned()))?;

        let certificate = Certificate::from_der(&cert_der)?;

        Ok(Self {
            _pkcs11: pkcs11,
            session: Mutex::new(session),
            key_handle,
            certificate,
            digest: DigestAlgorithm::Sha256,
            key_type,
        })
    }

    /// Returns the list of slot indices that have a token present.
    ///
    /// Useful for discovering which slot to pass to [`Pkcs11Signer::new`].
    ///
    /// # Errors
    ///
    /// Returns [`AdesError::Pkcs11`] if the library cannot be loaded.
    pub fn list_slots(lib_path: impl AsRef<std::path::Path>) -> Result<Vec<u64>, AdesError> {
        let pkcs11 = Pkcs11::new(lib_path).map_err(pkcs11_err)?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(pkcs11_err)?;
        let slots = pkcs11.get_slots_with_token().map_err(pkcs11_err)?;
        Ok(slots
            .into_iter()
            .enumerate()
            .map(|(i, _)| i as u64)
            .collect())
    }
}

#[cfg(feature = "pkcs11")]
impl crate::signer::Signer for Pkcs11Signer {
    type Error = AdesError;

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let session = self
            .session
            .lock()
            .map_err(|_| AdesError::Pkcs11("session mutex poisoned".to_owned()))?;
        match self.key_type {
            // RSA PKCS#1 v1.5: C_Sign expects a DigestInfo-wrapped hash
            Pkcs11KeyType::Rsa => {
                let digest_info = build_digest_info(digest, self.digest)?;
                session
                    .sign(&Mechanism::RsaPkcs, self.key_handle, &digest_info)
                    .map_err(pkcs11_err)
            }
            // ECDSA: C_Sign expects the raw hash, returns raw r||s (fixed-size per curve).
            // CMS requires DER SEQUENCE { INTEGER r, INTEGER s } (X9.62 / RFC 3279).
            Pkcs11KeyType::Ec => {
                let raw = session
                    .sign(&Mechanism::Ecdsa, self.key_handle, digest)
                    .map_err(pkcs11_err)?;
                ec_raw_sig_to_der(&raw)
            }
        }
    }

    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pkcs11_err(e: impl std::fmt::Display) -> AdesError {
    AdesError::Pkcs11(e.to_string())
}

fn find_object(
    session: &Session,
    class: ObjectClass,
    label: Option<&str>,
) -> Result<ObjectHandle, AdesError> {
    let mut template = vec![Attribute::Class(class)];
    if let Some(lbl) = label {
        template.push(Attribute::Label(lbl.as_bytes().to_vec()));
    }
    session
        .find_objects(&template)
        .map_err(pkcs11_err)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            AdesError::Pkcs11(format!(
                "no {class:?} object found on token{}",
                label
                    .map(|l| format!(" with label '{l}'"))
                    .unwrap_or_default()
            ))
        })
}

fn detect_key_type(
    session: &Session,
    key_handle: ObjectHandle,
) -> Result<Pkcs11KeyType, AdesError> {
    let attrs = session
        .get_attributes(key_handle, &[AttributeType::KeyType])
        .map_err(pkcs11_err)?;
    let kt = attrs
        .into_iter()
        .find_map(|a| {
            if let Attribute::KeyType(kt) = a {
                Some(kt)
            } else {
                None
            }
        })
        .ok_or_else(|| AdesError::Pkcs11("could not read CKA_KEY_TYPE attribute".to_owned()))?;

    if kt == KeyType::RSA {
        Ok(Pkcs11KeyType::Rsa)
    } else if kt == KeyType::EC {
        Ok(Pkcs11KeyType::Ec)
    } else {
        Err(AdesError::Pkcs11(format!(
            "unsupported key type {kt:?} — only RSA and EC are supported"
        )))
    }
}

/// Converts a raw PKCS#11 ECDSA signature (`r || s`) to DER format.
///
/// `CKM_ECDSA` returns `r` and `s` as fixed-size unsigned big-endian integers
/// concatenated without any framing. CMS (RFC 3279 §2.2.3) requires:
/// ```text
/// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
/// ```
fn ec_raw_sig_to_der(raw: &[u8]) -> Result<Vec<u8>, AdesError> {
    if !raw.len().is_multiple_of(2) {
        return Err(AdesError::Pkcs11(format!(
            "ECDSA raw signature length {} is not even",
            raw.len()
        )));
    }
    let coord = raw.len() / 2;
    Ok(der_sequence(&[
        &der_integer(&raw[..coord]),
        &der_integer(&raw[coord..]),
    ]))
}

/// Encodes a DER INTEGER from a big-endian unsigned byte slice.
/// Strips leading zeros and prepends 0x00 if the high bit is set.
fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => &[0],
    };
    let mut value = if trimmed[0] & 0x80 != 0 {
        let mut v = vec![0x00];
        v.extend_from_slice(trimmed);
        v
    } else {
        trimmed.to_vec()
    };
    let mut out = vec![0x02]; // INTEGER tag
    der_push_length(&mut out, value.len());
    out.append(&mut value);
    out
}

/// Encodes a DER SEQUENCE wrapping the concatenation of `items`.
fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|s| s.iter().copied()).collect();
    let mut out = vec![0x30]; // SEQUENCE tag
    der_push_length(&mut out, payload.len());
    out.extend_from_slice(&payload);
    out
}

fn der_push_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

/// Wraps a pre-computed hash in a PKCS#1 DigestInfo structure.
///
/// `CKM_RSA_PKCS` requires the input to be DER-encoded as:
/// ```text
/// DigestInfo ::= SEQUENCE {
///   digestAlgorithm  AlgorithmIdentifier,
///   digest           OCTET STRING
/// }
/// ```
fn build_digest_info(digest: &[u8], algo: DigestAlgorithm) -> Result<Vec<u8>, AdesError> {
    // Standard DER-encoded DigestInfo headers (AlgorithmIdentifier + OCTET STRING header).
    // These prefixes are constant for each algorithm and well-specified in RFC 8017 §9.2.
    let prefix: &[u8] = match algo {
        DigestAlgorithm::Sha256 => &[
            0x30, 0x31, // SEQUENCE (49 bytes total)
            0x30, 0x0d, // AlgorithmIdentifier SEQUENCE (13 bytes)
            0x06, 0x09, // OID (9 bytes)
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // id-sha256
            0x05, 0x00, // NULL parameters
            0x04, 0x20, // OCTET STRING (32 bytes)
        ],
        DigestAlgorithm::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, // id-sha384
            0x05, 0x00, 0x04, 0x30, // 48 bytes
        ],
        DigestAlgorithm::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, // id-sha512
            0x05, 0x00, 0x04, 0x40, // 64 bytes
        ],
    };
    let mut out = prefix.to_vec();
    out.extend_from_slice(digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_info_sha256_length() {
        let hash = [0u8; 32];
        let di = build_digest_info(&hash, DigestAlgorithm::Sha256).unwrap();
        // DigestInfo DER: prefix (19 bytes) + 32-byte hash = 51 bytes total
        assert_eq!(di.len(), 51);
        assert_eq!(di[0], 0x30); // SEQUENCE tag
        assert_eq!(di[1], 0x31); // 49 bytes payload
    }

    #[test]
    fn digest_info_sha384_length() {
        let hash = [0u8; 48];
        let di = build_digest_info(&hash, DigestAlgorithm::Sha384).unwrap();
        // prefix (19 bytes) + 48-byte hash = 67 bytes
        assert_eq!(di.len(), 67);
        assert_eq!(di[0], 0x30);
        assert_eq!(di[1], 0x41); // 65 bytes payload
    }

    #[test]
    fn digest_info_sha512_length() {
        let hash = [0u8; 64];
        let di = build_digest_info(&hash, DigestAlgorithm::Sha512).unwrap();
        // prefix (19 bytes) + 64-byte hash = 83 bytes
        assert_eq!(di.len(), 83);
        assert_eq!(di[0], 0x30);
        assert_eq!(di[1], 0x51); // 81 bytes payload
    }

    #[test]
    fn digest_info_sha256_oid_bytes() {
        let hash = [0xabu8; 32];
        let di = build_digest_info(&hash, DigestAlgorithm::Sha256).unwrap();
        // OID id-sha256 tag(0x06) + len(0x09) + 9-byte value at offset 4
        assert_eq!(
            &di[4..15],
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        );
        // Hash payload occupies the last 32 bytes
        assert_eq!(&di[di.len() - 32..], &[0xabu8; 32]);
    }
}
