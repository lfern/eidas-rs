use crate::{certificate::Certificate, digest::DigestAlgorithm, error::AdesError};

/// Abstraction over a signing key, compatible with software keys, DNIe, HSM, and WebCrypto.
///
/// The private key never leaves the device: only the digest is passed to `sign_digest`.
/// This design ensures hardware tokens (PKCS#11, WebCrypto) can implement this trait
/// without ever exposing the raw key material.
///
/// # Example
///
/// ```no_run
/// use ades::signer::{Signer, SoftSigner};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// ```
pub trait Signer {
    /// The error type returned by signing operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Signs `digest` (the pre-computed hash of the data) and returns the raw signature bytes.
    ///
    /// The digest length must match the algorithm returned by [`Self::digest_algorithm`].
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` if the signing operation fails.
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Returns the signer's certificate. Used to embed the signing certificate in the signature.
    fn certificate(&self) -> &Certificate;

    /// Returns the digest algorithm used by this signer.
    fn digest_algorithm(&self) -> DigestAlgorithm;
}

/// Software signing backend — holds the private key in memory.
///
/// Intended for testing and development. Do not use in production with real keys.
///
/// Enabled only when the `soft` feature is active (on by default).
#[cfg(feature = "soft")]
pub struct SoftSigner {
    private_key: rsa::RsaPrivateKey,
    certificate: Certificate,
    digest: DigestAlgorithm,
}

#[cfg(feature = "soft")]
impl SoftSigner {
    /// Generates a fresh RSA key pair of `bits` size and a self-signed certificate.
    ///
    /// `bits` should be 2048 or 4096. Using 2048 is sufficient for testing.
    ///
    /// # Errors
    ///
    /// Returns [`AdesError`] if key generation or certificate construction fails.
    pub fn generate(bits: usize) -> Result<Self, AdesError> {
        // M1: implement self-signed certificate generation with x509-cert builder
        let _ = bits;
        Err(AdesError::NotImplemented("SoftSigner::generate (M1)"))
    }

    /// Creates a `SoftSigner` from an existing RSA private key and DER-encoded certificate.
    ///
    /// # Errors
    ///
    /// Returns [`AdesError`] if the certificate DER is invalid.
    pub fn from_parts(
        private_key: rsa::RsaPrivateKey,
        cert_der: &[u8],
        digest: DigestAlgorithm,
    ) -> Result<Self, AdesError> {
        let certificate = Certificate::from_der(cert_der)?;
        Ok(Self {
            private_key,
            certificate,
            digest,
        })
    }
}

#[cfg(feature = "soft")]
impl Signer for SoftSigner {
    type Error = AdesError;

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, Self::Error> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::hazmat::PrehashSigner;
        use rsa::signature::SignatureEncoding;
        use sha2::Sha256;

        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature: rsa::pkcs1v15::Signature = signing_key.sign_prehash(digest)?;
        Ok(signature.to_vec())
    }

    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest
    }
}
