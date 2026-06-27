use const_oid::ObjectIdentifier;
use sha2::Digest;

/// Supported digest algorithms for AdES signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256 (recommended minimum for new signatures).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestAlgorithm {
    /// Returns the OID for this digest algorithm.
    ///
    /// # Example
    ///
    /// ```
    /// use ades::DigestAlgorithm;
    /// let oid = DigestAlgorithm::Sha256.oid();
    /// assert_eq!(oid.to_string(), "2.16.840.1.101.3.4.2.1");
    /// ```
    #[must_use]
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            // id-sha256
            Self::Sha256 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            // id-sha384
            Self::Sha384 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
            // id-sha512
            Self::Sha512 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3"),
        }
    }

    /// Computes the digest of `data` using this algorithm.
    ///
    /// # Example
    ///
    /// ```
    /// use ades::DigestAlgorithm;
    /// let digest = DigestAlgorithm::Sha256.hash(b"hello world");
    /// assert_eq!(digest.len(), 32);
    /// ```
    #[must_use]
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// Returns the output length in bytes for this algorithm.
    #[must_use]
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}
