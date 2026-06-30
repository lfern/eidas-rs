//! Shared CMS/PKCS#7 utilities used by CAdES and PAdES.

use const_oid::ObjectIdentifier;
use der::{Any, Decode};
use spki::AlgorithmIdentifierOwned;

use crate::{digest::DigestAlgorithm, error::AdesError};

// Public key algorithm OIDs (SubjectPublicKeyInfo)
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

// RSA signature algorithm OIDs (RFC 3279 / RFC 4055)
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

// ECDSA signature algorithm OIDs (RFC 5758)
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

/// Derives the CMS `signatureAlgorithm` identifier from the certificate's public key OID
/// and the chosen digest algorithm.
///
/// - RSA: `sha{N}WithRSAEncryption` with explicit NULL parameters (RFC 3279 §2.2.1).
/// - EC:  `ecdsa-with-SHA{N}` with absent parameters (RFC 5758 §3.2).
///
/// # Errors
///
/// Returns [`AdesError::NotImplemented`] if the key algorithm is not RSA or EC.
pub fn signature_algorithm_id(
    key_alg_oid: ObjectIdentifier,
    digest: DigestAlgorithm,
) -> Result<AlgorithmIdentifierOwned, AdesError> {
    if key_alg_oid == RSA_ENCRYPTION {
        // RSA requires explicit NULL parameters in the AlgorithmIdentifier
        let null_params = Any::from_der(&[0x05u8, 0x00])?;
        let oid = match digest {
            DigestAlgorithm::Sha256 => SHA256_WITH_RSA,
            DigestAlgorithm::Sha384 => SHA384_WITH_RSA,
            DigestAlgorithm::Sha512 => SHA512_WITH_RSA,
        };
        Ok(AlgorithmIdentifierOwned {
            oid,
            parameters: Some(null_params),
        })
    } else if key_alg_oid == EC_PUBLIC_KEY {
        // ECDSA parameters must be absent in the AlgorithmIdentifier (RFC 5758)
        let oid = match digest {
            DigestAlgorithm::Sha256 => ECDSA_WITH_SHA256,
            DigestAlgorithm::Sha384 => ECDSA_WITH_SHA384,
            DigestAlgorithm::Sha512 => ECDSA_WITH_SHA512,
        };
        Ok(AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        })
    } else {
        Err(AdesError::NotImplemented(
            "unsupported public key algorithm — only RSA and EC are supported",
        ))
    }
}
