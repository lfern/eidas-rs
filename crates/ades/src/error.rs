use thiserror::Error;

/// Errors produced by the `ades` crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AdesError {
    /// RSA key operation failed (key generation, key import).
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    /// Cryptographic signature operation failed.
    #[error("signature error: {0}")]
    Signature(#[from] signature::Error),

    /// DER encoding or decoding failed (certificates, CMS structures).
    #[error("DER error: {0}")]
    Der(#[from] der::Error),

    /// Certificate builder error (key mismatch, extension encoding, etc.).
    #[error("certificate builder error: {0}")]
    Builder(#[from] x509_cert::builder::Error),

    /// Error returned by a [`crate::signer::Signer`] backend.
    #[error("signer error: {0}")]
    Signer(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// TSP (RFC 3161) request or response error.
    #[error("TSP error: {0}")]
    Tsp(String),

    /// OCSP (RFC 6960) request or response error.
    #[error("OCSP error: {0}")]
    Ocsp(String),

    /// Operation not yet implemented.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}
