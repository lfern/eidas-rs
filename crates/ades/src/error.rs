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

    /// Operation not yet implemented.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}
