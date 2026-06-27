#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(missing_docs)]

//! AdES (Advanced Electronic Signatures) for the eIDAS 2.0 ecosystem.
//!
//! ## Supported formats
//!
//! | Format | Level | Status |
//! |--------|-------|--------|
//! | CAdES  | B-B   | M1 — in development |
//! | PAdES  | B-B   | M2 — planned |
//!
//! ## RustCrypto compatibility
//!
//! The [`signer::Signer`] trait is designed to be compatible with
//! RustCrypto's `DigestSigner` pattern: only the pre-computed digest is
//! passed to the signing function, so the private key never needs to be
//! extracted from hardware tokens (DNIe, HSM, WebCrypto).
//!
//! ## Quick start
//!
//! ```no_run
//! use ades::cades;
//! use ades::signer::SoftSigner;
//!
//! let signer = SoftSigner::generate(2048).unwrap();
//! let signed = cades::sign(b"hello world", &signer).unwrap();
//! ```

/// X.509 certificate wrapper.
pub mod certificate;
/// Digest algorithm abstractions.
pub mod digest;
/// Error types.
pub mod error;
/// Signer trait and software backend.
pub mod signer;

/// CAdES (CMS Advanced Electronic Signatures).
#[cfg(feature = "cades")]
pub mod cades;

/// PAdES (PDF Advanced Electronic Signatures).
#[cfg(feature = "pades")]
pub mod pades;

pub use certificate::Certificate;
pub use digest::DigestAlgorithm;
pub use error::AdesError;
