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
/// Shared CMS/PKCS#7 utilities (signature algorithm derivation).
pub(crate) mod cms;
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

/// TSP (Time-Stamp Protocol, RFC 3161) client.
pub mod tsp;

/// OCSP (Online Certificate Status Protocol, RFC 6960) client.
pub mod ocsp;

/// AdES signature level upgrades (B-T, B-LT, B-LTA).
pub mod levels;

/// PKCS#11 signing backend (DNIe, smart cards, HSMs).
#[cfg(feature = "pkcs11")]
pub mod pkcs11;

pub use certificate::Certificate;
pub use digest::DigestAlgorithm;
pub use error::AdesError;
