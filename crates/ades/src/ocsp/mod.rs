//! OCSP (Online Certificate Status Protocol, RFC 6960) client.
//!
//! Checks the revocation status of an X.509 certificate by querying
//! the OCSP responder URL found in the certificate's AIA extension,
//! or a URL provided explicitly.

/// OCSP client implementation.
#[cfg(feature = "ocsp")]
pub mod client;

#[cfg(feature = "ocsp")]
pub use client::{OcspClient, OcspStatus};
