//! CAdES (CMS Advanced Electronic Signatures) implementation.
//!
//! Supported levels:
//! - **B-B** (Baseline-B): basic signature — M1
//! - **B-T** (Baseline-T): B-B + signature timestamp — M3c
//! - **B-LT** (Baseline-LT): B-T + embedded revocation data — M3c

/// CAdES B-B signing.
pub mod sign;

/// CAdES B-T and B-LT signing.
#[cfg(feature = "cades")]
pub mod sign_t;

pub use sign::sign;

#[cfg(all(feature = "cades", feature = "tsp"))]
pub use sign_t::sign_t;

#[cfg(all(feature = "cades", feature = "tsp", feature = "ocsp"))]
pub use sign_t::sign_lt;
