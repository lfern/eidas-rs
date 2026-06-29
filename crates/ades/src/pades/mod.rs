//! PAdES (PDF Advanced Electronic Signatures) implementation.
//!
//! Supported levels:
//! - **B-B** (Baseline-B): basic signature — M2
//! - **B-T** (Baseline-T): B-B + signature timestamp — M3c
//! - **B-LT** (Baseline-LT): B-T + embedded revocation data — M3c

/// PAdES B-B signing.
pub mod sign;

/// PAdES B-T and B-LT signing.
#[cfg(feature = "pades")]
pub mod sign_t;

pub use sign::sign;

#[cfg(all(feature = "pades", feature = "tsp"))]
pub use sign_t::sign_t;

#[cfg(all(feature = "pades", feature = "tsp", feature = "ocsp"))]
pub use sign_t::sign_lt;
