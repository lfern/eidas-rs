//! PAdES (PDF Advanced Electronic Signatures) implementation.
//!
//! Supported levels:
//! - **B-B** (Baseline-B): basic signature — M2

/// PAdES signing functions.
pub mod sign;

pub use sign::sign;
