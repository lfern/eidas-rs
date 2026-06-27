//! CAdES (CMS Advanced Electronic Signatures) implementation.
//!
//! Supported levels:
//! - **B-B** (Baseline-B): basic signature — M1

/// CAdES signing functions.
pub mod sign;

pub use sign::sign;
