//! TSP (Time-Stamp Protocol, RFC 3161) client.
//!
//! Sends a `TimeStampReq` to a TSA and returns the `TimeStampToken`
//! (a CMS `ContentInfo`) for embedding in AdES signatures.

/// TSP client implementation.
#[cfg(feature = "tsp")]
pub mod client;

#[cfg(feature = "tsp")]
pub use client::TspClient;
