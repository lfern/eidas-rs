/// XAdES B-B signing.
mod sign;

/// XAdES B-T and B-LT signing.
#[cfg(feature = "tsp")]
mod sign_t;

pub use sign::sign;

#[cfg(feature = "tsp")]
pub use sign_t::sign_t;

#[cfg(all(feature = "tsp", feature = "ocsp"))]
pub use sign_t::sign_lt;
