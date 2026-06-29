//! PKCS#11 signing backend — for DNIe, smart cards, and HSMs.
//!
//! Enabled with the `pkcs11` feature. Requires a PKCS#11 shared library
//! (e.g., `/usr/lib/softhsm/libsofthsm2.so` for SoftHSM2, or
//! `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` for DNIe/OpenSC).

/// [`Pkcs11Signer`] implementation.
pub mod signer;

pub use signer::Pkcs11Signer;
