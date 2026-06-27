use crate::{error::AdesError, signer::Signer};

/// Produces a PAdES B-B signature over a PDF document.
///
/// Returns the signed PDF bytes with an embedded CAdES signature in a
/// `/ByteRange` + `/Contents` signature field as defined in ISO 32000-2
/// and ETSI EN 319 102-1.
///
/// # Errors
///
/// Returns [`AdesError`] if PDF parsing, signing, or CMS encoding fails.
///
/// # Example
///
/// ```no_run
/// use ades::{pades, signer::SoftSigner};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let pdf = std::fs::read("document.pdf").unwrap();
/// let signed_pdf = pades::sign(&pdf, &signer).unwrap();
/// ```
#[cfg(feature = "pades")]
pub fn sign<S: Signer>(pdf: &[u8], signer: &S) -> Result<Vec<u8>, AdesError> {
    // M2: implement PAdES B-B
    // Steps:
    //   1. Parse PDF with lopdf
    //   2. Add signature dictionary with placeholder /Contents
    //   3. Compute /ByteRange (everything except /Contents placeholder)
    //   4. Compute digest over byte ranges
    //   5. Build CAdES signature over the digest (reuse cades::sign logic)
    //   6. Write signature bytes into /Contents placeholder
    //   7. Return modified PDF bytes
    let _ = (pdf, signer);
    Err(AdesError::NotImplemented("PAdES B-B signing (M2)"))
}
