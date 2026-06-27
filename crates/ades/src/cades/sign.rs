use crate::{error::AdesError, signer::Signer};

/// Produces a CAdES B-B signature over `data`.
///
/// Returns the raw DER-encoded CMS `SignedData` structure suitable for
/// submission to a DSS validator.
///
/// The signature includes the mandatory signed attributes for CAdES B-B:
/// - `id-contentType`
/// - `id-signingTime`
/// - `id-messageDigest`
///
/// # Errors
///
/// Returns [`AdesError`] if signing or CMS encoding fails.
///
/// # Example
///
/// ```no_run
/// use ades::{cades, signer::SoftSigner};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let signed = cades::sign(b"hello world", &signer).unwrap();
/// ```
#[cfg(feature = "cades")]
pub fn sign<S: Signer>(data: &[u8], signer: &S) -> Result<Vec<u8>, AdesError> {
    // M1: implement CAdES B-B
    // Steps:
    //   1. Compute digest over `data` using signer.digest_algorithm()
    //   2. Build SignedAttributes: id-contentType, id-signingTime, id-messageDigest
    //   3. DER-encode SignedAttributes
    //   4. Sign the DER-encoded SignedAttributes with signer.sign_digest()
    //   5. Build CMS SignedData with:
    //      - version = 1
    //      - digestAlgorithms
    //      - encapContentInfo (id-data, data detached or encapsulated)
    //      - certificates (signer certificate)
    //      - signerInfos
    //   6. Return DER encoding of the ContentInfo wrapping SignedData
    let _ = (data, signer);
    Err(AdesError::NotImplemented("CAdES B-B signing (M1)"))
}
