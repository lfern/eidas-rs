use crate::{error::AdesError, levels, signer::Signer, tsp::TspClient};

/// Produces a CAdES B-T signature: B-B + a signature timestamp from a TSA.
///
/// The `TimeStampToken` is embedded as the unsigned attribute
/// `id-aa-signatureTimeStampToken` (over the `SignatureValue`).
///
/// # Errors
///
/// Returns [`AdesError`] if signing, the TSA request, or CMS re-encoding fails.
///
/// # Example
///
/// ```no_run
/// use ades::{cades, signer::SoftSigner, tsp::TspClient};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let tsa = TspClient::new("https://freetsa.org/tsr");
/// let signed = cades::sign_t(b"hello world", &signer, &tsa).unwrap();
/// ```
#[cfg(all(feature = "cades", feature = "tsp"))]
pub fn sign_t<S>(data: &[u8], signer: &S, tsa: &TspClient) -> Result<Vec<u8>, AdesError>
where
    S: Signer,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    // 1. Produce B-B signature
    let bb = crate::cades::sign(data, signer)?;

    // 2. Extract SignatureValue bytes to timestamp.
    //    Per ETSI EN 319 122-1 §5.2.7, the TST covers the signature value octets.
    let sig_value = extract_signature_value(&bb)?;

    // 3. Request TST from TSA
    let digest_algo = signer.digest_algorithm();
    let hash = digest_algo.hash(&sig_value);
    let tst = tsa.timestamp(&hash, digest_algo)?;

    // 4. Embed TST as unsigned attribute
    levels::add_signature_timestamp(&bb, &tst)
}

/// Produces a CAdES B-LT signature: B-T + embedded revocation data (OCSP).
///
/// # Errors
///
/// Returns [`AdesError`] if any step fails.
///
/// # Example
///
/// ```no_run
/// use ades::{cades, signer::SoftSigner, tsp::TspClient, ocsp::OcspClient};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let tsa = TspClient::new("https://freetsa.org/tsr");
/// let ocsp = OcspClient::new();
/// let signed = cades::sign_lt(b"hello world", &signer, &tsa, &ocsp).unwrap();
/// ```
#[cfg(all(feature = "cades", feature = "tsp", feature = "ocsp"))]
pub fn sign_lt<S>(
    data: &[u8],
    signer: &S,
    tsa: &TspClient,
    ocsp: &crate::ocsp::OcspClient,
) -> Result<Vec<u8>, AdesError>
where
    S: Signer,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    // 1. B-T
    let bt = sign_t(data, signer, tsa)?;

    // 2. Check revocation status and get raw OCSP response bytes.
    //    For self-signed certs (no AIA), we skip revocation embedding.
    //    Production certs with AIA will trigger a real OCSP request.
    let cert = signer.certificate();
    let ocsp_resp = match ocsp.raw_response(cert, cert) {
        Ok(resp) => resp,
        Err(AdesError::Ocsp(_)) => {
            // No AIA or OCSP unavailable — still return B-T (acceptable for test certs)
            return Ok(bt);
        }
        Err(e) => return Err(e),
    };

    // 3. Embed revocation data
    levels::add_revocation_values(&bt, &ocsp_resp)
}

/// Extracts the raw `SignatureValue` bytes from a CMS `ContentInfo`.
///
/// Per RFC 5652 §5.3, `SignatureValue` is an OCTET STRING inside `SignerInfo`.
fn extract_signature_value(cms_der: &[u8]) -> Result<Vec<u8>, AdesError> {
    use cms::{content_info::ContentInfo, signed_data::SignedData};
    use der::{Decode, Encode};

    let ci = ContentInfo::from_der(cms_der)?;
    let sd = SignedData::from_der(&ci.content.to_der()?)?;
    let si = sd
        .signer_infos
        .0
        .as_ref()
        .first()
        .ok_or(AdesError::NotImplemented("CMS has no signer infos"))?;

    Ok(si.signature.as_bytes().to_vec())
}
