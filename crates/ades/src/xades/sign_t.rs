use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};

use crate::{digest::DigestAlgorithm, error::AdesError, signer::Signer, tsp::TspClient};

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Produces an XAdES B-T signature: B-B plus an RFC 3161 timestamp from a TSA.
///
/// The timestamp token is placed in `<xades:UnsignedProperties>` /
/// `<xades:UnsignedSignatureProperties>` / `<xades:SignatureTimeStamp>` /
/// `<xades:EncapsulatedTimeStamp>`.  The message imprint is the SHA-256 hash
/// of the exclusive-C14N form of `<ds:SignatureValue>`.
///
/// # Errors
///
/// Returns [`AdesError`] if signing, the TSA request, or XML modification fails.
///
/// # Example
///
/// ```no_run
/// use ades::{xades, signer::SoftSigner, tsp::TspClient};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let tsa = TspClient::new("https://freetsa.org/tsr");
/// let xml = xades::sign_t(b"hello world", &signer, &tsa).unwrap();
/// ```
#[cfg(all(feature = "xades", feature = "tsp"))]
pub fn sign_t<S>(data: &[u8], signer: &S, tsa: &TspClient) -> Result<Vec<u8>, AdesError>
where
    S: Signer,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let xml_bytes = super::sign::sign(data, signer)?;
    add_signature_timestamp(xml_bytes, tsa)
}

/// Produces an XAdES B-LT signature: B-T plus embedded OCSP revocation data.
///
/// Revocation values are placed in `<xades:UnsignedSignatureProperties>` /
/// `<xades:RevocationValues>` / `<xades:OCSPValues>` /
/// `<xades:EncapsulatedOCSPValue>`.
///
/// If the signing certificate has no OCSP URL (e.g. self-signed test certs),
/// the function silently returns B-T without revocation data.
///
/// # Errors
///
/// Returns [`AdesError`] if any step fails.
///
/// # Example
///
/// ```no_run
/// use ades::{xades, signer::SoftSigner, tsp::TspClient, ocsp::OcspClient};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let tsa = TspClient::new("https://freetsa.org/tsr");
/// let ocsp = OcspClient::new();
/// let xml = xades::sign_lt(b"hello world", &signer, &tsa, &ocsp).unwrap();
/// ```
#[cfg(all(feature = "xades", feature = "tsp", feature = "ocsp"))]
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
    let bt_bytes = sign_t(data, signer, tsa)?;

    let cert = signer.certificate();
    let ocsp_resp = match ocsp.raw_response(cert, cert) {
        Ok(resp) => resp,
        Err(AdesError::Ocsp(_)) => return Ok(bt_bytes),
        Err(e) => return Err(e),
    };

    add_revocation_values(bt_bytes, &ocsp_resp)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "tsp")]
fn add_signature_timestamp(xml_bytes: Vec<u8>, tsa: &TspClient) -> Result<Vec<u8>, AdesError> {
    let xml = String::from_utf8(xml_bytes)
        .map_err(|_| AdesError::NotImplemented("XAdES: XML is not valid UTF-8"))?;

    // Extract the base64 content of <ds:SignatureValue>.
    // The element has no attributes in our B-B output, so exact-tag search works.
    let sig_b64 = extract_element_text(&xml, "ds:SignatureValue").ok_or(
        AdesError::NotImplemented("XAdES: <ds:SignatureValue> not found in B-B XML"),
    )?;

    // Exclusive C14N of the <ds:SignatureValue> subtree (no ancestor context):
    // ds: is visibly utilized → xmlns:ds on the element.
    let sv_canon = format!("<ds:SignatureValue xmlns:ds=\"{DS_NS}\">{sig_b64}</ds:SignatureValue>");

    let imprint = Sha256::digest(sv_canon.as_bytes());
    let tsr = tsa.timestamp(&imprint, DigestAlgorithm::Sha256)?;
    let tsr_b64 = Base64::encode_string(&tsr);

    let unsigned_props = format!(
        "<xades:UnsignedProperties>\
<xades:UnsignedSignatureProperties>\
<xades:SignatureTimeStamp>\
<ds:CanonicalizationMethod xmlns:ds=\"{DS_NS}\" Algorithm=\"{EXC_C14N}\"></ds:CanonicalizationMethod>\
<xades:EncapsulatedTimeStamp>{tsr_b64}</xades:EncapsulatedTimeStamp>\
</xades:SignatureTimeStamp>\
</xades:UnsignedSignatureProperties>\
</xades:UnsignedProperties>"
    );

    let closing = "</xades:QualifyingProperties>";
    let pos = xml.rfind(closing).ok_or(AdesError::NotImplemented(
        "XAdES: </xades:QualifyingProperties> not found",
    ))?;

    let mut result = String::with_capacity(xml.len() + unsigned_props.len() + 2);
    result.push_str(&xml[..pos]);
    result.push('\n');
    result.push_str(&unsigned_props);
    result.push('\n');
    result.push_str(&xml[pos..]);

    Ok(result.into_bytes())
}

#[cfg(all(feature = "tsp", feature = "ocsp"))]
fn add_revocation_values(xml_bytes: Vec<u8>, ocsp_resp: &[u8]) -> Result<Vec<u8>, AdesError> {
    let xml = String::from_utf8(xml_bytes)
        .map_err(|_| AdesError::NotImplemented("XAdES: XML is not valid UTF-8"))?;

    let ocsp_b64 = Base64::encode_string(ocsp_resp);
    let revocation = format!(
        "<xades:RevocationValues>\
<xades:OCSPValues>\
<xades:EncapsulatedOCSPValue>{ocsp_b64}</xades:EncapsulatedOCSPValue>\
</xades:OCSPValues>\
</xades:RevocationValues>"
    );

    let anchor = "</xades:UnsignedSignatureProperties>";
    let pos = xml.rfind(anchor).ok_or(AdesError::NotImplemented(
        "XAdES: </xades:UnsignedSignatureProperties> not found — is this a B-T signature?",
    ))?;

    let mut result = String::with_capacity(xml.len() + revocation.len() + 2);
    result.push_str(&xml[..pos]);
    result.push('\n');
    result.push_str(&revocation);
    result.push('\n');
    result.push_str(&xml[pos..]);

    Ok(result.into_bytes())
}

fn extract_element_text<'a>(xml: &'a str, element: &str) -> Option<&'a str> {
    let open = format!("<{element}>");
    let close = format!("</{element}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}
