use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};

use crate::{error::AdesError, signer::Signer};

// XML-DSig and XAdES namespace URIs
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";

// Algorithm URIs
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const SHA256_ALG: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const SIGNED_PROPS_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";

// OIDs for key type detection
const RSA_OID: &str = "1.2.840.113549.1.1.1";
const EC_OID: &str = "1.2.840.10045.2.1";

/// Produces an XAdES B-B enveloping signature over `data`.
///
/// Returns a UTF-8 encoded XML document containing a `<ds:Signature>` with:
/// - The data embedded as base64 inside `<ds:Object>`
/// - `<xades:QualifyingProperties>` with `SigningTime` and `SigningCertificateV2`
/// - Exclusive C14N (exc-c14n) for all canonicalization
///
/// The result is self-contained and can be submitted directly to DSS for
/// validation without the original document.
///
/// # Errors
///
/// Returns [`AdesError`] if signing fails or system time is unavailable.
///
/// # Example
///
/// ```no_run
/// use ades::{xades, signer::SoftSigner};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let xml = xades::sign(b"hello world", &signer).unwrap();
/// ```
pub fn sign<S: Signer>(data: &[u8], signer: &S) -> Result<Vec<u8>, AdesError>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let cert = signer.certificate();
    let digest_algo = signer.digest_algorithm();

    // Derive the XML-DSig signature algorithm URI from the certificate's key type
    let key_alg_oid = cert
        .inner()
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string();
    let sig_method_alg = match key_alg_oid.as_str() {
        RSA_OID => RSA_SHA256,
        EC_OID => ECDSA_SHA256,
        _ => {
            return Err(AdesError::NotImplemented(
                "XAdES: unsupported key type — only RSA and EC are supported",
            ))
        }
    };

    // Fixed element IDs
    let sig_id = "id-sig";
    let data_obj_id = "id-data-obj";
    let signed_props_id = "id-signed-props";

    // Base64 encodings
    let data_b64 = Base64::encode_string(data);
    let cert_der = cert.to_der();
    let cert_b64 = Base64::encode_string(cert_der);

    // SHA-256 of cert DER — goes into xades:SigningCertificateV2
    let cert_digest_b64 = Base64::encode_string(&Sha256::digest(cert_der));

    // Signing time in XML Schema dateTime format (UTC)
    let signing_time = utc_datetime_now()?;

    // -----------------------------------------------------------------------
    // Step 1: Canonical form of <ds:Object Id="id-data-obj"> and its hash
    //
    // Exclusive C14N rules applied:
    //   - Namespace declarations rendered before regular attributes, sorted by prefix
    //   - Regular attributes sorted by (namespace-uri, local-name)
    //   - Empty elements: <tag></tag> (no self-closing)
    //
    // `ds:` prefix is utilized by the element → xmlns:ds is rendered here.
    // -----------------------------------------------------------------------
    let data_obj_canon =
        format!("<ds:Object xmlns:ds=\"{DS_NS}\" Id=\"{data_obj_id}\">{data_b64}</ds:Object>");
    let data_digest_b64 = Base64::encode_string(&Sha256::digest(data_obj_canon.as_bytes()));

    // -----------------------------------------------------------------------
    // Step 2: Canonical form of <xades:SignedProperties> and its hash
    //
    // Exclusive C14N renders namespace declarations only for the prefix
    // VISIBLY UTILIZED BY THE ELEMENT ITSELF (not by descendants):
    //   - <xades:SignedProperties>: uses `xades:` → only xmlns:xades here
    //   - <ds:DigestMethod>: uses `ds:` → xmlns:ds here (first ds: element)
    //   - <ds:DigestValue>: uses `ds:` but it is a SIBLING of DigestMethod,
    //     not a descendant → xmlns:ds must be repeated (sibling ancestors
    //     don't count as "already rendered").
    // -----------------------------------------------------------------------
    let signed_props_canon = format!(
        "<xades:SignedProperties xmlns:xades=\"{XADES_NS}\" Id=\"{signed_props_id}\">\
<xades:SignedSignatureProperties>\
<xades:SigningTime>{signing_time}</xades:SigningTime>\
<xades:SigningCertificateV2>\
<xades:Cert>\
<xades:CertDigest>\
<ds:DigestMethod xmlns:ds=\"{DS_NS}\" Algorithm=\"{SHA256_ALG}\"></ds:DigestMethod>\
<ds:DigestValue xmlns:ds=\"{DS_NS}\">{cert_digest_b64}</ds:DigestValue>\
</xades:CertDigest>\
</xades:Cert>\
</xades:SigningCertificateV2>\
</xades:SignedSignatureProperties>\
</xades:SignedProperties>"
    );
    let props_digest_b64 = Base64::encode_string(&Sha256::digest(signed_props_canon.as_bytes()));

    // -----------------------------------------------------------------------
    // Step 3: Canonical form of <ds:SignedInfo> for signing
    //
    // Only `ds:` is utilized → xmlns:ds on the root; children do not repeat it.
    // Attribute ordering within each element:
    //   - <ds:Reference Type="..." URI="...">: Type < URI alphabetically
    // -----------------------------------------------------------------------
    let signed_info_canon = format!(
        "<ds:SignedInfo xmlns:ds=\"{DS_NS}\">\
<ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"></ds:CanonicalizationMethod>\
<ds:SignatureMethod Algorithm=\"{sig_method_alg}\"></ds:SignatureMethod>\
<ds:Reference URI=\"#{data_obj_id}\">\
<ds:Transforms><ds:Transform Algorithm=\"{EXC_C14N}\"></ds:Transform></ds:Transforms>\
<ds:DigestMethod Algorithm=\"{SHA256_ALG}\"></ds:DigestMethod>\
<ds:DigestValue>{data_digest_b64}</ds:DigestValue>\
</ds:Reference>\
<ds:Reference Type=\"{SIGNED_PROPS_TYPE}\" URI=\"#{signed_props_id}\">\
<ds:Transforms><ds:Transform Algorithm=\"{EXC_C14N}\"></ds:Transform></ds:Transforms>\
<ds:DigestMethod Algorithm=\"{SHA256_ALG}\"></ds:DigestMethod>\
<ds:DigestValue>{props_digest_b64}</ds:DigestValue>\
</ds:Reference>\
</ds:SignedInfo>"
    );

    // Hash the canonical SignedInfo and sign the hash
    let si_digest = digest_algo.hash(signed_info_canon.as_bytes());
    let signature_bytes = signer
        .sign_digest(&si_digest)
        .map_err(|e| AdesError::Signer(Box::new(e)))?;

    // For ECDSA: XML-DSig requires raw r||s, but Pkcs11Signer returns DER.
    // Convert DER → raw if needed.
    let signature_bytes = if sig_method_alg == ECDSA_SHA256 {
        ecdsa_der_to_raw(&signature_bytes)?
    } else {
        signature_bytes
    };

    let sig_b64 = Base64::encode_string(&signature_bytes);

    // -----------------------------------------------------------------------
    // Step 4: Assemble the complete XML document
    //
    // The canonical sub-elements are embedded verbatim so that when DSS
    // parses and re-canonicalizes them it produces the same bytes we hashed.
    // Whitespace between elements outside the hashed subtrees is irrelevant.
    // -----------------------------------------------------------------------
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<ds:Signature Id=\"{sig_id}\" xmlns:ds=\"{DS_NS}\">\n\
{signed_info_canon}\n\
<ds:SignatureValue>{sig_b64}</ds:SignatureValue>\n\
<ds:KeyInfo>\n\
<ds:X509Data>\n\
<ds:X509Certificate>{cert_b64}</ds:X509Certificate>\n\
</ds:X509Data>\n\
</ds:KeyInfo>\n\
{data_obj_canon}\n\
<ds:Object>\n\
<xades:QualifyingProperties Target=\"#{sig_id}\" xmlns:xades=\"{XADES_NS}\">\n\
{signed_props_canon}\n\
</xades:QualifyingProperties>\n\
</ds:Object>\n\
</ds:Signature>"
    );

    Ok(xml.into_bytes())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts an ECDSA DER signature (SEQUENCE { INTEGER r, INTEGER s }) to
/// the raw r||s format required by XML-DSig (RFC 6931 §2.1.2).
fn ecdsa_der_to_raw(der: &[u8]) -> Result<Vec<u8>, AdesError> {
    // DER: 0x30 [seq_len] 0x02 [r_len] [r] 0x02 [s_len] [s]
    let err = || AdesError::NotImplemented("XAdES: malformed ECDSA DER signature");

    if der.len() < 6 || der[0] != 0x30 {
        return Err(err());
    }
    let seq_len = der[1] as usize;
    if der.len() < 2 + seq_len {
        return Err(err());
    }
    let content = &der[2..2 + seq_len];

    // Parse r
    if content.len() < 2 || content[0] != 0x02 {
        return Err(err());
    }
    let r_len = content[1] as usize;
    if content.len() < 2 + r_len {
        return Err(err());
    }
    let r_bytes = &content[2..2 + r_len];

    // Parse s
    let rest = &content[2 + r_len..];
    if rest.len() < 2 || rest[0] != 0x02 {
        return Err(err());
    }
    let s_len = rest[1] as usize;
    if rest.len() < 2 + s_len {
        return Err(err());
    }
    let s_bytes = &rest[2..2 + s_len];

    // DER INTEGERs may have a leading 0x00 padding byte — strip it, then
    // pad both r and s to the same length (determined by the larger one)
    let r_trimmed = strip_leading_zero(r_bytes);
    let s_trimmed = strip_leading_zero(s_bytes);
    let coord = r_trimmed.len().max(s_trimmed.len());

    let mut out = vec![0u8; 2 * coord];
    out[coord - r_trimmed.len()..coord].copy_from_slice(r_trimmed);
    out[2 * coord - s_trimmed.len()..].copy_from_slice(s_trimmed);
    Ok(out)
}

fn strip_leading_zero(b: &[u8]) -> &[u8] {
    if b.first() == Some(&0x00) {
        &b[1..]
    } else {
        b
    }
}

/// Returns the current UTC time as an XML Schema `dateTime` string (`YYYY-MM-DDTHH:MM:SSZ`).
fn utc_datetime_now() -> Result<String, AdesError> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AdesError::NotImplemented("system time before Unix epoch"))?
        .as_secs();

    let s = (secs % 60) as u32;
    let m = ((secs / 60) % 60) as u32;
    let h = ((secs / 3600) % 24) as u32;

    // Days to Gregorian Y-M-D: Howard Hinnant's algorithm
    // https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = (secs / 86400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mn = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mn <= 2 { y + 1 } else { y };

    Ok(format!("{year:04}-{mn:02}-{d:02}T{h:02}:{m:02}:{s:02}Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_datetime_format() {
        // Unix epoch should be 1970-01-01T00:00:00Z
        let secs = 0u64;
        let z = secs as i64 + 719_468;
        let era = z / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let mn = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = if mn <= 2 { y + 1 } else { y };
        assert_eq!((year, mn, d), (1970, 1, 1));
    }

    #[test]
    fn ecdsa_der_to_raw_roundtrip() {
        // DER: SEQUENCE { INTEGER 0x01 (r=1), INTEGER 0x02 (s=2) }
        // SEQUENCE: 0x30 0x06
        //   INTEGER: 0x02 0x01 0x01  (r = 1)
        //   INTEGER: 0x02 0x01 0x02  (s = 2)
        let der = &[0x30u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let raw = ecdsa_der_to_raw(der).unwrap();
        assert_eq!(raw, &[0x01, 0x02]);
    }
}
