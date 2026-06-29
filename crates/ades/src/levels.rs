//! AdES signature levels B-T, B-LT, B-LTA.
//!
//! These functions take an existing B-B CMS `ContentInfo` (DER) and augment
//! it with unsigned attributes required by each level.

use crate::error::AdesError;

// OID id-aa-signatureTimeStampToken (ETSI EN 319 122-1 §5.2.7)
const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
// OID id-aa-ets-revocationValues (ETSI EN 319 122-1 §5.2.8)
const ID_AA_ETS_REVOCATION_VALUES: &str = "1.2.840.113549.1.9.16.2.24";

/// Upgrades a CAdES/PAdES B-B CMS to **B-T** by adding a signature timestamp.
///
/// `tst_der` is the DER-encoded `TimeStampToken` (CMS `ContentInfo`) returned
/// by a TSA. It is inserted as the unsigned attribute
/// `id-aa-signatureTimeStampToken` (over the `SignatureValue` bytes).
///
/// # Errors
///
/// Returns [`AdesError`] if the CMS cannot be parsed or re-encoded.
pub fn add_signature_timestamp(cms_der: &[u8], tst_der: &[u8]) -> Result<Vec<u8>, AdesError> {
    use const_oid::ObjectIdentifier;
    use der::asn1::SetOfVec;
    use der::{Any, Decode};
    use x509_cert::attr::Attribute;

    let oid = ObjectIdentifier::new_unwrap(ID_AA_SIGNATURE_TIME_STAMP_TOKEN);
    let attr = Attribute {
        oid,
        values: {
            let mut set = SetOfVec::<Any>::new();
            set.insert(Any::from_der(tst_der)?)?;
            set
        },
    };
    add_unsigned_attr_to_cms(cms_der, attr)
}

/// Upgrades a CAdES/PAdES B-T CMS to **B-LT** by embedding revocation data.
///
/// `ocsp_resp_der` is the DER-encoded `BasicOCSPResponse` (the raw bytes
/// inside the OCSP `responseBytes.response` OCTET STRING).
///
/// # Errors
///
/// Returns [`AdesError`] if the CMS cannot be parsed or re-encoded.
pub fn add_revocation_values(cms_der: &[u8], ocsp_resp_der: &[u8]) -> Result<Vec<u8>, AdesError> {
    use const_oid::ObjectIdentifier;
    use der::asn1::SetOfVec;
    use der::{Any, Decode};
    use x509_cert::attr::Attribute;

    // RevocationValues ::= SEQUENCE {
    //   ocspValues  [1] SEQUENCE OF BasicOCSPResponse OPTIONAL
    // }
    // BasicOCSPResponse is already a SEQUENCE — wrap as [1] EXPLICIT inside RevocationValues.
    let basic_seq = der_tlv(0x30, ocsp_resp_der); // BasicOCSPResponse inside a SEQUENCE OF
    let ocsp_values_inner = der_tlv(0x30, &basic_seq); // SEQUENCE OF BasicOCSPResponse
    let ocsp_values = der_ctx_tag(0xa1, &ocsp_values_inner); // [1] EXPLICIT
    let rev_values_der = der_tlv(0x30, &ocsp_values); // RevocationValues SEQUENCE

    let oid = ObjectIdentifier::new_unwrap(ID_AA_ETS_REVOCATION_VALUES);
    let attr = Attribute {
        oid,
        values: {
            let mut set = SetOfVec::<Any>::new();
            set.insert(Any::from_der(&rev_values_der)?)?;
            set
        },
    };
    add_unsigned_attr_to_cms(cms_der, attr)
}

// ---------------------------------------------------------------------------
// Core: decode CMS → add unsigned attr → re-encode
// ---------------------------------------------------------------------------

fn add_unsigned_attr_to_cms(
    cms_der: &[u8],
    attr: x509_cert::attr::Attribute,
) -> Result<Vec<u8>, AdesError> {
    use cms::{
        content_info::ContentInfo,
        signed_data::{SignedData, SignerInfos},
    };
    use der::{Any, Decode, Encode};

    // Decode ContentInfo
    let ci = ContentInfo::from_der(cms_der)?;

    // Decode SignedData from content Any
    let sd_der = ci.content.to_der()?;
    let mut sd = SignedData::from_der(&sd_der)?;

    // Get first SignerInfo, round-trip through DER to get owned value
    let si_der = sd
        .signer_infos
        .0
        .as_ref()
        .first()
        .ok_or(AdesError::NotImplemented("CMS has no signer infos"))?
        .to_der()?;

    let mut si = cms::signed_data::SignerInfo::from_der(&si_der)?;

    // Add unsigned attribute
    let mut unsigned = si.unsigned_attrs.take().unwrap_or_default();
    unsigned.insert(attr)?;
    si.unsigned_attrs = Some(unsigned);

    // Rebuild SignerInfos with the updated SignerInfo
    let mut new_si_set = SignerInfos(Default::default());
    new_si_set.0.insert(si)?;
    sd.signer_infos = new_si_set;

    // Re-encode SignedData → ContentInfo
    let new_sd_der = sd.to_der()?;
    let new_ci = ContentInfo {
        content_type: ci.content_type,
        content: Any::from_der(&new_sd_der)?,
    };

    Ok(new_ci.to_der()?)
}

// ---------------------------------------------------------------------------
// Minimal DER helpers
// ---------------------------------------------------------------------------

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let len = value.len();
    let mut out = vec![tag];
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 65536 {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
    } else {
        out.extend_from_slice(&[
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xff) as u8,
        ]);
    }
    out.extend_from_slice(value);
    out
}

fn der_ctx_tag(tag: u8, value: &[u8]) -> Vec<u8> {
    der_tlv(tag, value)
}
