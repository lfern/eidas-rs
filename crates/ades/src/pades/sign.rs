use crate::{
    cms::signature_algorithm_id, digest::DigestAlgorithm, error::AdesError, signer::Signer,
};

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
pub fn sign<S: Signer>(pdf_bytes: &[u8], signer: &S) -> Result<Vec<u8>, AdesError>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    use lopdf::{Document, Object};

    // 1. Parse original PDF
    let doc = Document::load_mem(pdf_bytes).map_err(|e| AdesError::Signer(Box::new(e)))?;

    let catalog_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|e| AdesError::Signer(Box::new(e)))?;

    let first_page_id = doc
        .page_iter()
        .next()
        .ok_or(AdesError::NotImplemented("PDF has no pages"))?;

    let max_id = doc.max_id;
    let prev_xref = doc.xref_start;

    // Get first page /Annots if it exists
    let page_dict = doc
        .get_dictionary(first_page_id)
        .map_err(|e| AdesError::Signer(Box::new(e)))?;

    let existing_annots: Vec<(u32, u16)> = page_dict
        .get(b"Annots")
        .and_then(Object::as_array)
        .map(|arr| arr.iter().filter_map(|o| o.as_reference().ok()).collect())
        .unwrap_or_default();

    // Get catalog /AcroForm if it exists
    let catalog_dict = doc
        .get_dictionary(catalog_id)
        .map_err(|e| AdesError::Signer(Box::new(e)))?;

    let existing_acroform_fields: Vec<(u32, u16)> = catalog_dict
        .get(b"AcroForm")
        .and_then(Object::as_reference)
        .ok()
        .and_then(|af_id| doc.get_dictionary(af_id).ok())
        .and_then(|af| af.get(b"Fields").and_then(Object::as_array).ok())
        .map(|arr| arr.iter().filter_map(|o| o.as_reference().ok()).collect())
        .unwrap_or_default();

    // 2. Allocate new object IDs
    let sig_id = max_id + 1; // signature value dict
    let field_id = max_id + 2; // widget annotation
    let acroform_id = max_id + 3; // AcroForm dict

    // 3. Build the incremental update incrementally, tracking byte offsets
    let orig_len = pdf_bytes.len();

    // Signature date string
    let date_str = pdf_date_now();

    // Fixed-width ByteRange placeholders — 12 digits each handles files up to ~1 TB
    // After computing real values we replace in-place (same byte count, space-padded)
    const BR_W: usize = 12;
    // Size of the CMS placeholder in bytes. DSS rejects if the placeholder is too small.
    // RSA-2048 CAdES B-B with signing-certificate-v2 ≈ 1300 bytes; 8 KB is safe headroom.
    const SIG_SIZE: usize = 8192;

    // --- Build each object as raw bytes ---

    // Signature value dict
    let sig_obj_bytes = sig_obj_bytes(sig_id, &date_str, BR_W, SIG_SIZE);

    // Widget annotation (invisible, 0×0 rectangle)
    let field_obj_bytes = field_obj_bytes(field_id, first_page_id, sig_id);

    // AcroForm dict
    let mut acroform_fields = existing_acroform_fields.clone();
    acroform_fields.push((field_id, 0));
    let acroform_obj_bytes = acroform_obj_bytes(acroform_id, &acroform_fields);

    // Updated page (with widget in /Annots)
    let mut annots = existing_annots.clone();
    annots.push((field_id, 0));
    let page_obj_bytes = updated_page_obj_bytes(first_page_id, page_dict, &annots);

    // Updated catalog (with /AcroForm)
    let catalog_obj_bytes = updated_catalog_obj_bytes(catalog_id, catalog_dict, acroform_id);

    // --- Assemble incremental update, tracking offsets for xref ---

    let mut update: Vec<u8> = Vec::new();
    update.extend_from_slice(b"\n");

    let sig_obj_off = orig_len + update.len();
    update.extend_from_slice(&sig_obj_bytes);

    let field_obj_off = orig_len + update.len();
    update.extend_from_slice(&field_obj_bytes);

    let acroform_obj_off = orig_len + update.len();
    update.extend_from_slice(&acroform_obj_bytes);

    let page_obj_off = orig_len + update.len();
    update.extend_from_slice(&page_obj_bytes);

    let cat_obj_off = orig_len + update.len();
    update.extend_from_slice(&catalog_obj_bytes);

    // --- Write xref + trailer ---

    let xref_start = orig_len + update.len();

    let mut xref_entries: Vec<(u32, usize)> = vec![
        (sig_id, sig_obj_off),
        (field_id, field_obj_off),
        (acroform_id, acroform_obj_off),
        (first_page_id.0, page_obj_off),
        (catalog_id.0, cat_obj_off),
    ];
    xref_entries.sort_by_key(|&(id, _)| id);

    update.extend_from_slice(b"xref\n");
    // Each run of contiguous IDs is a sub-section
    write_xref_sections(&mut update, &xref_entries);

    // Trailer
    let new_max_id = acroform_id + 1; // one past the highest ID we wrote
    let trailer = format!(
        "trailer\n<<\n/Size {}\n/Root {} 0 R\n/Prev {}\n>>\nstartxref\n{}\n%%EOF\n",
        new_max_id, catalog_id.0, prev_xref, xref_start
    );
    update.extend_from_slice(trailer.as_bytes());

    // 4. Assemble full PDF with placeholder
    let mut pdf_with_placeholder = Vec::with_capacity(pdf_bytes.len() + update.len());
    pdf_with_placeholder.extend_from_slice(pdf_bytes);
    pdf_with_placeholder.extend_from_slice(&update);

    // 5. Locate the /Contents hex-string placeholder in the assembled file.
    //    The placeholder is SIG_SIZE bytes of zeros → SIG_SIZE*2 hex '0' chars, enclosed in < >.
    let contents_marker: Vec<u8> = std::iter::once(b'<')
        .chain(std::iter::repeat_n(b'0', SIG_SIZE * 2))
        .chain(std::iter::once(b'>'))
        .collect();
    let lt_abs = find_subsequence(&pdf_with_placeholder, &contents_marker).ok_or(
        AdesError::NotImplemented("signature placeholder not found in PDF"),
    )?;

    // ByteRange: [0, lt_abs, gt_abs+1, rest_len]
    let gt_abs = lt_abs + 1 + SIG_SIZE * 2; // position of '>'
    let r1_len = lt_abs;
    let r2_start = gt_abs + 1;
    let r2_len = pdf_with_placeholder.len() - r2_start;

    // 6. Patch the /ByteRange placeholder values in-place.
    //    Our placeholder written by sig_obj_bytes() looks like:
    //    /ByteRange [000000000000 000000000000 000000000000 000000000000]
    //    Each field is exactly BR_W chars, space-padded on the left.
    let br_marker: Vec<u8> = byterange_placeholder_bytes(BR_W);
    let br_pos = find_subsequence(&pdf_with_placeholder, &br_marker).ok_or(
        AdesError::NotImplemented("/ByteRange placeholder not found in PDF"),
    )?;

    let br_actual = byterange_actual_bytes(BR_W, 0, r1_len, r2_start, r2_len);
    assert_eq!(
        br_marker.len(),
        br_actual.len(),
        "ByteRange replacement must maintain byte count"
    );
    pdf_with_placeholder[br_pos..br_pos + br_actual.len()].copy_from_slice(&br_actual);

    // 7. Compute digest over the signed byte ranges
    let digest_algo = signer.digest_algorithm();
    let signed_bytes: Vec<u8> = pdf_with_placeholder[..r1_len]
        .iter()
        .chain(pdf_with_placeholder[r2_start..].iter())
        .copied()
        .collect();
    let content_digest = digest_algo.hash(&signed_bytes);

    // 8. Build CMS SignedData (same structure as CAdES B-B)
    let cms = build_pades_cms(signer, &content_digest, digest_algo)?;

    // 9. Embed the CMS into the /Contents placeholder (hex-encoded)
    if cms.len() > SIG_SIZE {
        return Err(AdesError::NotImplemented(
            "CMS signature larger than reserved placeholder; increase SIG_SIZE",
        ));
    }
    let hex_cms: Vec<u8> = cms
        .iter()
        .flat_map(|b| format!("{:02X}", b).into_bytes())
        .collect();
    // Pad with zeros to fill the placeholder (SIG_SIZE * 2 hex chars)
    let mut padded_hex = vec![b'0'; SIG_SIZE * 2];
    padded_hex[..hex_cms.len()].copy_from_slice(&hex_cms);

    // Replace the all-zeros placeholder hex with the actual padded hex
    pdf_with_placeholder[lt_abs + 1..lt_abs + 1 + SIG_SIZE * 2].copy_from_slice(&padded_hex);

    Ok(pdf_with_placeholder)
}

// ---------------------------------------------------------------------------
// CMS builder for PAdES (reuses the CAdES B-B attribute structure)
// ---------------------------------------------------------------------------

fn build_pades_cms<S: Signer>(
    signer: &S,
    content_digest: &[u8],
    digest_algo: DigestAlgorithm,
) -> Result<Vec<u8>, AdesError>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    use cms::{
        cert::{CertificateChoices, IssuerAndSerialNumber},
        content_info::{CmsVersion, ContentInfo},
        signed_data::{
            CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
            SignerIdentifier, SignerInfo, SignerInfos,
        },
    };
    use const_oid::ObjectIdentifier;
    use der::{
        asn1::{OctetString, SetOfVec, UtcTime},
        Any, Decode, Encode,
    };
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::attr::Attribute;

    const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
    const ID_MESSAGE_DIGEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
    const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
    const ID_AA_SIGNING_CERT_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

    let cert = signer.certificate();

    // Signed attributes — identical to CAdES B-B
    let content_type_attr = Attribute {
        oid: ID_CONTENT_TYPE,
        values: {
            let mut set = SetOfVec::<Any>::new();
            set.insert(Any::encode_from(&ID_DATA)?)?;
            set
        },
    };

    let now_duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AdesError::NotImplemented("system time before unix epoch"))?;
    let signing_time = UtcTime::from_unix_duration(now_duration)?;
    let signing_time_attr = Attribute {
        oid: ID_SIGNING_TIME,
        values: {
            let mut set = SetOfVec::<Any>::new();
            set.insert(Any::encode_from(&signing_time)?)?;
            set
        },
    };

    let message_digest_attr = Attribute {
        oid: ID_MESSAGE_DIGEST,
        values: {
            let mut set = SetOfVec::<Any>::new();
            let octet = OctetString::new(content_digest)?;
            set.insert(Any::encode_from(&octet)?)?;
            set
        },
    };

    let sc_v2_der = build_signing_cert_v2_der(cert.to_der())?;
    let signing_cert_attr = Attribute {
        oid: ID_AA_SIGNING_CERT_V2,
        values: {
            let mut set = SetOfVec::<Any>::new();
            set.insert(Any::from_der(&sc_v2_der)?)?;
            set
        },
    };

    let mut signed_attrs = SetOfVec::<Attribute>::new();
    signed_attrs.insert(content_type_attr)?;
    signed_attrs.insert(signing_time_attr)?;
    signed_attrs.insert(message_digest_attr)?;
    signed_attrs.insert(signing_cert_attr)?;

    let signed_attrs_der = signed_attrs.to_der()?;
    let signing_digest = digest_algo.hash(&signed_attrs_der);
    let signature_bytes = signer
        .sign_digest(&signing_digest)
        .map_err(|e| AdesError::Signer(Box::new(e)))?;

    let x509 = cert.inner();
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: x509.tbs_certificate.issuer.clone(),
        serial_number: x509.tbs_certificate.serial_number.clone(),
    });

    let digest_alg_id = AlgorithmIdentifierOwned {
        oid: digest_algo.oid(),
        parameters: None,
    };

    let key_alg_oid = x509.tbs_certificate.subject_public_key_info.algorithm.oid;
    let sig_alg_id = signature_algorithm_id(key_alg_oid, digest_algo)?;

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg: digest_alg_id.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: sig_alg_id,
        signature: OctetString::new(signature_bytes.as_slice())?,
        unsigned_attrs: None,
    };

    let mut digest_algorithms = DigestAlgorithmIdentifiers::new();
    digest_algorithms.insert(digest_alg_id)?;

    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };

    let cert_choice =
        CertificateChoices::Certificate(x509_cert::Certificate::from_der(cert.to_der())?);
    let mut certificates = CertificateSet(Default::default());
    certificates.0.insert(cert_choice)?;

    let mut signer_infos = SignerInfos(Default::default());
    signer_infos.0.insert(signer_info)?;

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info,
        certificates: Some(certificates),
        crls: None,
        signer_infos,
    };

    let signed_data_der = signed_data.to_der()?;
    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der)?,
    };

    Ok(content_info.to_der()?)
}

/// Builds the DER encoding of `SigningCertificateV2` (RFC 5035).
fn build_signing_cert_v2_der(cert_der: &[u8]) -> Result<Vec<u8>, AdesError> {
    use sha2::{Digest, Sha256};

    let hash: [u8; 32] = Sha256::digest(cert_der).into();

    let tlv = |tag: u8, value: &[u8]| -> Vec<u8> {
        let len = value.len();
        let mut out = vec![tag];
        if len < 128 {
            out.push(len as u8);
        } else if len < 256 {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        out.extend_from_slice(value);
        out
    };

    let hash_os = tlv(0x04, hash.as_slice());
    let ess_cert_id = tlv(0x30, &hash_os);
    let certs_seq = tlv(0x30, &ess_cert_id);
    Ok(tlv(0x30, &certs_seq))
}

// ---------------------------------------------------------------------------
// PDF object builders
// ---------------------------------------------------------------------------

fn sig_obj_bytes(id: u32, date: &str, br_w: usize, sig_size: usize) -> Vec<u8> {
    let br = byterange_placeholder_bytes(br_w);
    let br_str = String::from_utf8(br).expect("ascii");
    let hex_placeholder = "0".repeat(sig_size * 2);
    format!(
        "{id} 0 obj\n<<\n\
         /Type /Sig\n\
         /Filter /Adobe.PPKLite\n\
         /SubFilter /ETSI.CAdES.detached\n\
         /ByteRange {br_str}\n\
         /Contents <{hex_placeholder}>\n\
         /M ({date})\n\
         >>\nendobj\n"
    )
    .into_bytes()
}

fn field_obj_bytes(id: u32, page_id: (u32, u16), sig_id: u32) -> Vec<u8> {
    format!(
        "{id} 0 obj\n<<\n\
         /Type /Annot\n\
         /Subtype /Widget\n\
         /FT /Sig\n\
         /Rect [0 0 0 0]\n\
         /P {} 0 R\n\
         /T (Signature1)\n\
         /V {sig_id} 0 R\n\
         /F 132\n\
         >>\nendobj\n",
        page_id.0
    )
    .into_bytes()
}

fn acroform_obj_bytes(id: u32, fields: &[(u32, u16)]) -> Vec<u8> {
    let refs: String = fields.iter().map(|&(n, _)| format!("{n} 0 R ")).collect();
    format!(
        "{id} 0 obj\n<<\n\
         /Fields [{refs}]\n\
         /SigFlags 3\n\
         >>\nendobj\n"
    )
    .into_bytes()
}

fn updated_page_obj_bytes(
    id: (u32, u16),
    page: &lopdf::Dictionary,
    annots: &[(u32, u16)],
) -> Vec<u8> {
    let refs: String = annots.iter().map(|&(n, _)| format!("{n} 0 R ")).collect();
    // Re-emit the page dict, replacing (or adding) /Annots
    let mut dict_lines: Vec<String> = page
        .iter()
        .filter(|(k, _)| k.as_slice() != b"Annots")
        .map(|(k, v)| format!("/{} {}", String::from_utf8_lossy(k), pdf_obj_str(v)))
        .collect();
    dict_lines.push(format!("/Annots [{refs}]"));

    format!(
        "{} 0 obj\n<<\n{}\n>>\nendobj\n",
        id.0,
        dict_lines.join("\n")
    )
    .into_bytes()
}

fn updated_catalog_obj_bytes(
    id: (u32, u16),
    catalog: &lopdf::Dictionary,
    acroform_id: u32,
) -> Vec<u8> {
    let mut dict_lines: Vec<String> = catalog
        .iter()
        .filter(|(k, _)| k.as_slice() != b"AcroForm")
        .map(|(k, v)| format!("/{} {}", String::from_utf8_lossy(k), pdf_obj_str(v)))
        .collect();
    dict_lines.push(format!("/AcroForm {acroform_id} 0 R"));

    format!(
        "{} 0 obj\n<<\n{}\n>>\nendobj\n",
        id.0,
        dict_lines.join("\n")
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// xref helpers
// ---------------------------------------------------------------------------

fn write_xref_sections(out: &mut Vec<u8>, entries: &[(u32, usize)]) {
    if entries.is_empty() {
        return;
    }
    // Group into contiguous runs
    let mut i = 0;
    while i < entries.len() {
        let start_id = entries[i].0;
        let mut j = i + 1;
        while j < entries.len() && entries[j].0 == entries[j - 1].0 + 1 {
            j += 1;
        }
        let count = j - i;
        out.extend_from_slice(format!("{start_id} {count}\n").as_bytes());
        for &(_, offset) in &entries[i..j] {
            out.extend_from_slice(format!("{:010} 00000 n \n", offset).as_bytes());
        }
        i = j;
    }
}

// ---------------------------------------------------------------------------
// ByteRange placeholder / replacement
// ---------------------------------------------------------------------------

fn byterange_placeholder_bytes(br_w: usize) -> Vec<u8> {
    // Format: [000000000000 000000000000 000000000000 000000000000]
    // Each number is br_w zeros; separated by spaces; enclosed in []
    let field = "0".repeat(br_w);
    format!("[{field} {field} {field} {field}]").into_bytes()
}

fn byterange_actual_bytes(br_w: usize, r1s: usize, r1l: usize, r2s: usize, r2l: usize) -> Vec<u8> {
    // Same total byte count as byterange_placeholder_bytes()
    // Pad each value with leading spaces to br_w chars
    format!(
        "[{:>w$} {:>w$} {:>w$} {:>w$}]",
        r1s,
        r1l,
        r2s,
        r2l,
        w = br_w
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn pdf_date_now() -> String {
    // D:YYYYMMDDHHmmSSZ  (UTC, no timezone offset)
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = epoch_to_ymd_hms(secs);
    format!("D:{:04}{:02}{:02}{:02}{:02}{:02}Z", y, mo, d, h, mi, s)
}

fn epoch_to_ymd_hms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Gregorian calendar computation (Rata Die from 1970-01-01)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (
        year as u32,
        month as u32,
        day as u32,
        h as u32,
        m as u32,
        s as u32,
    )
}

/// Minimal PDF object to string (for re-emitting dict values).
fn pdf_obj_str(obj: &lopdf::Object) -> String {
    use lopdf::Object;
    match obj {
        Object::Integer(n) => n.to_string(),
        Object::Real(f) => format!("{f}"),
        Object::Boolean(b) => if *b { "true" } else { "false" }.to_string(),
        Object::Name(n) => format!("/{}", String::from_utf8_lossy(n)),
        Object::String(s, lopdf::StringFormat::Literal) => {
            format!("({})", String::from_utf8_lossy(s))
        }
        Object::String(s, _) => {
            let hex: String = s.iter().map(|b| format!("{:02X}", b)).collect();
            format!("<{hex}>")
        }
        Object::Array(arr) => {
            let items: Vec<String> = arr.iter().map(pdf_obj_str).collect();
            format!("[{}]", items.join(" "))
        }
        Object::Reference((n, g)) => format!("{n} {g} R"),
        Object::Null => "null".to_string(),
        Object::Dictionary(_) | Object::Stream(_) => "<<>>".to_string(), // not expected inline
    }
}
