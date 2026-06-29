use crate::{error::AdesError, levels, signer::Signer, tsp::TspClient};

/// Produces a PAdES B-T signature: B-B + a signature timestamp from a TSA.
///
/// # Errors
///
/// Returns [`AdesError`] if signing, the TSA request, or PDF/CMS re-encoding fails.
///
/// # Example
///
/// ```no_run
/// use ades::{pades, signer::SoftSigner, tsp::TspClient};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let tsa = TspClient::new("https://freetsa.org/tsr");
/// let pdf = std::fs::read("document.pdf").unwrap();
/// let signed = pades::sign_t(&pdf, &signer, &tsa).unwrap();
/// ```
#[cfg(all(feature = "pades", feature = "tsp"))]
pub fn sign_t<S>(pdf: &[u8], signer: &S, tsa: &TspClient) -> Result<Vec<u8>, AdesError>
where
    S: Signer,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    // 1. B-B signed PDF
    let bb_pdf = crate::pades::sign(pdf, signer)?;

    // 2. Extract the embedded CMS from the /Contents hex field
    let cms_der = extract_cms_from_pdf(&bb_pdf)?;

    // 3. Extract SignatureValue to timestamp
    let sig_value = extract_signature_value(&cms_der)?;
    let digest_algo = signer.digest_algorithm();
    let hash = digest_algo.hash(&sig_value);
    let tst = tsa.timestamp(&hash, digest_algo)?;

    // 4. Upgrade CMS to B-T
    let bt_cms = levels::add_signature_timestamp(&cms_der, &tst)?;

    // 5. Re-embed the larger CMS back into the PDF
    replace_cms_in_pdf(bb_pdf, &bt_cms)
}

/// Produces a PAdES B-LT signature: B-T + embedded revocation data.
///
/// # Errors
///
/// Returns [`AdesError`] if any step fails.
///
/// # Example
///
/// ```no_run
/// use ades::{pades, signer::SoftSigner, tsp::TspClient, ocsp::OcspClient};
///
/// let signer = SoftSigner::generate(2048).unwrap();
/// let tsa = TspClient::new("https://freetsa.org/tsr");
/// let ocsp = OcspClient::new();
/// let pdf = std::fs::read("document.pdf").unwrap();
/// let signed = pades::sign_lt(&pdf, &signer, &tsa, &ocsp).unwrap();
/// ```
#[cfg(all(feature = "pades", feature = "tsp", feature = "ocsp"))]
pub fn sign_lt<S>(
    pdf: &[u8],
    signer: &S,
    tsa: &TspClient,
    ocsp: &crate::ocsp::OcspClient,
) -> Result<Vec<u8>, AdesError>
where
    S: Signer,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let bt_pdf = sign_t(pdf, signer, tsa)?;
    let cms_der = extract_cms_from_pdf(&bt_pdf)?;

    let cert = signer.certificate();
    let ocsp_resp = match ocsp.raw_response(cert, cert) {
        Ok(r) => r,
        Err(AdesError::Ocsp(_)) => return Ok(bt_pdf),
        Err(e) => return Err(e),
    };

    let lt_cms = levels::add_revocation_values(&cms_der, &ocsp_resp)?;
    replace_cms_in_pdf(bt_pdf, &lt_cms)
}

// ---------------------------------------------------------------------------
// PDF CMS extraction and replacement
// ---------------------------------------------------------------------------

/// Extracts the CMS `ContentInfo` bytes from the `/Contents` hex string of the
/// first signature field in a signed PDF.
fn extract_cms_from_pdf(pdf: &[u8]) -> Result<Vec<u8>, AdesError> {
    // Find /Contents < ... > — the hex-encoded CMS bytes
    let marker = b"/Contents <";
    let start =
        pdf.windows(marker.len())
            .position(|w| w == marker)
            .ok_or(AdesError::NotImplemented(
                "cannot find /Contents in signed PDF",
            ))?;

    let hex_start = start + marker.len();
    let hex_end =
        pdf[hex_start..]
            .iter()
            .position(|&b| b == b'>')
            .ok_or(AdesError::NotImplemented(
                "unterminated /Contents hex string",
            ))?
            + hex_start;

    // Hex-decode the full placeholder into bytes first
    let hex_bytes = &pdf[hex_start..hex_end];
    if !hex_bytes.len().is_multiple_of(2) {
        return Err(AdesError::NotImplemented("/Contents hex has odd length"));
    }
    let raw: Vec<u8> = hex_bytes
        .chunks(2)
        .filter_map(|h| {
            let s = std::str::from_utf8(h).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect();

    if raw.is_empty() || raw[0] != 0x30 {
        return Err(AdesError::NotImplemented(
            "/Contents does not contain a DER SEQUENCE",
        ));
    }

    // Use the DER length to know exactly how many bytes the CMS occupies,
    // instead of trimming trailing zeros (which would corrupt CMS bytes ending in 0x00).
    let cms_len = der_content_info_len(&raw)?;
    Ok(raw[..cms_len].to_vec())
}

/// Replaces the /Contents hex in `pdf` with the new CMS bytes.
///
/// The new CMS must fit in the existing placeholder (same size or smaller).
/// If it doesn't fit this returns an error — the B-B sign allocated 8 KiB
/// of placeholder which is sufficient for B-T (adds ~4-5 KiB TST).
fn replace_cms_in_pdf(mut pdf: Vec<u8>, new_cms: &[u8]) -> Result<Vec<u8>, AdesError> {
    let marker = b"/Contents <";
    let start =
        pdf.windows(marker.len())
            .position(|w| w == marker)
            .ok_or(AdesError::NotImplemented(
                "cannot find /Contents in signed PDF",
            ))?;

    let hex_start = start + marker.len();
    let hex_end =
        pdf[hex_start..]
            .iter()
            .position(|&b| b == b'>')
            .ok_or(AdesError::NotImplemented(
                "unterminated /Contents hex string",
            ))?
            + hex_start;

    let placeholder_len = hex_end - hex_start; // in hex chars
    let needed = new_cms.len() * 2;

    if needed > placeholder_len {
        return Err(AdesError::NotImplemented(
            "new CMS is too large for the /Contents placeholder; increase SIG_SIZE in pades::sign",
        ));
    }

    // Hex-encode new CMS and pad with zeros to fill the placeholder
    let mut hex_new: Vec<u8> = new_cms
        .iter()
        .flat_map(|b| format!("{:02X}", b).into_bytes())
        .collect();
    hex_new.resize(placeholder_len, b'0');

    pdf[hex_start..hex_end].copy_from_slice(&hex_new);

    // NOTE: The ByteRange is still valid — we're only changing bytes inside
    // the /Contents placeholder, which is already excluded from the signed ranges.
    Ok(pdf)
}

/// Returns the total byte length of the DER-encoded `ContentInfo` SEQUENCE
/// starting at `data[0]`, using the DER length field — not zero-trimming.
fn der_content_info_len(data: &[u8]) -> Result<usize, AdesError> {
    if data.is_empty() || data[0] != 0x30 {
        return Err(AdesError::NotImplemented("not a DER SEQUENCE"));
    }
    let (content_len, header_end) = der_decode_len_at(data, 1)?;
    Ok(header_end + content_len)
}

fn der_decode_len_at(data: &[u8], offset: usize) -> Result<(usize, usize), AdesError> {
    let err = || AdesError::NotImplemented("malformed DER length");
    let b = *data.get(offset).ok_or_else(err)?;
    if b < 0x80 {
        return Ok((b as usize, offset + 1));
    }
    let n = (b & 0x7f) as usize;
    if n == 0 || n > 4 || data.len() <= offset + n {
        return Err(err());
    }
    let mut len = 0usize;
    for i in 1..=n {
        len = (len << 8) | data[offset + i] as usize;
    }
    Ok((len, offset + 1 + n))
}

/// Extracts the `SignatureValue` OCTET STRING bytes from a CMS `ContentInfo`.
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
