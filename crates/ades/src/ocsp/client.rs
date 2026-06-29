use crate::{certificate::Certificate, error::AdesError};
use x509_cert::Certificate as X509Certificate;

/// Revocation status returned by an OCSP responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspStatus {
    /// Certificate is valid and not revoked.
    Good,
    /// Certificate has been revoked.
    Revoked,
    /// Responder does not know the status of the certificate.
    Unknown,
}

/// RFC 6960 OCSP client.
///
/// Queries an OCSP responder for the revocation status of a certificate.
/// The OCSP URL is either provided explicitly or extracted from the
/// certificate's Authority Information Access (AIA) extension.
///
/// # Example
///
/// ```no_run
/// use ades::ocsp::OcspClient;
///
/// // provide cert and its issuer cert
/// # let cert_der = &[][..];
/// # let issuer_der = &[][..];
/// use ades::Certificate;
/// let cert = Certificate::from_der(cert_der).unwrap();
/// let issuer = Certificate::from_der(issuer_der).unwrap();
///
/// let client = OcspClient::new();
/// let status = client.check(&cert, &issuer).unwrap();
/// ```
#[cfg(feature = "ocsp")]
pub struct OcspClient {
    /// Override URL; if `None`, extracted from the certificate AIA extension.
    url_override: Option<String>,
}

#[cfg(feature = "ocsp")]
impl OcspClient {
    /// Creates a new OCSP client that uses the URL from the certificate's AIA extension.
    #[must_use]
    pub fn new() -> Self {
        Self { url_override: None }
    }

    /// Creates a new OCSP client with an explicit responder URL (ignores AIA).
    #[must_use]
    pub fn with_url(url: &str) -> Self {
        Self {
            url_override: Some(url.to_owned()),
        }
    }

    /// Queries the OCSP responder for the revocation status of `cert`.
    ///
    /// `issuer` must be the direct issuer of `cert` (used to compute the
    /// `CertID` hash fields per RFC 6960 §4.1.1).
    ///
    /// # Errors
    ///
    /// Returns [`AdesError`] if the AIA extension is absent (when no URL
    /// override is set), the HTTP request fails, or the response cannot be
    /// parsed.
    pub fn check(&self, cert: &Certificate, issuer: &Certificate) -> Result<OcspStatus, AdesError> {
        let url = match &self.url_override {
            Some(u) => u.clone(),
            None => extract_ocsp_url(cert.inner())
                .ok_or_else(|| AdesError::Ocsp("no OCSP URL in certificate AIA".to_owned()))?,
        };

        let req_der = build_ocsp_req(cert.inner(), issuer.inner())?;
        let resp_der = self.post(&url, &req_der)?;
        parse_ocsp_resp(&resp_der)
    }

    /// Like [`check`](Self::check) but returns the raw `OCSPResponse` DER bytes
    /// for embedding in a B-LT signature (`id-aa-ets-revocationValues`).
    ///
    /// # Errors
    ///
    /// Returns [`AdesError`] if the AIA extension is absent or the request fails.
    pub fn raw_response(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<Vec<u8>, AdesError> {
        let url = match &self.url_override {
            Some(u) => u.clone(),
            None => extract_ocsp_url(cert.inner())
                .ok_or_else(|| AdesError::Ocsp("no OCSP URL in certificate AIA".to_owned()))?,
        };
        let req_der = build_ocsp_req(cert.inner(), issuer.inner())?;
        self.post(&url, &req_der)
    }

    fn post(&self, url: &str, req_der: &[u8]) -> Result<Vec<u8>, AdesError> {
        let resp = ureq::post(url)
            .set("Content-Type", "application/ocsp-request")
            .send_bytes(req_der)
            .map_err(|e| AdesError::Ocsp(e.to_string()))?;

        let mut body = Vec::new();
        resp.into_reader()
            .read_to_end(&mut body)
            .map_err(|e| AdesError::Ocsp(e.to_string()))?;

        Ok(body)
    }
}

#[cfg(feature = "ocsp")]
impl Default for OcspClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AIA URL extraction
// ---------------------------------------------------------------------------

/// Extracts the first OCSP URL from the certificate's AIA extension, if present.
fn extract_ocsp_url(cert: &X509Certificate) -> Option<String> {
    use der::Decode;
    use x509_cert::ext::pkix::{name::GeneralName, AccessDescription, AuthorityInfoAccessSyntax};

    // OID for id-ad-ocsp
    const ID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";

    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id.to_string() != "1.3.6.1.5.5.7.1.1" {
            // Not the AIA extension (id-pe-authorityInfoAccess)
            continue;
        }
        let aia = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()).ok()?;
        for AccessDescription {
            access_method,
            access_location,
        } in aia.0.iter()
        {
            if access_method.to_string() == ID_AD_OCSP {
                if let GeneralName::UniformResourceIdentifier(uri) = access_location {
                    return Some(uri.to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// OCSPRequest builder (RFC 6960 §4.1)
// ---------------------------------------------------------------------------

/// Builds a minimal DER-encoded `OCSPRequest`:
///
/// ```asn1
/// OCSPRequest ::= SEQUENCE {
///    tbsRequest  TBSRequest
/// }
/// TBSRequest ::= SEQUENCE {
///    requestList  SEQUENCE OF Request
/// }
/// Request ::= SEQUENCE {
///    reqCert  CertID
/// }
/// CertID ::= SEQUENCE {
///    hashAlgorithm  AlgorithmIdentifier,  -- SHA-1 (required by most responders)
///    issuerNameHash OCTET STRING,
///    issuerKeyHash  OCTET STRING,
///    serialNumber   INTEGER
/// }
/// ```
///
/// Most OCSP responders still require SHA-1 for the CertID hash fields
/// (RFC 6960 §4.1.1 recommends it for interoperability).
fn build_ocsp_req(cert: &X509Certificate, issuer: &X509Certificate) -> Result<Vec<u8>, AdesError> {
    use der::Encode;
    use sha1::Digest as _;

    // issuerNameHash: SHA-1 of the DER encoding of the issuer's subject name
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| AdesError::Ocsp(e.to_string()))?;
    let issuer_name_hash = sha1::Sha1::digest(&issuer_name_der);

    // issuerKeyHash: SHA-1 of the BIT STRING value of the issuer's public key
    // (the raw subjectPublicKey bits, without the BIT STRING tag/length wrapper)
    let issuer_spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let issuer_key_hash = sha1::Sha1::digest(issuer_spki_der);

    // serialNumber: integer bytes of the cert serial
    let serial_der = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|e| AdesError::Ocsp(e.to_string()))?;

    // SHA-1 AlgorithmIdentifier: OID 1.3.14.3.2.26, NULL params
    let sha1_oid_bytes = [
        0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, // OID 1.3.14.3.2.26
        0x05, 0x00, // NULL
    ];
    let hash_alg = der_tlv(0x30, &sha1_oid_bytes);

    let name_hash_os = der_tlv(0x04, &issuer_name_hash);
    let key_hash_os = der_tlv(0x04, &issuer_key_hash);

    let cert_id = der_tlv(
        0x30,
        &[
            hash_alg.as_slice(),
            &name_hash_os,
            &key_hash_os,
            &serial_der, // already DER INTEGER
        ]
        .concat(),
    );

    let request = der_tlv(0x30, &cert_id);
    let request_list = der_tlv(0x30, &request);
    let tbs_request = der_tlv(0x30, &request_list);
    Ok(der_tlv(0x30, &tbs_request))
}

// ---------------------------------------------------------------------------
// OCSPResponse parser (RFC 6960 §4.2)
// ---------------------------------------------------------------------------

/// Parses an `OCSPResponse` and returns the certificate status.
///
/// ```asn1
/// OCSPResponse ::= SEQUENCE {
///    responseStatus         OCSPResponseStatus,   -- ENUMERATED
///    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL
/// }
/// BasicOCSPResponse ::= SEQUENCE {
///    tbsResponseData  ResponseData,
///    ...
/// }
/// ResponseData ::= SEQUENCE {
///    version    [0] EXPLICIT INTEGER DEFAULT v1,
///    ...
///    responses  SEQUENCE OF SingleResponse
/// }
/// SingleResponse ::= SEQUENCE {
///    certID    CertID,
///    certStatus CertStatus,   -- CHOICE
///    ...
/// }
/// CertStatus ::= CHOICE {
///    good    [0] IMPLICIT NULL,
///    revoked [1] IMPLICIT RevokedInfo,
///    unknown [2] IMPLICIT UnknownInfo
/// }
/// ```
fn parse_ocsp_resp(resp_der: &[u8]) -> Result<OcspStatus, AdesError> {
    // Outer OCSPResponse SEQUENCE
    let outer = der_unwrap_seq(resp_der)
        .ok_or_else(|| AdesError::Ocsp("invalid OCSPResponse: not a SEQUENCE".to_owned()))?;

    // responseStatus ENUMERATED (tag 0x0a)
    let (status_tlv, rest) =
        der_next_tlv(outer).ok_or_else(|| AdesError::Ocsp("missing responseStatus".to_owned()))?;

    let response_status = *status_tlv
        .last()
        .ok_or_else(|| AdesError::Ocsp("empty responseStatus".to_owned()))?;

    // OCSPResponseStatus: 0 = successful
    if response_status != 0 {
        return Err(AdesError::Ocsp(format!(
            "OCSP responder returned status {response_status}"
        )));
    }

    // responseBytes [0] EXPLICIT SEQUENCE { responseType OID, response OCTET STRING }
    // Tag is 0xa0 (context [0] constructed)
    if rest.is_empty() || rest[0] != 0xa0 {
        return Err(AdesError::Ocsp(
            "OCSPResponse missing responseBytes".to_owned(),
        ));
    }
    let (resp_bytes_ctx, _) =
        der_next_tlv(rest).ok_or_else(|| AdesError::Ocsp("invalid responseBytes".to_owned()))?;

    // Unwrap [0] explicit: skip tag+len to get the inner SEQUENCE
    let resp_bytes_inner = der_strip_explicit_tag(resp_bytes_ctx)
        .ok_or_else(|| AdesError::Ocsp("cannot unwrap responseBytes [0]".to_owned()))?;

    let (resp_bytes_seq, _) = der_next_tlv(resp_bytes_inner)
        .ok_or_else(|| AdesError::Ocsp("invalid ResponseBytes SEQUENCE".to_owned()))?;

    let resp_bytes_contents = der_unwrap_seq(resp_bytes_seq)
        .ok_or_else(|| AdesError::Ocsp("ResponseBytes not a SEQUENCE".to_owned()))?;

    // Skip responseType OID, get the response OCTET STRING
    let (_, after_oid) = der_next_tlv(resp_bytes_contents)
        .ok_or_else(|| AdesError::Ocsp("missing responseType OID".to_owned()))?;

    let (resp_octet_tlv, _) = der_next_tlv(after_oid)
        .ok_or_else(|| AdesError::Ocsp("missing response OCTET STRING".to_owned()))?;

    // The OCTET STRING contains a DER-encoded BasicOCSPResponse
    let basic_resp_der = der_octet_string_value(resp_octet_tlv)
        .ok_or_else(|| AdesError::Ocsp("response is not an OCTET STRING".to_owned()))?;

    // BasicOCSPResponse SEQUENCE → tbsResponseData SEQUENCE → responses SEQUENCE OF
    let basic_contents = der_unwrap_seq(basic_resp_der)
        .ok_or_else(|| AdesError::Ocsp("BasicOCSPResponse not a SEQUENCE".to_owned()))?;

    // First element: ResponseData SEQUENCE
    let (tbs_data_tlv, _) = der_next_tlv(basic_contents)
        .ok_or_else(|| AdesError::Ocsp("missing tbsResponseData".to_owned()))?;

    let tbs_contents = der_unwrap_seq(tbs_data_tlv)
        .ok_or_else(|| AdesError::Ocsp("tbsResponseData not a SEQUENCE".to_owned()))?;

    // ResponseData may start with [0] version (optional) or [1]/[2] responderID
    // Then producedAt GeneralizedTime, then responses SEQUENCE OF SingleResponse
    // Walk elements until we find a SEQUENCE (the responses field)
    let responses_seq = find_responses_seq(tbs_contents)
        .ok_or_else(|| AdesError::Ocsp("missing responses in ResponseData".to_owned()))?;

    let responses_contents = der_unwrap_seq(responses_seq)
        .ok_or_else(|| AdesError::Ocsp("responses not a SEQUENCE".to_owned()))?;

    // First SingleResponse
    let (single_resp_tlv, _) = der_next_tlv(responses_contents)
        .ok_or_else(|| AdesError::Ocsp("empty responses list".to_owned()))?;

    let single_contents = der_unwrap_seq(single_resp_tlv)
        .ok_or_else(|| AdesError::Ocsp("SingleResponse not a SEQUENCE".to_owned()))?;

    // Skip CertID SEQUENCE, get certStatus CHOICE
    let (_, after_cert_id) = der_next_tlv(single_contents)
        .ok_or_else(|| AdesError::Ocsp("missing certID in SingleResponse".to_owned()))?;

    let (cert_status_tlv, _) = der_next_tlv(after_cert_id)
        .ok_or_else(|| AdesError::Ocsp("missing certStatus in SingleResponse".to_owned()))?;

    // CertStatus CHOICE tag:
    //   [0] IMPLICIT NULL  → good   (tag 0x80)
    //   [1] IMPLICIT       → revoked (tag 0xa1, constructed)
    //   [2] IMPLICIT NULL  → unknown (tag 0x82)
    let status_tag = cert_status_tlv
        .first()
        .copied()
        .ok_or_else(|| AdesError::Ocsp("empty certStatus".to_owned()))?;

    Ok(match status_tag {
        0x80 => OcspStatus::Good,
        0xa1 => OcspStatus::Revoked,
        0x82 => OcspStatus::Unknown,
        other => {
            return Err(AdesError::Ocsp(format!(
                "unknown certStatus tag 0x{other:02x}"
            )))
        }
    })
}

/// Walks the elements of `data` and returns the first SEQUENCE OF (the responses field).
/// ResponseData structure: [version] responderID producedAt responses [responseExtensions]
fn find_responses_seq(data: &[u8]) -> Option<&[u8]> {
    let mut pos = data;
    // Responses is the first plain SEQUENCE (0x30) we encounter after
    // skipping any context-tagged elements ([0], [1], [2]) and GeneralizedTime (0x18).
    while !pos.is_empty() {
        let tag = *pos.first()?;
        let (tlv, rest) = der_next_tlv(pos)?;
        match tag {
            0x30 => return Some(tlv), // found the responses SEQUENCE OF
            _ => pos = rest,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Minimal DER helpers (shared with tsp/client.rs via copy — kept simple)
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

fn der_unwrap_seq(data: &[u8]) -> Option<&[u8]> {
    if data.first()? != &0x30 {
        return None;
    }
    let (len, contents) = der_decode_len(&data[1..])?;
    if contents.len() < len {
        return None;
    }
    Some(&contents[..len])
}

fn der_next_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let (len, contents) = der_decode_len(&data[1..])?;
    let header_size = contents.as_ptr() as usize - data.as_ptr() as usize;
    let end = header_size + len;
    if end > data.len() {
        return None;
    }
    Some((&data[..end], &data[end..]))
}

/// Strips an explicit context tag (0xa0–0xbf) and returns the inner bytes.
fn der_strip_explicit_tag(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    let (len, contents) = der_decode_len(&data[1..])?;
    if contents.len() < len {
        return None;
    }
    Some(&contents[..len])
}

/// Returns the value bytes of a DER OCTET STRING TLV, or `None` if not one.
fn der_octet_string_value(data: &[u8]) -> Option<&[u8]> {
    if data.first()? != &0x04 {
        return None;
    }
    let (len, contents) = der_decode_len(&data[1..])?;
    if contents.len() < len {
        return None;
    }
    Some(&contents[..len])
}

fn der_decode_len(data: &[u8]) -> Option<(usize, &[u8])> {
    let first = *data.first()?;
    if first < 0x80 {
        return Some((first as usize, &data[1..]));
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || data.len() <= num_bytes {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[1..=num_bytes] {
        len = (len << 8) | b as usize;
    }
    Some((len, &data[1 + num_bytes..]))
}
