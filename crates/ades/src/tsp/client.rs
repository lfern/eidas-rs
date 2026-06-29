use crate::{digest::DigestAlgorithm, error::AdesError};

/// TSA URL for FreeTSA — free, no authentication required.
pub const FREETSA_URL: &str = "https://freetsa.org/tsr";

/// RFC 3161 Time-Stamp Protocol client.
///
/// Sends a hash to a TSA (Time Stamping Authority) and receives a
/// `TimeStampToken` — a CMS `ContentInfo` wrapping a `TSTInfo` — that
/// proves the hash existed at the time of stamping.
///
/// # Example
///
/// ```no_run
/// use ades::tsp::TspClient;
/// use ades::DigestAlgorithm;
///
/// let client = TspClient::new("https://freetsa.org/tsr");
/// let hash = DigestAlgorithm::Sha256.hash(b"hello world");
/// let token = client.timestamp(&hash, DigestAlgorithm::Sha256).unwrap();
/// // token is DER-encoded CMS ContentInfo (TimeStampToken)
/// ```
#[cfg(feature = "tsp")]
pub struct TspClient {
    url: String,
}

#[cfg(feature = "tsp")]
impl TspClient {
    /// Creates a new TSP client for the given TSA URL.
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
        }
    }

    /// Sends a `TimeStampReq` to the TSA and returns the raw DER bytes of the
    /// `TimeStampToken` (CMS `ContentInfo`).
    ///
    /// # Errors
    ///
    /// Returns [`AdesError`] if request encoding, HTTP transport, or response
    /// parsing fails.
    pub fn timestamp(&self, hash: &[u8], algo: DigestAlgorithm) -> Result<Vec<u8>, AdesError> {
        let req_der = build_ts_req(hash, algo)?;
        let resp_der = self.post(&req_der)?;
        extract_token(&resp_der)
    }

    fn post(&self, req_der: &[u8]) -> Result<Vec<u8>, AdesError> {
        let resp = ureq::post(&self.url)
            .set("Content-Type", "application/timestamp-query")
            .send_bytes(req_der)
            .map_err(|e| AdesError::Tsp(e.to_string()))?;

        let mut body = Vec::new();
        resp.into_reader()
            .read_to_end(&mut body)
            .map_err(|e| AdesError::Tsp(e.to_string()))?;

        Ok(body)
    }
}

// ---------------------------------------------------------------------------
// RFC 3161 DER encoding
// ---------------------------------------------------------------------------

/// Builds a minimal `TimeStampReq` (RFC 3161 §2.4.1):
///
/// ```asn1
/// TimeStampReq ::= SEQUENCE {
///    version          INTEGER { v1(1) },
///    messageImprint   MessageImprint,
///    certReq          BOOLEAN DEFAULT FALSE   -- we set TRUE
/// }
/// MessageImprint ::= SEQUENCE {
///    hashAlgorithm    AlgorithmIdentifier,
///    hashedMessage    OCTET STRING
/// }
/// ```
fn build_ts_req(hash: &[u8], algo: DigestAlgorithm) -> Result<Vec<u8>, AdesError> {
    // AlgorithmIdentifier: SEQUENCE { OID, NULL }
    let oid = algo.oid();
    let alg_oid = der_tlv(0x06, oid.as_bytes()); // OID
    let alg_null = [0x05u8, 0x00]; // NULL
    let alg_seq = der_tlv(0x30, &[alg_oid.as_slice(), &alg_null].concat()); // SEQUENCE

    // MessageImprint: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    let hash_os = der_tlv(0x04, hash); // OCTET STRING
    let msg_imprint = der_tlv(0x30, &[alg_seq.as_slice(), hash_os.as_slice()].concat());

    // version INTEGER = 1
    let version = [0x02u8, 0x01, 0x01]; // INTEGER 1

    // certReq BOOLEAN = TRUE
    let cert_req = [0x01u8, 0x01, 0xff]; // BOOLEAN TRUE

    // TimeStampReq SEQUENCE
    let body = [version.as_slice(), &msg_imprint, &cert_req].concat();
    Ok(der_tlv(0x30, &body))
}

/// Parses a `TimeStampResp` (RFC 3161 §2.4.2) and returns the
/// `TimeStampToken` bytes (the second element of the outer SEQUENCE).
///
/// ```asn1
/// TimeStampResp ::= SEQUENCE {
///    status           PKIStatusInfo,
///    timeStampToken   TimeStampToken OPTIONAL
/// }
/// PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }
/// ```
fn extract_token(resp_der: &[u8]) -> Result<Vec<u8>, AdesError> {
    // Outer SEQUENCE
    let outer = der_unwrap_seq(resp_der)
        .ok_or_else(|| AdesError::Tsp("invalid TimeStampResp: not a SEQUENCE".to_owned()))?;

    // First element: PKIStatusInfo SEQUENCE
    let (status_seq, rest) =
        der_next_tlv(outer).ok_or_else(|| AdesError::Tsp("missing PKIStatusInfo".to_owned()))?;

    // First element of PKIStatusInfo: status INTEGER
    let status_inner = der_unwrap_seq(status_seq)
        .ok_or_else(|| AdesError::Tsp("PKIStatusInfo not a SEQUENCE".to_owned()))?;
    let (status_int, _) = der_next_tlv(status_inner)
        .ok_or_else(|| AdesError::Tsp("missing status INTEGER".to_owned()))?;

    let status_value = status_int
        .last()
        .copied()
        .ok_or_else(|| AdesError::Tsp("empty status INTEGER".to_owned()))?;

    // PKIStatus: 0 = granted, 1 = grantedWithMods
    if status_value > 1 {
        return Err(AdesError::Tsp(format!(
            "TSA rejected request with status {status_value}"
        )));
    }

    // Second element: TimeStampToken (ContentInfo, a SEQUENCE)
    if rest.is_empty() {
        return Err(AdesError::Tsp(
            "TimeStampResp missing timeStampToken".to_owned(),
        ));
    }
    let (token_bytes, _) =
        der_next_tlv(rest).ok_or_else(|| AdesError::Tsp("invalid timeStampToken".to_owned()))?;

    Ok(token_bytes.to_vec())
}

// ---------------------------------------------------------------------------
// Minimal DER primitives (no external dep beyond what ades already has)
// ---------------------------------------------------------------------------

/// Wraps `value` in a DER TLV with the given `tag`.
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

/// Returns the declared contents of the outermost SEQUENCE (trimmed to the declared length).
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

/// Returns `(full_tlv, remainder)` for the first TLV in `data`.
fn der_next_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let (len, contents) = der_decode_len(&data[1..])?;
    // header_size = tag byte (1) + length bytes; contents.as_ptr() - data.as_ptr() gives that.
    let header_size = contents.as_ptr() as usize - data.as_ptr() as usize;
    let end = header_size + len;
    if end > data.len() {
        return None;
    }
    Some((&data[..end], &data[end..]))
}

/// Decodes a DER length at `data[0..]`.
/// Returns `(length, rest_of_data_after_length_bytes)`.
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
