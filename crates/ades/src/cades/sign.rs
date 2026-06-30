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
    Any, Encode,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;

use crate::{cms::signature_algorithm_id, error::AdesError, signer::Signer};

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
// id-aa-signingCertificateV2 (RFC 5035 / ESS) — mandatory for CAdES B-B
const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

/// Produces a CAdES B-B signature over `data`.
///
/// Returns the raw DER-encoded CMS `ContentInfo` (wrapping `SignedData`) suitable for
/// submission to a DSS validator.
///
/// The signature includes the mandatory signed attributes for CAdES B-B:
/// - `id-contentType`
/// - `id-signingTime`
/// - `id-messageDigest`
///
/// The original `data` is embedded as detached (eContent absent).
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
pub fn sign<S: Signer>(data: &[u8], signer: &S) -> Result<Vec<u8>, AdesError>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    use der::Decode;

    let digest_algo = signer.digest_algorithm();
    let cert = signer.certificate();

    // 1. Compute content digest (goes into id-messageDigest attribute)
    let content_digest = digest_algo.hash(data);

    // 2. Build signed attributes (order in SET is determined by DER sort, not insertion order)
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
            let octet = OctetString::new(content_digest.as_slice())?;
            set.insert(Any::encode_from(&octet)?)?;
            set
        },
    };

    // signing-certificate-v2 (RFC 5035): mandatory for CAdES B-B (ETSI EN 319 122-1 §5.2.3)
    // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
    // ESSCertIDv2 ::= SEQUENCE { certHash OCTET STRING }  (SHA-256 of cert DER)
    let signing_cert_v2_attr = {
        let sc_v2_der = build_signing_cert_v2_der(cert.to_der())?;
        Attribute {
            oid: ID_AA_SIGNING_CERTIFICATE_V2,
            values: {
                let mut set = SetOfVec::<Any>::new();
                set.insert(Any::from_der(&sc_v2_der)?)?;
                set
            },
        }
    };

    // Assemble signed attrs: SetOfVec sorts by DER encoding (RFC 5652 §5.3)
    let mut signed_attrs = SetOfVec::<Attribute>::new();
    signed_attrs.insert(content_type_attr)?;
    signed_attrs.insert(signing_time_attr)?;
    signed_attrs.insert(message_digest_attr)?;
    signed_attrs.insert(signing_cert_v2_attr)?;

    // 3. The signature covers the SET encoding of signedAttrs (not the [0] IMPLICIT form)
    //    Per RFC 5652 §5.4: "the complete DER encoding of the signedAttrs value"
    let signed_attrs_der = signed_attrs.to_der()?;
    let signing_digest = digest_algo.hash(&signed_attrs_der);
    let signature_bytes = signer
        .sign_digest(&signing_digest)
        .map_err(|e| AdesError::Signer(Box::new(e)))?;

    // 4. Build SignerInfo
    let x509 = cert.inner();
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: x509.tbs_certificate.issuer.clone(),
        serial_number: x509.tbs_certificate.serial_number.clone(),
    });

    let digest_alg_id = AlgorithmIdentifierOwned {
        oid: digest_algo.oid(),
        parameters: None,
    };

    let key_alg_oid = cert
        .inner()
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid;
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

    // 5. Assemble SignedData
    let mut digest_algorithms = DigestAlgorithmIdentifiers::new();
    digest_algorithms.insert(digest_alg_id)?;

    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };

    // Embed the signing certificate in the certificates field
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

    // 6. Wrap in ContentInfo { contentType: id-signedData, content: [0] EXPLICIT SignedData }
    let signed_data_der = signed_data.to_der()?;
    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der)?,
    };

    Ok(content_info.to_der()?)
}

/// Builds the DER encoding of `SigningCertificateV2` (RFC 5035) for the given cert DER.
///
/// ```asn1
/// SigningCertificateV2 ::= SEQUENCE {
///     certs  SEQUENCE OF ESSCertIDv2
/// }
/// ESSCertIDv2 ::= SEQUENCE {
///     certHash  OCTET STRING   -- SHA-256 of the cert DER
/// }
/// ```
fn build_signing_cert_v2_der(cert_der: &[u8]) -> Result<Vec<u8>, AdesError> {
    use sha2::{Digest, Sha256};

    let hash: [u8; 32] = Sha256::digest(cert_der).into();

    // Build from inside out: each level is tag + length + value.
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

    let hash_os = tlv(0x04, hash.as_slice()); // OCTET STRING
    let ess_cert_id = tlv(0x30, &hash_os); // ESSCertIDv2 ::= SEQUENCE { certHash }
    let certs_seq = tlv(0x30, &ess_cert_id); // SEQUENCE OF ESSCertIDv2 (the certs field)
    Ok(tlv(0x30, &certs_seq)) // SigningCertificateV2 ::= SEQUENCE { certs }
}
