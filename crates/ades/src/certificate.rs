use der::Decode;
use x509_cert::Certificate as X509Certificate;

use crate::error::AdesError;

/// A parsed X.509 certificate.
///
/// Wraps [`x509_cert::Certificate`] with convenience methods for AdES signing.
#[derive(Debug, Clone)]
pub struct Certificate {
    inner: X509Certificate,
    /// Raw DER bytes — kept to avoid re-encoding when building CMS structures.
    der: Vec<u8>,
}

impl Certificate {
    /// Parses a certificate from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AdesError::Der`] if the bytes are not valid DER.
    pub fn from_der(der: &[u8]) -> Result<Self, AdesError> {
        let inner = X509Certificate::from_der(der)?;
        Ok(Self {
            inner,
            der: der.to_vec(),
        })
    }

    /// Returns the raw DER encoding of this certificate.
    #[must_use]
    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// Returns a reference to the underlying [`x509_cert::Certificate`].
    #[must_use]
    pub fn inner(&self) -> &X509Certificate {
        &self.inner
    }
}
