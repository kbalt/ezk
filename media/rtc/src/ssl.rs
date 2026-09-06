use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};

use crate::Mtu;

/// DTLS certificate and configuration used to establish DTLS-SRTP sessions
#[derive(Clone)]
pub(crate) struct DtlsContext {
    pub(crate) cert: dimpl::DtlsCertificate,
    pub(crate) config: Arc<dimpl::Config>,
}

impl DtlsContext {
    /// Create a new context with a self-signed certificate
    pub(crate) fn new(mtu: Mtu) -> DtlsContext {
        let cert = generate_self_signed_certificate().expect("certificate is valid");

        let config = dimpl::Config::builder()
            .mtu(mtu.base())
            .build()
            .expect("dimpl config is valid");

        DtlsContext {
            cert,
            config: Arc::new(config),
        }
    }

    /// SHA-256 fingerprint of the local certificate
    pub(crate) fn fingerprint(&self) -> Vec<u8> {
        Sha256::digest(&self.cert.certificate).to_vec()
    }
}

// Copy of dimpl's generate_self_signed_certificate, since they require aws-lc-rs
// https://github.com/algesten/dimpl/blob/37f950984af1d0c2f86ef21b940c672fb27cd7c7/src/certificate.rs#L39
fn generate_self_signed_certificate() -> Result<dimpl::DtlsCertificate, rcgen::Error> {
    // Create a key pair for the certificate
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    // Set up certificate parameters
    let mut params = CertificateParams::new(Vec::<String>::new())?;

    // Set up distinguished name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "DTLS".to_string());
    distinguished_name.push(DnType::CommonName, "DTLS Peer".to_string());
    params.distinguished_name = distinguished_name;

    // Configure as end entity certificate (not a CA)
    params.is_ca = IsCa::NoCa;

    // Set validity period (1 year)
    let not_before = time::OffsetDateTime::now_utc();
    let not_after = not_before + time::Duration::days(365);
    params.not_before = not_before;
    params.not_after = not_after;

    // Serial number: must be unique for Firefox compatibility, not only across all certificates
    // of this process, but also across all certificates of other processes/machines!
    // See: https://github.com/versatica/mediasoup/issues/127#issuecomment-474460153
    // and https://github.com/algesten/str0m/issues/517
    let serial_buf: [u8; 16] = rand::random();
    params.serial_number = Some(serial_buf.to_vec().into());

    // Build the certificate
    let cert = params.self_signed(&key_pair)?;

    // Get the certificate in DER format
    let cert_der = cert.der().to_vec();

    // Get the private key in DER format
    let key_der = key_pair.serialize_der();

    Ok(dimpl::DtlsCertificate {
        certificate: cert_der,
        private_key: key_der,
    })
}
