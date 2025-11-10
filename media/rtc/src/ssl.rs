use std::time::SystemTime;

use openssl::{
    asn1::{Asn1Integer, Asn1Time, Asn1Type},
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslContext, SslMethod, SslVersion},
    x509::{X509, X509Name},
};

/// Wrapper around a [`SslContext`] with the guarantee that a certificate is set
#[derive(Clone)]
pub struct OpenSslContext {
    pub(crate) ctx: SslContext,
}

impl OpenSslContext {
    /// Create a new SSL context, with a new certificate used for DTLS
    pub fn try_new() -> Result<Self, ErrorStack> {
        openssl::init();

        let (cert, pkey) = make_ca_cert()?;

        let mut ctx = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
        ctx.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32:SRTP_AEAD_AES_128_GCM:SRTP_AEAD_AES_256_GCM")?;
        ctx.set_min_proto_version(Some(SslVersion::DTLS1_2))?;
        ctx.set_private_key(&pkey)?;
        ctx.set_certificate(&cert)?;
        ctx.check_private_key()?;

        Ok(Self {
            ctx: ctx.build().into_context(),
        })
    }

    /// Try to create a new context from an existing [`SslContext`]
    ///
    /// Fails if there is no certificate available
    pub fn try_from_ctx(ctx: SslContext) -> Result<OpenSslContext, SslContext> {
        if ctx.certificate().is_none() {
            Err(ctx)
        } else {
            Ok(Self { ctx })
        }
    }
}

/// Used str0m's implementation as reference https://github.com/algesten/str0m/blob/8f118ddd6a267583cddd0115ae8560095232d39a/src/crypto/ossl/cert.rs#L35
fn make_ca_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    const RSA_F4: u32 = 0x10001;

    let f4 = BigNum::from_u32(RSA_F4).unwrap();

    let key = Rsa::generate_with_e(2048, &f4)?;
    let pkey = PKey::from_rsa(key)?;

    let mut x509b = X509::builder()?;
    x509b.set_version(2)?; // X509.V3 (zero indexed)

    let mut serial_buf = [0u8; 16];
    openssl::rand::rand_bytes(&mut serial_buf)?;

    let serial_bn = BigNum::from_slice(&serial_buf)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    x509b.set_serial_number(&serial)?;
    let before = Asn1Time::from_unix((unix_time() - 3600).try_into().unwrap())?;
    x509b.set_not_before(&before)?;
    let after = Asn1Time::days_from_now(7)?;
    x509b.set_not_after(&after)?;
    x509b.set_pubkey(&pkey)?;

    let mut nameb = X509Name::builder()?;
    nameb.append_entry_by_nid_with_type(Nid::COMMONNAME, "ezk-rtc", Asn1Type::UTF8STRING)?;

    let name = nameb.build();

    x509b.set_subject_name(&name)?;
    x509b.set_issuer_name(&name)?;

    x509b.sign(&pkey, MessageDigest::sha256())?;
    let x509 = x509b.build();

    Ok((x509, pkey))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
