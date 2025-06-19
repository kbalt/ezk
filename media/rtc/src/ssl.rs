use openssl::{
    asn1::{Asn1Time, Asn1Type},
    bn::{BigNum, MsbOption},
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
        let (cert, pkey) = make_ca_cert()?;

        let mut ctx = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
        ctx.set_tlsext_use_srtp(srtp::openssl::SRTP_PROFILE_NAMES)?;
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

fn make_ca_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    openssl::init();

    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;

    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;

    cert_builder.set_pubkey(&pkey)?;
    cert_builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    cert_builder.set_not_after(Asn1Time::days_from_now(7)?.as_ref())?;

    let mut x509_name = X509Name::builder()?;
    x509_name.append_entry_by_nid_with_type(Nid::COMMONNAME, "ezk-rtc", Asn1Type::UTF8STRING)?;
    let x509_name = x509_name.build();

    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;

    cert_builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, pkey))
}
