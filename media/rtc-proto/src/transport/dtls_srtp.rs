use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{ErrorCode, Ssl, SslAcceptor, SslContext, SslMethod, SslStream, SslVerifyMode},
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509,
    },
};
use sdp_types::FingerprintAlgorithm;
use srtp::openssl::Config;
use std::{
    collections::VecDeque,
    io::{self, Cursor, Read, Write},
    time::Duration,
};

#[derive(Debug, Clone, Copy)]
pub(crate) enum DtlsSetup {
    Accept,
    Connect,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DtlsState {
    Accepting,
    Connecting,
    Connected,
    Failed,
}

pub(crate) struct DtlsSrtpSession {
    stream: SslStream<IoQueue>,
    state: DtlsState,
}

impl DtlsSrtpSession {
    pub(crate) fn new(
        ssl_context: &SslContext,
        fingerprints: Vec<(MessageDigest, Vec<u8>)>,
        setup: DtlsSetup,
    ) -> io::Result<Self> {
        let mut ssl = Ssl::new(ssl_context)?;
        ssl.set_mtu(1200)?;

        ssl.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            move |_, x509_store| {
                let Some(certificate) = x509_store.current_cert() else {
                    return false;
                };

                for (digest, fingerprint) in &fingerprints {
                    let Ok(peer_fingerprint) = certificate.digest(*digest) else {
                        continue;
                    };

                    if peer_fingerprint.as_ref() == fingerprint {
                        return true;
                    }
                }

                false
            },
        );

        let mut this = Self {
            stream: SslStream::new(
                ssl,
                IoQueue {
                    to_read: None,
                    out: VecDeque::new(),
                },
            )?,
            state: match setup {
                DtlsSetup::Accept => DtlsState::Accepting,
                DtlsSetup::Connect => DtlsState::Connecting,
            },
        };

        // Put initial handshake into the IoQueue
        assert!(this.handshake()?.is_none());

        Ok(this)
    }

    pub(crate) fn state(&self) -> DtlsState {
        self.state
    }

    // TODO: if event_timeout is ever merged, use it
    // #[cfg(openssl320)]
    // pub(crate) fn timeout(&self) -> Option<Duration> {
    //     self.stream.ssl().event_timeout().unwrap()
    // }

    // #[cfg(not(openssl320))]
    pub(crate) fn timeout(&self) -> Option<Duration> {
        match self.state {
            DtlsState::Accepting => Some(Duration::from_millis(100)),
            DtlsState::Connecting => Some(Duration::from_millis(100)),
            DtlsState::Connected => None,
            DtlsState::Failed => None,
        }
    }

    pub(crate) fn receive(&mut self, data: Vec<u8>) {
        assert!(self.stream.get_mut().to_read.is_none());
        self.stream.get_mut().to_read = Some(Cursor::new(data));
    }

    pub(crate) fn handshake(
        &mut self,
    ) -> io::Result<
        Option<(
            srtp::openssl::InboundSession,
            srtp::openssl::OutboundSession,
        )>,
    > {
        let result = match self.state {
            DtlsState::Connecting => self.stream.connect(),
            DtlsState::Accepting => self.stream.accept(),
            _ => {
                assert!(
                    self.stream.get_mut().to_read.is_none(),
                    "IoQueue has something to read, but state is None"
                );
                return Ok(None);
            }
        };

        if let Err(e) = result {
            if e.code() == ErrorCode::WANT_READ {
                return Ok(None);
            } else {
                self.state = DtlsState::Failed;
                return Err(io::Error::other(e));
            }
        }

        self.state = DtlsState::Connected;

        let (inbound, outbound) =
            srtp::openssl::session_pair(self.stream.ssl(), Config::default()).unwrap();

        Ok(Some((inbound, outbound)))
    }

    pub(crate) fn pop_to_send(&mut self) -> Option<Vec<u8>> {
        self.stream.get_mut().out.pop_front()
    }
}

struct IoQueue {
    to_read: Option<Cursor<Vec<u8>>>,
    out: VecDeque<Vec<u8>>,
}

impl Read for IoQueue {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(to_read) = &mut self.to_read else {
            return Err(io::ErrorKind::WouldBlock.into());
        };

        let result = to_read.read(buf)?;

        if to_read.position() == u64::try_from(to_read.get_ref().len()).unwrap() {
            self.to_read = None;
        }

        Ok(result)
    }
}

impl Write for IoQueue {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.out.push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn to_openssl_digest(algo: &FingerprintAlgorithm) -> Option<MessageDigest> {
    match algo {
        FingerprintAlgorithm::SHA1 => Some(MessageDigest::sha1()),
        FingerprintAlgorithm::SHA224 => Some(MessageDigest::sha224()),
        FingerprintAlgorithm::SHA256 => Some(MessageDigest::sha256()),
        FingerprintAlgorithm::SHA384 => Some(MessageDigest::sha384()),
        FingerprintAlgorithm::SHA512 => Some(MessageDigest::sha512()),
        FingerprintAlgorithm::MD5 => Some(MessageDigest::md5()),
        FingerprintAlgorithm::MD2 => None,
        FingerprintAlgorithm::Other(..) => None,
    }
}

pub(super) fn make_ssl_context() -> SslContext {
    let (cert, pkey) = make_ca_cert().unwrap();

    let mut ctx = SslAcceptor::mozilla_modern(SslMethod::dtls()).unwrap();
    ctx.set_tlsext_use_srtp(srtp::openssl::SRTP_PROFILE_NAMES)
        .unwrap();
    ctx.set_private_key(&pkey).unwrap();
    ctx.set_certificate(&cert).unwrap();
    ctx.check_private_key().unwrap();
    ctx.build().into_context()
}

fn make_ca_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    openssl::init();

    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "XX")?;
    x509_name.append_entry_by_text("ST", "XX")?;
    x509_name.append_entry_by_text("O", "EZK")?;
    x509_name.append_entry_by_text("CN", "EZK-DTLS-SRTP")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    cert_builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    cert_builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}
