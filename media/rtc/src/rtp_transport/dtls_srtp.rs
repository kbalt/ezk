use openssl::{
    hash::MessageDigest,
    ssl::{ErrorCode, Ssl, SslStream, SslVerifyMode},
};
use srtp::{DtlsSrtpPolicies, SrtpError, SrtpFromSslError, SrtpSession};
use std::{
    collections::VecDeque,
    io::{self, Cursor, Read, Write},
    time::Duration,
};

use crate::{Mtu, OpenSslContext};

#[derive(Debug, thiserror::Error)]
pub enum DtlsSrtpCreateError {
    #[error("Failed to create Ssl: {0}")]
    NewSsl(#[source] openssl::error::ErrorStack),
    #[error("Failed to set MTU: {0}")]
    SetMtu(#[source] openssl::error::ErrorStack),
    #[error("Failed to create SslStream: {0}")]
    NewSslStream(#[source] openssl::error::ErrorStack),
}

#[derive(Debug, thiserror::Error)]
pub enum DtlsHandshakeError {
    #[error("OpenSSL handshake error: {0}")]
    OpenSsl(#[from] openssl::ssl::Error),
    #[error("Failed to create SRTP policies from DTLS state: {0}")]
    SrtpFromSsl(#[from] SrtpFromSslError),
    #[error("Failed to create SRTP session: {0}")]
    CreateSrtp(#[from] SrtpError),
}

#[derive(Debug, Clone, Copy)]
pub enum DtlsSetup {
    Accept,
    Connect,
}

pub(crate) enum DtlsState {
    Accepting,
    Connecting,
    Connected {
        inbound: SrtpSession,
        outbound: SrtpSession,
    },
    Failed,
}

pub struct RtpDtlsSrtpTransport {
    stream: SslStream<IoQueue>,
    setup: DtlsSetup,
    state: DtlsState,
}

impl RtpDtlsSrtpTransport {
    pub fn new(
        ssl_context: &OpenSslContext,
        fingerprints: Vec<(MessageDigest, Vec<u8>)>,
        setup: DtlsSetup,
        mtu: Mtu,
    ) -> Result<Self, DtlsSrtpCreateError> {
        let mut ssl = Ssl::new(&ssl_context.ctx).map_err(DtlsSrtpCreateError::NewSsl)?;

        ssl.set_mtu(
            mtu.for_dtls()
                .try_into()
                .expect("MTU must not be larger than u32::MAX"),
        )
        .map_err(DtlsSrtpCreateError::SetMtu)?;

        // Use the openssl verify callback to test the peer certificate against the fingerprints that were sent to us
        ssl.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            move |_preverify_ok, x509_store| {
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

        let stream = SslStream::new(
            ssl,
            IoQueue {
                to_read: None,
                out: VecDeque::new(),
            },
        )
        .map_err(DtlsSrtpCreateError::NewSslStream)?;

        let mut this = RtpDtlsSrtpTransport {
            stream,
            setup,
            state: match setup {
                DtlsSetup::Accept => DtlsState::Accepting,
                DtlsSetup::Connect => DtlsState::Connecting,
            },
        };

        // Put initial handshake into the IoQueue
        this.handshake()
            .expect("First call to handshake must not fail");

        Ok(this)
    }

    pub fn setup(&self) -> DtlsSetup {
        self.setup
    }

    pub(crate) fn state(&self) -> &DtlsState {
        &self.state
    }

    pub(crate) fn state_mut(&mut self) -> &mut DtlsState {
        &mut self.state
    }

    pub(crate) fn timeout(&self) -> Option<Duration> {
        match self.state {
            DtlsState::Accepting => Some(Duration::from_millis(100)),
            DtlsState::Connecting => Some(Duration::from_millis(100)),
            DtlsState::Connected { .. } => None,
            DtlsState::Failed => None,
        }
    }

    pub(crate) fn receive(&mut self, data: Vec<u8>) {
        assert!(self.stream.get_mut().to_read.is_none());
        self.stream.get_mut().to_read = Some(Cursor::new(data));
    }

    pub(crate) fn handshake(&mut self) -> Result<(), DtlsHandshakeError> {
        let result = match self.state {
            DtlsState::Connecting => self.stream.connect(),
            DtlsState::Accepting => self.stream.accept(),
            DtlsState::Connected { .. } => match self.setup {
                DtlsSetup::Accept => self.stream.accept(),
                DtlsSetup::Connect => self.stream.connect(),
            },
            DtlsState::Failed => {
                return Ok(());
            }
        };

        if let Err(e) = result {
            if e.code() == ErrorCode::WANT_READ {
                return Ok(());
            } else {
                self.state = DtlsState::Failed;
                return Err(DtlsHandshakeError::OpenSsl(e));
            }
        }

        if matches!(self.state, DtlsState::Connected { .. }) {
            Ok(())
        } else {
            let DtlsSrtpPolicies { inbound, outbound } =
                DtlsSrtpPolicies::from_ssl(self.stream.ssl())?;

            self.state = DtlsState::Connected {
                inbound: SrtpSession::new(vec![inbound])?,
                outbound: SrtpSession::new(vec![outbound])?,
            };

            Ok(())
        }
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

        let position = usize::try_from(to_read.position()).expect("position must fit into usize");

        if position == to_read.get_ref().len() {
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
