use crate::{Mtu, OpenSslContext};
use openssl::{
    hash::MessageDigest,
    ssl::{ErrorCode, Ssl, SslStream, SslVerifyMode},
};
use srtp::{DtlsSrtpPolicies, SrtpError, SrtpFromSslError, SrtpSession};
use std::{
    cmp,
    collections::VecDeque,
    io::{self, Cursor, Read, Write},
    time::{Duration, Instant},
};

const DTLS_INITIAL_TIMEOUT: Duration = Duration::from_millis(100);
const DTLS_MAX_TIMEOUT: Duration = Duration::from_millis(1000);

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

    /// When to retransmit DTLS packets during the initial handshake
    retransmit_at: Option<Instant>,
    next_retransmit_delta: Duration,
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

        match setup {
            DtlsSetup::Accept => ssl.set_accept_state(),
            DtlsSetup::Connect => ssl.set_connect_state(),
        }

        let stream = SslStream::new(
            ssl,
            IoQueue {
                to_read: VecDeque::new(),
                current: None,
                out: VecDeque::new(),
                mtu: mtu.for_dtls(),
            },
        )
        .map_err(DtlsSrtpCreateError::NewSslStream)?;

        let this = RtpDtlsSrtpTransport {
            stream,
            setup,
            state: match setup {
                DtlsSetup::Accept => DtlsState::Accepting,
                DtlsSetup::Connect => DtlsState::Connecting,
            },
            retransmit_at: None,
            next_retransmit_delta: DTLS_INITIAL_TIMEOUT,
        };

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

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        self.retransmit_at
            .map(|deadline| deadline.checked_duration_since(now).unwrap_or_default())
    }

    pub(crate) fn receive(
        &mut self,
        now: Instant,
        data: Vec<u8>,
    ) -> Result<(), DtlsHandshakeError> {
        self.stream.get_mut().to_read.push_back(data);
        self.next_retransmit_delta = DTLS_INITIAL_TIMEOUT;
        self.do_poll(now)
    }

    pub(crate) fn poll(&mut self, now: Instant) -> Result<(), DtlsHandshakeError> {
        if self.retransmit_at.is_none()
            && let DtlsState::Connecting | DtlsState::Accepting = &self.state
        {
            // First poll call, set initial retransmit timeout
            //
            // do_poll must not set the timeout if it is `None`, since `receive` may be called before
            // the ICE connection is established from our POV, causing the timeout to be wrong once
            // the DTLS setup should begin.
            self.retransmit_at = Some(now + DTLS_INITIAL_TIMEOUT);
            return self.do_poll(now);
        }

        // Only when there's a timeout poll the dtls session, after handshake this transport doesn't do anything anymore, keys have been exchanged
        let retransmit_at = self.retransmit_at.is_some_and(|deadline| deadline <= now);

        if retransmit_at {
            self.do_poll(now)?;
        }

        Ok(())
    }

    fn do_poll(&mut self, now: Instant) -> Result<(), DtlsHandshakeError> {
        let result = match self.state {
            DtlsState::Connecting => self.stream.do_handshake(),
            DtlsState::Accepting => self.stream.do_handshake(),
            DtlsState::Connected { .. } => {
                // Poll DTLS state machine
                while let Ok(1..) = self.stream.read(&mut [0]) {}
                return Ok(());
            }
            DtlsState::Failed => return Ok(()),
        };

        log::trace!("do_handshake {}", self.stream.ssl().state_string_long());

        if let Err(e) = result {
            if e.code() == ErrorCode::WANT_READ {
                // Set timeout only if it has one and it has elapsed. See comment in `poll`
                let retransmit_at = self.retransmit_at.is_some_and(|deadline| deadline <= now);
                if retransmit_at {
                    self.bump_retransmit_at(now);
                }
                return Ok(());
            } else {
                self.retransmit_at = None;
                self.state = DtlsState::Failed;
                return Err(DtlsHandshakeError::OpenSsl(e));
            }
        }

        let DtlsSrtpPolicies { inbound, outbound } =
            match DtlsSrtpPolicies::from_ssl(self.stream.ssl()) {
                Ok(policies) => policies,
                Err(e) => {
                    self.retransmit_at = None;
                    self.state = DtlsState::Failed;
                    return Err(DtlsHandshakeError::SrtpFromSsl(e));
                }
            };

        self.state = DtlsState::Connected {
            inbound: SrtpSession::new(vec![inbound])?,
            outbound: SrtpSession::new(vec![outbound])?,
        };

        self.retransmit_at = None;

        Ok(())
    }

    fn bump_retransmit_at(&mut self, now: Instant) {
        if matches!(self.state, DtlsState::Connecting | DtlsState::Accepting) {
            self.retransmit_at = Some(now + self.next_retransmit_delta);
            self.next_retransmit_delta = cmp::min(
                self.next_retransmit_delta.saturating_mul(2),
                DTLS_MAX_TIMEOUT,
            );
        } else {
            self.retransmit_at = None;
        }
    }

    pub(crate) fn pop_to_send(&mut self) -> Option<Vec<u8>> {
        self.stream.get_mut().out.pop_front()
    }
}

struct IoQueue {
    to_read: VecDeque<Vec<u8>>,
    current: Option<Cursor<Vec<u8>>>,
    out: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Read for IoQueue {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.to_read.is_empty() && self.current.is_none() {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        let to_read = self
            .current
            .get_or_insert_with(|| Cursor::new(self.to_read.pop_front().unwrap()));

        let result = to_read.read(buf)?;

        let position = usize::try_from(to_read.position()).expect("position must fit into usize");

        if position == to_read.get_ref().len() {
            self.current = None;
        }

        Ok(result)
    }
}

impl Write for IoQueue {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(last) = self.out.back_mut()
            && last.len() + buf.len() <= self.mtu
        {
            last.extend_from_slice(buf);
            return Ok(buf.len());
        }

        self.out.push_back(buf.to_vec());

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
