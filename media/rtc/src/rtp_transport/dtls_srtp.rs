use dimpl::Dtls;
use sha2::{Digest, Sha256};
use srtp::{DtlsSrtpPolicies, SrtpSession};
use std::{
    cmp,
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

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
    dtls: Dtls,

    timeout: Option<Instant>,

    out_buf: Vec<u8>,

    peer_fingerprint: Vec<u8>,

    setup: DtlsSetup,
    state: DtlsState,

    events: VecDeque<Vec<u8>>,
}

impl RtpDtlsSrtpTransport {
    pub fn new(
        config: Arc<dimpl::Config>,
        certificate: dimpl::DtlsCertificate,
        peer_fingerprint: Vec<u8>,
        setup: DtlsSetup,
        now: Instant,
    ) -> Self {
        let mut dtls = Dtls::new_auto(config, certificate, now);

        dtls.set_active(match setup {
            DtlsSetup::Accept => false,
            DtlsSetup::Connect => true,
        });

        let mut this = RtpDtlsSrtpTransport {
            dtls,
            // TODO: trigger handle_timeout immediately otherwise dimpl panics
            timeout: Some(now),
            out_buf: vec![0u8; 2000],
            peer_fingerprint,
            setup,
            state: match setup {
                DtlsSetup::Accept => DtlsState::Accepting,
                DtlsSetup::Connect => DtlsState::Connecting,
            },
            events: VecDeque::new(),
        };

        this.poll(now);

        this
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
        if let DtlsState::Failed = self.state {
            return None;
        }

        self.timeout
            .map(|timeout| timeout.saturating_duration_since(now))
    }

    pub(crate) fn receive(&mut self, data: Vec<u8>) {
        if let DtlsState::Failed = self.state {
            return;
        }

        if let Err(err) = self.dtls.handle_packet(&data) {
            log::error!("Failed to handle DTLS packet, {err:?}");
            self.state = DtlsState::Failed;
        }
    }

    pub(crate) fn poll(&mut self, now: Instant) {
        if let DtlsState::Failed = self.state {
            return;
        }

        if self.timeout.is_some_and(|t| now >= t) {
            self.timeout = None;

            if let Err(err) = self.dtls.handle_timeout(now) {
                log::error!("DTLS handle_timeout failed, {err:?}");
                self.state = DtlsState::Failed;
                return;
            }
        }

        loop {
            match self.dtls.poll_output(&mut self.out_buf) {
                dimpl::Output::Packet(packet) => self.events.push_back(packet.to_vec()),
                dimpl::Output::BufferTooSmall { needed } => self.out_buf.resize(needed, 0),
                dimpl::Output::Timeout(instant) => {
                    self.timeout = Some(instant);
                    break;
                }
                dimpl::Output::PeerCert(peer_cert) => {
                    let peer_cert_fingerprint = Sha256::digest(peer_cert);

                    if peer_cert_fingerprint[..] != self.peer_fingerprint {
                        log::warn!(
                            "peer certificate sha256 fingerprint mismatch expected={:X?} got={:X?}",
                            self.peer_fingerprint,
                            peer_cert_fingerprint,
                        );
                        self.state = DtlsState::Failed;
                        return;
                    }
                }
                dimpl::Output::KeyingMaterial(keying_material, srtp_profile) => {
                    match DtlsSrtpPolicies::from_dimpl(
                        keying_material,
                        srtp_profile,
                        !self.dtls.is_active(),
                    ) {
                        Ok(DtlsSrtpPolicies { inbound, outbound }) => {
                            let inbound = match SrtpSession::new(vec![inbound]) {
                                Ok(session) => session,
                                Err(err) => {
                                    log::error!("Failed to create inbound SRTP session: {err}");
                                    self.state = DtlsState::Failed;
                                    return;
                                }
                            };
                            let outbound = match SrtpSession::new(vec![outbound]) {
                                Ok(session) => session,
                                Err(err) => {
                                    log::error!("Failed to create outbound SRTP session: {err}");
                                    self.state = DtlsState::Failed;
                                    return;
                                }
                            };

                            self.state = DtlsState::Connected { inbound, outbound };
                        }
                        Err(err) => {
                            log::error!(
                                "Failed to create SRTP policies from keying-material, {err:?}"
                            );
                            self.state = DtlsState::Failed;
                        }
                    }
                }
                dimpl::Output::CloseNotify => {
                    log::debug!("received DTLS close notify");
                    self.state = DtlsState::Failed;
                }
                _ => {}
            }
        }
    }

    pub(crate) fn pop_to_send(&mut self) -> Option<Vec<u8>> {
        self.events.pop_front()
    }
}
