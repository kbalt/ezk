use sdp_types::SrtpCrypto;
use srtp::SrtpSession;

pub struct RtpSdesSrtpTransport {
    local_sdp_crypto: SrtpCrypto,

    pub(crate) inbound: SrtpSession,
    pub(crate) outbound: SrtpSession,
}

impl RtpSdesSrtpTransport {
    pub fn new(local_sdp_crypto: SrtpCrypto, inbound: SrtpSession, outbound: SrtpSession) -> Self {
        Self {
            local_sdp_crypto,
            inbound,
            outbound,
        }
    }

    pub fn local_sdp_crypto(&self) -> &SrtpCrypto {
        &self.local_sdp_crypto
    }
}
