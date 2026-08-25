use sdp_types::SrtpCrypto;
use srtp::{SrtpProtector, SrtpUnprotector};

pub struct RtpSdesSrtpTransport {
    local_sdp_crypto: SrtpCrypto,

    pub(crate) inbound: SrtpUnprotector,
    pub(crate) outbound: SrtpProtector,
}

impl RtpSdesSrtpTransport {
    pub fn new(
        local_sdp_crypto: SrtpCrypto,
        inbound: SrtpUnprotector,
        outbound: SrtpProtector,
    ) -> Self {
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
