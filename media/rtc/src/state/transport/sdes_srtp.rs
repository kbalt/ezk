use sdp_types::SrtpCrypto;

pub struct RtpSdesSrtpTransport {
    local_sdp_crypto: SrtpCrypto,

    pub(crate) inbound: srtp::Session,
    pub(crate) outbound: srtp::Session,
}

impl RtpSdesSrtpTransport {
    pub fn new(
        local_sdp_crypto: SrtpCrypto,
        inbound: srtp::Session,
        outbound: srtp::Session,
    ) -> Result<Self, srtp::Error> {
        Ok(Self {
            local_sdp_crypto,
            inbound,
            outbound,
        })
    }

    pub fn local_sdp_crypto(&self) -> &SrtpCrypto {
        &self.local_sdp_crypto
    }
}
