const RTP_OVERHEAD: usize = rtp::rtp_types::RtpPacket::MIN_RTP_PACKET_LEN;

// TODO: using conservative values here since I'm not entirely sure what is correct here
const SRTP_OVERHEAD: usize = 32;
const SRTCP_OVERHEAD: usize = 32;

/// Maximum Transmission Unit. Utility type to calculate maximum packet sizes.
#[derive(Debug, Clone, Copy)]
pub struct Mtu {
    base: usize,
    srtp: bool,
    // total overhead introduced by RTP extensions only
    rtp_extensions: usize,
}

impl Default for Mtu {
    fn default() -> Self {
        Mtu {
            base: 1472,
            srtp: false,
            rtp_extensions: 0,
        }
    }
}

impl Mtu {
    /// Create a new MTU config with the given upper limit.
    ///
    /// The limit will always be at least 256, which is a value I completely made up.
    ///
    /// Overhead of the IP & UDP layer is not taken into account when calculating RTP/RTCP packet sizes.
    pub const fn new(mut mtu: usize) -> Self {
        if mtu < 256 {
            mtu = 256;
        }

        Self {
            base: mtu,
            srtp: false,
            rtp_extensions: 0,
        }
    }

    pub(crate) const fn with_srtp_overhead(self) -> Self {
        Self { srtp: true, ..self }
    }

    pub(crate) const fn with_additional_rtp_extension(mut self, attribute_len: usize) -> Self {
        // This code assumes the worst case scenario, that the two byte header extensions are used

        if self.rtp_extensions == 0 {
            // Add the two byte header overhead
            self.rtp_extensions = 2;
        }

        Self {
            // Add the attribute length + two byte prefix
            rtp_extensions: self.rtp_extensions + attribute_len + 2,
            ..self
        }
    }

    /// The maximum allowed size of RTP payloads
    pub const fn for_rtp_payload(self) -> usize {
        let mut base = self.base;

        if self.srtp {
            base -= SRTP_OVERHEAD;
        }

        base.saturating_sub(self.rtp_extensions)
            .saturating_sub(RTP_OVERHEAD)
    }

    pub(crate) const fn for_rtcp_packets(self) -> usize {
        if self.srtp {
            self.base - SRTCP_OVERHEAD
        } else {
            self.base
        }
    }
}
