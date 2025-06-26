use crate::connection::Connection;
use crate::media::Media;
use crate::{
    Direction, ExtMap, Fingerprint, Fmtp, IceCandidate, IcePassword, IceUsernameFragment,
    MediaType, RtpMap, Setup, SrtpCrypto, Ssrc, TransportProtocol, UnknownAttribute,
};
use crate::{Rtcp, bandwidth::Bandwidth};
use bytesstr::BytesStr;
use std::fmt::{self, Debug};

/// Part of the [`SessionDescription`](crate::SessionDescription) describes a single media session
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.14)
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// Media description's media field (m=)
    pub media: Media,

    /// Optional connection (c field)
    pub connection: Option<Connection>,

    /// Optional bandwidths (b fields)
    pub bandwidth: Vec<Bandwidth>,

    /// Media direction attribute
    pub direction: Direction,

    /// rtcp attribute
    pub rtcp: Option<Rtcp>,

    /// rtcp-mux attribute
    pub rtcp_mux: bool,

    /// Media ID (a=mid)
    pub mid: Option<BytesStr>,

    /// RTP Payload mappings
    pub rtpmap: Vec<RtpMap>,

    /// RTP encoding parameters
    pub fmtp: Vec<Fmtp>,

    /// ICE username fragment
    pub ice_ufrag: Option<IceUsernameFragment>,

    /// ICE password
    pub ice_pwd: Option<IcePassword>,

    /// ICE candidates
    pub ice_candidates: Vec<IceCandidate>,

    /// ICE a=end-of-candidates attribute
    pub ice_end_of_candidates: bool,

    /// Crypto attributes
    pub crypto: Vec<SrtpCrypto>,

    /// ExtMap attributes
    pub extmap: Vec<ExtMap>,

    /// Extmap allow mixed attribute (a=extmap-allow-mixed)
    pub extmap_allow_mixed: bool,

    /// SSRC attribute (a=ssrc)
    pub ssrc: Vec<Ssrc>,

    /// Setup attribute (a=setup)
    pub setup: Option<Setup>,

    /// Fingerprint attribute (a=fingerprint)
    pub fingerprint: Vec<Fingerprint>,

    /// Additional attributes
    pub attributes: Vec<UnknownAttribute>,
}

impl fmt::Display for MediaDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "m={}\r\n", self.media)?;

        if let Some(conn) = &self.connection {
            write!(f, "c={conn}\r\n")?;
        }

        for bw in &self.bandwidth {
            write!(f, "b={bw}\r\n")?;
        }

        write!(f, "a={}\r\n", self.direction)?;

        if let Some(rtcp) = &self.rtcp {
            write!(f, "a=rtcp:{rtcp}\r\n")?;
        }

        if self.rtcp_mux {
            write!(f, "a=rtcp-mux\r\n")?;
        }

        if let Some(mid) = &self.mid {
            write!(f, "a=mid:{mid}\r\n")?;
        }

        for rtpmap in &self.rtpmap {
            write!(f, "a=rtpmap:{rtpmap}\r\n")?;
        }

        for fmtp in &self.fmtp {
            write!(f, "a=fmtp:{fmtp}\r\n")?;
        }

        if let Some(ufrag) = &self.ice_ufrag {
            write!(f, "a=ice-ufrag:{}\r\n", ufrag.ufrag)?;
        }

        if let Some(pwd) = &self.ice_pwd {
            write!(f, "a=ice-pwd:{}\r\n", pwd.pwd)?;
        }

        for candidate in &self.ice_candidates {
            write!(f, "a=candidate:{candidate}\r\n")?;
        }

        if self.ice_end_of_candidates {
            write!(f, "a=end-of-candidates\r\n")?;
        }

        for crypto in &self.crypto {
            write!(f, "a=crypto:{crypto}\r\n")?;
        }

        for extmap in &self.extmap {
            write!(f, "a=extmap:{extmap}\r\n")?;
        }

        if self.extmap_allow_mixed {
            write!(f, "a=extmap-allow-mixed\r\n")?;
        }

        for ssrc in &self.ssrc {
            write!(f, "a=ssrc:{ssrc}\r\n")?;
        }

        if let Some(setup) = self.setup {
            write!(f, "a=setup:{setup}\r\n")?;
        }

        for fingerprint in &self.fingerprint {
            write!(f, "a=fingerprint:{fingerprint}\r\n")?;
        }

        for attr in &self.attributes {
            write!(f, "{attr}\r\n")?;
        }

        Ok(())
    }
}

impl MediaDescription {
    /// Create media description which signals rejected media
    pub fn rejected(media_type: MediaType) -> Self {
        MediaDescription {
            media: Media {
                media_type,
                port: 0,
                ports_num: None,
                proto: TransportProtocol::RtpAvp,
                fmts: vec![],
            },
            connection: None,
            bandwidth: vec![],
            direction: Direction::Inactive,
            rtcp: None,
            rtcp_mux: false,
            mid: None,
            rtpmap: vec![],
            fmtp: vec![],
            ice_ufrag: None,
            ice_pwd: None,
            ice_candidates: vec![],
            ice_end_of_candidates: false,
            crypto: vec![],
            extmap: vec![],
            extmap_allow_mixed: false,
            ssrc: vec![],
            setup: None,
            fingerprint: vec![],
            attributes: vec![],
        }
    }
}
