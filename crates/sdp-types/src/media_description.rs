use crate::connection::Connection;
use crate::media::Media;
use crate::{bandwidth::Bandwidth, Rtcp};
use crate::{
    Direction, ExtMap, Fmtp, IceCandidate, IcePassword, IceUsernameFragment, RtpMap, SrtpCrypto,
    UnknownAttribute,
};
use bytesstr::BytesStr;
use std::fmt::{self, Debug};

/// Part of the [`SessionDescription`] describes a single media session
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

    /// Additional attributes
    pub attributes: Vec<UnknownAttribute>,
}

impl fmt::Display for MediaDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\r\n", self.media)?;

        if let Some(conn) = &self.connection {
            write!(f, "{}\r\n", conn)?;
        }

        for bw in &self.bandwidth {
            write!(f, "b={bw}\r\n")?;
        }

        write!(f, "a={}\r\n", self.direction)?;

        if let Some(rtcp) = &self.rtcp {
            write!(f, "a=rtcp:{}\r\n", rtcp)?;
        }

        if self.rtcp_mux {
            write!(f, "a=rtcp-mux\r\n")?;
        }

        if let Some(mid) = &self.mid {
            write!(f, "a=mid:{}\r\n", mid)?;
        }

        for rtpmap in &self.rtpmap {
            write!(f, "a=rtpmap:{}\r\n", rtpmap)?;
        }

        for fmtp in &self.fmtp {
            write!(f, "a=fmtp:{}\r\n", fmtp)?;
        }

        if let Some(ufrag) = &self.ice_ufrag {
            write!(f, "{}\r\n", ufrag)?;
        }

        if let Some(pwd) = &self.ice_pwd {
            write!(f, "{}\r\n", pwd)?;
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

        for attr in &self.attributes {
            write!(f, "{}\r\n", attr)?;
        }

        Ok(())
    }
}
