use crate::{
    rtp_transport::Connectivity,
    sdp::{Codec, DirectionBools, EstablishedTransport, EstablishedTransportId, LocalMediaId},
};
use bytesstr::BytesStr;
use rtp::Ssrc;
use sdp_types::{Direction, MediaDescription, MediaType, SessionDescription};
use slotmap::SlotMap;

/// Technically represents a single payload type, with different payload types for local and remote
///
/// While rare some implementations do sometimes respond with different payload types than offered
#[derive(Debug, Clone, Copy)]
pub struct PtPair {
    pub local: u8,
    pub remote: u8,
}

pub struct Media {
    pub(super) id: MediaId,
    pub(super) local_media_id: LocalMediaId,
    pub(super) media_type: MediaType,

    pub(super) stream_id: Option<BytesStr>,
    pub(super) track_id: Option<BytesStr>,

    /// Wether to use the extended RTP profile for realtime RTCP feedback
    pub(super) use_avpf: bool,

    /// media id attribute used in SDP and RTP. Only set if the peer supports it.
    pub(super) mid: Option<BytesStr>,
    pub(super) direction: DirectionBools,
    pub(super) streams: MediaStreams,

    /// transport used by the media. May be shared with others if transport bundling is used
    pub(super) transport_id: EstablishedTransportId,

    /// negotiated media payload type
    pub(super) codec_pt: PtPair,
    pub(super) codec: Codec,

    // negotiated rtx payload types
    pub(super) rtx_pt: Option<PtPair>,

    /// negotiated telephone-event payload type with the same clock-rate as codec
    pub(super) dtmf_pt: Option<PtPair>,

    /// Accept generic RTCP nack
    pub(super) accepts_nack: bool,
    /// Accepts Picture Loss Indication feedback requests
    pub(super) accepts_nack_pli: bool,
    /// Accepts Full Intra Request feedback requests
    pub(super) accepts_ccm_fir: bool,
    /// Accepts Transport Wide Congestion Control messages
    pub(super) accepts_transport_cc: bool,
}

impl Media {
    /// Id of this media
    pub fn id(&self) -> MediaId {
        self.id
    }

    /// Id of the local media used for this
    pub fn local_media_id(&self) -> LocalMediaId {
        self.local_media_id
    }

    /// Type of media, e.g. audio, video etc..
    pub fn media_type(&self) -> MediaType {
        self.media_type
    }

    /// `mid` attribute used by this media
    ///
    /// Returns `None` if the peer does not support `mid` attributes
    pub fn mid(&self) -> Option<&str> {
        self.mid.as_deref()
    }

    /// WebRTC MediaStream stream identifier
    pub fn stream_id(&self) -> Option<&str> {
        self.stream_id.as_deref()
    }

    /// WebRTC MediaStream track identifier
    pub fn track_id(&self) -> Option<&str> {
        self.track_id.as_deref()
    }

    /// Direction of this media
    pub fn direction(&self) -> Direction {
        self.direction.into()
    }

    /// Does the media support sending RTCP "Picture Loss Indication" transport feedback
    pub fn accepts_pli(&self) -> bool {
        self.accepts_nack_pli
    }

    /// Does the media support sending RTCP "Full Intra Refresh" transport feedback
    pub fn accepts_fir(&self) -> bool {
        self.accepts_ccm_fir
    }

    /// Check if the media matches a media section in SDP
    pub(super) fn matches(
        &self,
        transports: &SlotMap<EstablishedTransportId, EstablishedTransport>,
        sess: &SessionDescription,
        desc: &MediaDescription,
    ) -> bool {
        // TODO: include check for negotiated codec in here

        if self.media_type != desc.media.media_type {
            return false;
        }

        // Check for the media id attribute
        if self.mid.is_some() {
            return self.mid == desc.mid;
        }

        if let Some(e) = transports.get(self.transport_id) {
            match e.transport.connectivity() {
                Connectivity::Static {
                    remote_rtp_address,
                    remote_rtcp_address: _,
                } => remote_rtp_address.port() == desc.media.port,
                Connectivity::Ice(..) => sess.ice_ufrag.is_some() || desc.ice_ufrag.is_some(),
            }
        } else {
            false
        }
    }

    /// Returns if the payload type is actual media, excludes rtx streams
    pub(super) fn is_remote_media_pt(&self, pt: u8) -> bool {
        self.codec_pt.remote == pt || self.dtmf_pt.is_some_and(|x| x.remote == pt)
    }

    /// Returns if the payload type is actual media, excludes rtx streams
    pub(super) fn accepts_pt(&self, pt: u8) -> bool {
        self.codec_pt.remote == pt
            || self.rtx_pt.is_some_and(|x| x.remote == pt)
            || self.dtmf_pt.is_some_and(|x| x.remote == pt)
    }
}

#[derive(Default)]
pub(super) struct MediaStreams {
    pub(super) tx: Option<Ssrc>,
    pub(super) rx: Option<Ssrc>,
}

/// Identifies a single media stream.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MediaId(pub(crate) u32);

impl MediaId {
    pub(crate) fn increment(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }

    /// Returns the internal representation of the media id. This will always be unique inside a [`SdpSession`].
    pub fn repr(&self) -> u32 {
        self.0
    }
}
