use crate::{
    rtp_transport::Connectivity,
    sdp::{Codec, DirectionBools, EstablishedTransport, EstablishedTransportId, LocalMediaId},
};
use bytesstr::BytesStr;
use rtp::Ssrc;
use sdp_types::{Direction, MediaDescription, MediaType, SessionDescription};
use slotmap::SlotMap;

pub struct Media {
    pub(super) id: MediaId,
    pub(super) local_media_id: LocalMediaId,
    pub(super) media_type: MediaType,

    /// Wether to use the extended RTP profile for realtime RTCP feedback
    pub(super) use_avpf: bool,

    /// media id attribute used in SDP and RTP. Only set if the peer supports it.
    pub(super) mid: Option<BytesStr>,
    pub(super) direction: DirectionBools,
    pub(super) streams: MediaStreams,

    /// transport used by the media. May be shared with others if transport bundling is used
    pub(super) transport_id: EstablishedTransportId,

    /// negotiated media payload type
    pub(super) codec_pt: u8,
    pub(super) codec: Codec,

    /// negotiated telephone-event payload type with the same clock-rate as codec
    pub(super) dtmf_pt: Option<u8>,

    /// Picture Loss Indication RTCP feedback was negotiated for the selected coded of this media
    pub(super) accepts_nack_pli: bool,
    /// Full Intra Request RTCP feedback was negotiated for the selected coded of this media
    pub(super) accepts_ccm_fir: bool,
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

    pub(super) fn accepts_pt(&self, pt: u8) -> bool {
        self.codec_pt == pt || self.dtmf_pt == Some(pt)
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
}
