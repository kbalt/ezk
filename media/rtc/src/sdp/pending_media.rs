use bytesstr::BytesStr;
use sdp_types::{Direction, MediaDescription, MediaType};
use slotmap::SlotMap;

use crate::sdp::{
    AnyTransportId, EstablishedTransport, EstablishedTransportId, LocalMediaId, MediaId,
    OfferedTransportId, transport::OfferedTransport,
};

pub struct PendingMedia {
    pub(super) id: MediaId,
    pub(super) local_media_id: LocalMediaId,
    pub(super) media_type: MediaType,
    pub(super) mid: BytesStr,
    pub(super) stream_id: Option<BytesStr>,
    pub(super) track_id: Option<BytesStr>,
    pub(super) direction: Direction,
    pub(super) use_avpf: bool,
    /// Transport to use when not bundling,
    /// this is discarded when the peer chooses the bundle transport
    pub(super) standalone_transport_id: Option<AnyTransportId>,
    /// Transport to use when bundling
    pub(super) bundle_transport_id: AnyTransportId,
}

impl PendingMedia {
    /// Id of the media being offered
    pub fn id(&self) -> MediaId {
        self.id
    }

    /// Local media used for this offered media
    pub fn local_media_id(&self) -> LocalMediaId {
        self.local_media_id
    }

    /// Media type of the offered media
    pub fn media_type(&self) -> MediaType {
        self.media_type
    }

    /// mid attribute offered by this media
    ///
    /// Will be discarded if the peer does not support mid attributes
    pub fn mid(&self) -> &str {
        &self.mid
    }

    /// WebRTC MediaStream stream identifier
    pub fn stream_id(&self) -> Option<&str> {
        self.stream_id.as_deref()
    }

    /// WebRTC MediaStream track identifier
    pub fn track_id(&self) -> Option<&str> {
        self.track_id.as_deref()
    }

    /// Media direction being offered
    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub(super) fn matches_answer(
        &self,
        transports: &SlotMap<EstablishedTransportId, EstablishedTransport>,
        offered_transports: &SlotMap<OfferedTransportId, OfferedTransport>,
        desc: &MediaDescription,
    ) -> bool {
        if self.media_type != desc.media.media_type {
            return false;
        }

        if let Some(answer_mid) = &desc.mid {
            return self.mid == answer_mid.as_str();
        }

        if let Some(standalone_transport) = self.standalone_transport_id {
            let expected_sdp_transport = match standalone_transport {
                AnyTransportId::Established(transport_id) => transports[transport_id]
                    .transport
                    .type_()
                    .sdp_type(self.use_avpf),
                AnyTransportId::Offered(offered_transport_id) => offered_transports
                    [offered_transport_id]
                    .type_()
                    .sdp_type(self.use_avpf),
            };

            if expected_sdp_transport == desc.media.proto {
                return true;
            }
        }

        let expected_sdp_transport = match self.bundle_transport_id {
            AnyTransportId::Established(transport_id) => transports[transport_id]
                .transport
                .type_()
                .sdp_type(self.use_avpf),
            AnyTransportId::Offered(offered_transport_id) => offered_transports
                [offered_transport_id]
                .type_()
                .sdp_type(self.use_avpf),
        };

        expected_sdp_transport == desc.media.proto
    }
}
