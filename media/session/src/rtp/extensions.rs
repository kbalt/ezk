use bytesstr::BytesStr;
use rtp::RtpExtensionIds;
use sdp_types::{Direction, ExtMap, MediaDescription, SessionDescription};

const RTP_MID_HDREXT: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";

pub(crate) trait RtpExtensionIdsExt {
    fn offer() -> Self;
    fn from_sdp(session_desc: &SessionDescription, media_desc: &MediaDescription) -> Self;
    fn to_extmap(&self) -> Vec<ExtMap>;
}

impl RtpExtensionIdsExt for RtpExtensionIds {
    fn offer() -> Self {
        RtpExtensionIds { mid: Some(1) }
    }

    fn from_sdp(session_desc: &SessionDescription, media_desc: &MediaDescription) -> Self {
        fn from_extmaps(v: &[ExtMap]) -> RtpExtensionIds {
            RtpExtensionIds {
                mid: v
                    .iter()
                    .find(|extmap| extmap.uri == RTP_MID_HDREXT)
                    .map(|extmap| extmap.id),
            }
        }

        let a = from_extmaps(&session_desc.extmap);
        let b = from_extmaps(&media_desc.extmap);

        Self {
            mid: b.mid.or(a.mid),
        }
    }

    fn to_extmap(&self) -> Vec<ExtMap> {
        let mut extmap = vec![];

        if let Some(mid_id) = self.mid {
            extmap.push(ExtMap {
                id: mid_id,
                uri: BytesStr::from_static(RTP_MID_HDREXT),
                direction: Direction::SendRecv,
            });
        }

        extmap
    }
}
