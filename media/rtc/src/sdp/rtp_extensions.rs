use bytesstr::BytesStr;
use rtp::RtpExtensionIds;
use sdp_types::{Direction, ExtMap, MediaDescription, MediaType, SessionDescription};

const RTP_MID_HDREXT: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const RTP_AUDIO_LEVEL_HDREXT: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
const RTP_TWCC_HDREXT: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

pub(crate) trait RtpExtensionIdsExt {
    fn offer(media_type: MediaType) -> Self;
    fn from_sdp(session_desc: &SessionDescription, media_desc: &MediaDescription) -> Self;
    fn to_extmap(&self) -> Vec<ExtMap>;
}

impl RtpExtensionIdsExt for RtpExtensionIds {
    fn offer(media_type: MediaType) -> Self {
        RtpExtensionIds {
            mid: Some(1),
            audio_level: Some(2).filter(|_| media_type == MediaType::Audio),
            twcc_sequence_number: Some(3),
        }
    }

    fn from_sdp(session_desc: &SessionDescription, media_desc: &MediaDescription) -> Self {
        fn from_extmaps(v: &[ExtMap]) -> RtpExtensionIds {
            RtpExtensionIds {
                mid: v
                    .iter()
                    .find(|extmap| extmap.extension_name == RTP_MID_HDREXT)
                    .map(|extmap| extmap.id),
                audio_level: v
                    .iter()
                    .find(|extmap| extmap.extension_name == RTP_AUDIO_LEVEL_HDREXT)
                    .map(|extmap| extmap.id),
                twcc_sequence_number: v
                    .iter()
                    .find(|extmap| extmap.extension_name == RTP_TWCC_HDREXT)
                    .map(|extmap| extmap.id),
            }
        }

        let a = from_extmaps(&session_desc.extmap);
        let b = from_extmaps(&media_desc.extmap);

        Self {
            mid: b.mid.or(a.mid),
            audio_level: b.audio_level.or(a.audio_level),
            twcc_sequence_number: b.twcc_sequence_number.or(a.twcc_sequence_number),
        }
    }

    fn to_extmap(&self) -> Vec<ExtMap> {
        let mut extmap = vec![];

        if let Some(mid_id) = self.mid {
            extmap.push(ExtMap {
                id: mid_id,
                direction: Direction::SendRecv,
                extension_name: BytesStr::from_static(RTP_MID_HDREXT),
                extension_attributes: vec![],
            });
        }

        if let Some(audio_level) = self.audio_level {
            extmap.push(ExtMap {
                id: audio_level,
                direction: Direction::SendRecv,
                extension_name: BytesStr::from_static(RTP_AUDIO_LEVEL_HDREXT),
                extension_attributes: vec![BytesStr::from_static("vad=on")],
            });
        }

        if let Some(twcc_sequence_number) = self.twcc_sequence_number {
            extmap.push(ExtMap {
                id: twcc_sequence_number,
                direction: Direction::SendRecv,
                extension_name: BytesStr::from_static(RTP_TWCC_HDREXT),
                extension_attributes: vec![],
            });
        }

        extmap
    }
}
