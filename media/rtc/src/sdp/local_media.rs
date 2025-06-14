use crate::sdp::{Codec, Codecs, DirectionBools};
use sdp_types::{Direction, MediaDescription};

slotmap::new_key_type! {
    pub struct LocalMediaId;
}

pub(super) struct LocalMedia {
    pub(super) codecs: Codecs,
    pub(super) direction: DirectionBools,

    /// DTMF payload type to clockrate mapping for this media
    pub(super) dtmf: Vec<(u8, u32)>,
}

pub(super) struct ChosenCodec {
    pub(super) codec: Codec,
    pub(super) remote_pt: u8,
    pub(super) direction: DirectionBools,
    pub(super) dtmf: Option<u8>,
}

impl LocalMedia {
    pub(super) fn maybe_use_for_offer(&mut self, desc: &MediaDescription) -> Option<ChosenCodec> {
        if self.codecs.media_type != desc.media.media_type {
            return None;
        }

        self.choose_codec(desc)
    }

    pub(super) fn choose_codec_from_answer(
        &mut self,
        desc: &MediaDescription,
    ) -> Option<ChosenCodec> {
        if self.codecs.media_type != desc.media.media_type {
            return None;
        }

        self.choose_codec(desc)
    }

    fn choose_codec(&mut self, desc: &MediaDescription) -> Option<ChosenCodec> {
        for codec in &mut self.codecs.codecs {
            let pt = codec.pt.expect("pt is set when added to session");

            let codec_pt = if codec.pt_is_static {
                if desc.media.fmts.contains(&pt) {
                    Some(pt)
                } else {
                    None
                }
            } else {
                desc.rtpmap
                    .iter()
                    .find(|rtpmap| {
                        rtpmap.encoding == codec.name.as_ref()
                            && rtpmap.clock_rate == codec.clock_rate
                    })
                    .map(|rtpmap| rtpmap.payload)
            };

            let Some(codec_pt) = codec_pt else {
                continue;
            };

            let (do_send, do_receive) = match desc.direction.flipped() {
                Direction::SendRecv => (self.direction.send, self.direction.recv),
                Direction::RecvOnly => (false, self.direction.recv),
                Direction::SendOnly => (self.direction.send, false),
                Direction::Inactive => (false, false),
            };

            if !(do_send || do_receive) {
                // There would be no sender or receiver
                return None;
            }

            let dtmf = desc
                .rtpmap
                .iter()
                .find(|rtpmap| {
                    rtpmap.encoding.eq_ignore_ascii_case("telephone-event")
                        && rtpmap.clock_rate == codec.clock_rate
                })
                .map(|rtpmap| rtpmap.payload);

            return Some(ChosenCodec {
                codec: codec.clone(),
                remote_pt: codec_pt,
                direction: DirectionBools {
                    send: do_send,
                    recv: do_receive,
                },
                dtmf,
            });
        }

        None
    }
}
