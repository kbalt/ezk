use crate::{Codec, Codecs, DirectionBools};
use sdp_types::{Direction, MediaDescription};

pub(super) struct LocalMedia {
    pub(super) codecs: Codecs,
    pub(super) limit: u32,
    pub(super) direction: DirectionBools,
    pub(super) use_count: u32,
}

impl LocalMedia {
    pub(super) fn maybe_use_for_offer(
        &mut self,
        desc: &MediaDescription,
    ) -> Option<(Codec, u8, DirectionBools)> {
        if self.limit == self.use_count || self.codecs.media_type != desc.media.media_type {
            return None;
        }

        self.choose_codec(desc)
    }

    pub(super) fn choose_codec_from_answer(
        &mut self,
        desc: &MediaDescription,
    ) -> Option<(Codec, u8, DirectionBools)> {
        if self.codecs.media_type != desc.media.media_type {
            return None;
        }

        self.choose_codec(desc)
    }

    fn choose_codec(&mut self, desc: &MediaDescription) -> Option<(Codec, u8, DirectionBools)> {
        // Try choosing a codec
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

            self.use_count += 1;

            return Some((
                codec.clone(),
                codec_pt,
                DirectionBools {
                    send: do_send,
                    recv: do_receive,
                },
            ));
        }

        None
    }
}
