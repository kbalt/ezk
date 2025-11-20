use crate::sdp::{Codec, Codecs, DirectionBools, media::PtPair};
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
    pub(super) pt: PtPair,
    pub(super) rtx_pt: Option<PtPair>,
    pub(super) dtmf_pt: Option<PtPair>,
    pub(super) direction: DirectionBools,
}

impl LocalMedia {
    pub(super) fn maybe_use_for_offer(&mut self, desc: &MediaDescription) -> Option<ChosenCodec> {
        if self.codecs.media_type != desc.media.media_type {
            return None;
        }

        self.choose_codec(desc, true)
    }

    pub(super) fn choose_codec_from_answer(
        &mut self,
        desc: &MediaDescription,
    ) -> Option<ChosenCodec> {
        if self.codecs.media_type != desc.media.media_type {
            return None;
        }

        self.choose_codec(desc, false)
    }

    fn choose_codec(&self, desc: &MediaDescription, is_remote_offer: bool) -> Option<ChosenCodec> {
        for codec in &self.codecs.codecs {
            let codec_pt = codec.offer_pt.expect("pt is set when added to session");

            let codec_pt = if codec.pt_is_static {
                if desc.media.fmts.contains(&codec_pt) {
                    Some(codec_pt)
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

            let rtx_pt = if codec.allow_rtx {
                desc.rtpmap.iter().find_map(|rtpmap| {
                    if !rtpmap.encoding.eq_ignore_ascii_case("rtx")
                        || rtpmap.clock_rate != codec.clock_rate
                    {
                        return None;
                    }

                    let fmtp = desc
                        .fmtp
                        .iter()
                        .find(|fmtp| fmtp.format == rtpmap.payload)?;

                    let apt_index = fmtp.params.find("apt=")?;
                    let apt_value = &fmtp.params[apt_index + 4..];
                    let apt_value_len =
                        apt_value.bytes().take_while(|b| b.is_ascii_digit()).count();

                    let apt_pt: u8 = apt_value[..apt_value_len].parse().ok()?;

                    if apt_pt != codec_pt {
                        return None;
                    }

                    Some(PtPair {
                        local: if is_remote_offer {
                            rtpmap.payload
                        } else {
                            codec.offer_rtx_pt?
                        },
                        remote: rtpmap.payload,
                    })
                })
            } else {
                None
            };

            let dtmf_pt = desc.rtpmap.iter().find_map(|rtpmap| {
                // Must be telephone event
                if !rtpmap.encoding.eq_ignore_ascii_case("telephone-event") {
                    return None;
                }

                // Must match the codecs clock rate
                if rtpmap.clock_rate != codec.clock_rate {
                    return None;
                }

                Some(PtPair {
                    local: if is_remote_offer {
                        rtpmap.payload
                    } else {
                        // Make sure to use our offered payload type as local pt
                        self.dtmf
                            .iter()
                            .find(|(_, clock_rate)| *clock_rate == codec.clock_rate)?
                            .0
                    },
                    remote: rtpmap.payload,
                })
            });

            let pt = PtPair {
                local: if is_remote_offer {
                    codec_pt
                } else {
                    codec.offer_pt.unwrap()
                },
                remote: codec_pt,
            };

            return Some(ChosenCodec {
                codec: codec.clone(),
                pt,
                rtx_pt,
                dtmf_pt,
                direction: DirectionBools {
                    send: do_send,
                    recv: do_receive,
                },
            });
        }

        None
    }
}
