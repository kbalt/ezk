use common::{make_session, satisfy_transport_changes};
use ezk_rtc::sdp::{
    BundlePolicy, Codec, Codecs, LocalMediaId, MediaId, RtcpMuxPolicy, SdpSession,
    SdpSessionConfig, TransportType,
};
use sdp_types::{Direction, MediaType, RtcpFeedbackKind, TransportProtocol};

mod common;

fn make_audio_video_session(offer_avpf: bool) -> (LocalMediaId, LocalMediaId, SdpSession) {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_transport: TransportType::Rtp,
        offer_avpf,
        bundle_policy: BundlePolicy::MaxBundle,
        rtcp_mux_policy: RtcpMuxPolicy::Require,
        ..Default::default()
    });

    let video = session
        .add_local_media(
            Codecs::new(MediaType::Video).with_codec(Codec::H264),
            Direction::SendRecv,
        )
        .unwrap();
    (audio, video, session)
}

#[test]
fn rtcp_fb_exchange_avp() {
    let (audio, video, mut offer_session) = make_audio_video_session(
        // do not offer AVPF
        false,
    );

    let audio_media_id = offer_session.add_media(audio, Direction::SendRecv, None, None);
    let video_media_id = offer_session.add_media(video, Direction::SendRecv, None, None);

    satisfy_transport_changes(&mut offer_session, 1000);

    let offer = offer_session.create_sdp_offer();

    assert_eq!(
        offer.media_descriptions[0].media.proto,
        TransportProtocol::RtpAvp
    );
    assert_eq!(
        offer.media_descriptions[1].media.proto,
        TransportProtocol::RtpAvp
    );
    // Neither Audio nor Video can contain rtcp-fb attributes
    assert!(offer.media_descriptions[0].rtcp_fb.is_empty());
    assert!(offer.media_descriptions[1].rtcp_fb.is_empty());

    let (_, _, mut answer_session) = make_audio_video_session(
        // do not offer AVPF
        false,
    );

    let answer = answer_session.receive_sdp_offer(offer).unwrap();
    satisfy_transport_changes(&mut answer_session, 1000);
    let answer = answer_session.create_sdp_answer(answer);

    assert_eq!(
        answer.media_descriptions[0].media.proto,
        TransportProtocol::RtpAvp
    );
    assert_eq!(
        answer.media_descriptions[1].media.proto,
        TransportProtocol::RtpAvp
    );

    assert!(answer.media_descriptions[0].rtcp_fb.is_empty());
    assert!(answer.media_descriptions[1].rtcp_fb.is_empty());

    offer_session.receive_sdp_answer(answer).unwrap();

    assert!(!offer_session.media(audio_media_id).unwrap().accepts_pli());
    assert!(!offer_session.media(audio_media_id).unwrap().accepts_fir());

    assert!(!offer_session.media(video_media_id).unwrap().accepts_pli());
    assert!(!offer_session.media(video_media_id).unwrap().accepts_fir());

    let media_ids: Vec<MediaId> = answer_session.media_iter().map(|m| m.id()).collect();
    let audio_media_id = media_ids[0];
    let video_media_id = media_ids[1];

    assert!(!answer_session.media(audio_media_id).unwrap().accepts_pli());
    assert!(!answer_session.media(audio_media_id).unwrap().accepts_fir());

    assert!(!answer_session.media(video_media_id).unwrap().accepts_pli());
    assert!(!answer_session.media(video_media_id).unwrap().accepts_fir());
}

#[test]
fn rtcp_fb_avpf_offer_contains_fb() {
    let (audio, video, mut offer_session) = make_audio_video_session(
        // DO offer AVPF
        true,
    );

    let audio_media_id = offer_session.add_media(audio, Direction::SendRecv, None, None);
    let video_media_id = offer_session.add_media(video, Direction::SendRecv, None, None);

    satisfy_transport_changes(&mut offer_session, 1000);

    let offer = offer_session.create_sdp_offer();

    assert_eq!(
        offer.media_descriptions[0].media.proto,
        TransportProtocol::RtpAvpf
    );
    // Audio must not contain PLI & FIR feedback types
    assert!(offer.media_descriptions[0].rtcp_fb.is_empty());

    assert_eq!(
        offer.media_descriptions[1].media.proto,
        TransportProtocol::RtpAvpf
    );
    // Video must contain PLI & FIR feedback types
    assert_eq!(offer.media_descriptions[1].rtcp_fb.len(), 3);
    assert!(offer.media_descriptions[1].rtcp_fb[0].kind == RtcpFeedbackKind::Nack);
    assert!(offer.media_descriptions[1].rtcp_fb[1].kind == RtcpFeedbackKind::NackPli);
    assert!(offer.media_descriptions[1].rtcp_fb[2].kind == RtcpFeedbackKind::CcmFir);
    // assert!(offer.media_descriptions[1].rtcp_fb[3].kind == RtcpFeedbackKind::TransportCC);

    let (_, _, mut answer_session) = make_audio_video_session(true);

    let answer = answer_session.receive_sdp_offer(offer).unwrap();
    satisfy_transport_changes(&mut answer_session, 1000);
    let answer = answer_session.create_sdp_answer(answer);

    assert_eq!(
        answer.media_descriptions[0].media.proto,
        TransportProtocol::RtpAvpf
    );
    assert_eq!(
        answer.media_descriptions[1].media.proto,
        TransportProtocol::RtpAvpf
    );

    assert!(answer.media_descriptions[0].rtcp_fb.is_empty());
    assert_eq!(answer.media_descriptions[1].rtcp_fb.len(), 3);
    assert!(answer.media_descriptions[1].rtcp_fb[0].kind == RtcpFeedbackKind::Nack);
    assert!(answer.media_descriptions[1].rtcp_fb[1].kind == RtcpFeedbackKind::NackPli);
    assert!(answer.media_descriptions[1].rtcp_fb[2].kind == RtcpFeedbackKind::CcmFir);
    // assert!(answer.media_descriptions[1].rtcp_fb[3].kind == RtcpFeedbackKind::TransportCC);

    offer_session.receive_sdp_answer(answer).unwrap();

    assert!(!offer_session.media(audio_media_id).unwrap().accepts_pli());
    assert!(!offer_session.media(audio_media_id).unwrap().accepts_fir());

    assert!(offer_session.media(video_media_id).unwrap().accepts_pli());
    assert!(offer_session.media(video_media_id).unwrap().accepts_fir());

    let media_ids: Vec<MediaId> = answer_session.media_iter().map(|m| m.id()).collect();
    let audio_media_id = media_ids[0];
    let video_media_id = media_ids[1];

    assert!(!answer_session.media(audio_media_id).unwrap().accepts_pli());
    assert!(!answer_session.media(audio_media_id).unwrap().accepts_fir());

    assert!(answer_session.media(video_media_id).unwrap().accepts_pli());
    assert!(answer_session.media(video_media_id).unwrap().accepts_fir());
}
