use bytesstr::BytesStr;
use common::{make_session, satisfy_transport_changes};
use ezk_rtc::sdp::{Codec, Codecs, SdpSessionConfig, TransportType};
use sdp_types::{Direction, MediaType, SessionDescription};

mod common;

#[test]
fn offer_mid_exists() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_transport: TransportType::DtlsSrtp,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv, None, None);

    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();

    assert_eq!(offer.media_descriptions[0].mid, Some(BytesStr::from("0")));
    assert!(
        offer.media_descriptions[0]
            .extmap
            .iter()
            .any(|x| x.uri.contains("mid"))
    );
}

#[test]
fn answer_mid_exists() {
    let (_audio, mut session) = make_session(SdpSessionConfig::default());

    let offer = "\
v=0
o=- 34908 21938 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 1000 RTP/AVP 9
a=sendrecv
a=mid:audio-0
a=rtpmap:9 G722/8000/1
";

    let offer = SessionDescription::parse(&BytesStr::from_static(offer)).unwrap();

    let answer = session.receive_sdp_offer(offer).unwrap();

    satisfy_transport_changes(&mut session, 1000);

    let answer = session.create_sdp_answer(answer);

    assert_eq!(
        answer.media_descriptions[0].mid,
        Some(BytesStr::from("audio-0"))
    );
}

#[test]
fn answer_without_mid_if_none_is_offered() {
    let (_audio, mut session) = make_session(SdpSessionConfig::default());

    let offer = "\
v=0
o=- 34908 21938 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 1000 RTP/AVP 9
a=sendrecv
a=rtpmap:9 G722/8000/1
";

    let offer = SessionDescription::parse(&BytesStr::from_static(offer)).unwrap();

    let answer = session.receive_sdp_offer(offer).unwrap();

    satisfy_transport_changes(&mut session, 1000);

    let answer = session.create_sdp_answer(answer);

    assert_eq!(answer.media_descriptions[0].mid, None);
}

#[test]
fn keep_mid_throughout_renegotiation() {
    let (_audio, mut session) = make_session(SdpSessionConfig::default());

    let offer = "\
v=0
o=- 34908 21938 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 1000 RTP/AVP 9
a=sendrecv
a=mid:audio-0
a=rtpmap:9 G722/8000/1
";

    let offer = SessionDescription::parse(&BytesStr::from_static(offer)).unwrap();

    let answer = session.receive_sdp_offer(offer).unwrap();

    satisfy_transport_changes(&mut session, 1000);

    let answer = session.create_sdp_answer(answer);

    assert_eq!(
        answer.media_descriptions[0].mid,
        Some(BytesStr::from_static("audio-0"))
    );

    let video = session
        .add_local_media(
            Codecs::new(MediaType::Video).with_codec(Codec::H264),
            Direction::SendRecv,
        )
        .unwrap();

    session.add_media(video, Direction::SendRecv, None, None);

    satisfy_transport_changes(&mut session, 2000);

    let offer = session.create_sdp_offer();

    assert_eq!(
        offer.media_descriptions[0].mid,
        Some(BytesStr::from_static("audio-0"))
    );
    assert_eq!(
        offer.media_descriptions[1].mid,
        Some(BytesStr::from_static("1"))
    );
}
