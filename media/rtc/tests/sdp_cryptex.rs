//! Negotiation of cryptex ([RFC 9335]) via the `a=cryptex` SDP attribute
//!
//! [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335

use bytesstr::BytesStr;
use common::{make_session, satisfy_transport_changes};
use ezk_rtc::sdp::{BundlePolicy, SdpSessionConfig, TransportType};
use sdp_types::{Direction, SessionDescription};

mod common;

fn offer_with_cryptex(cryptex: bool) -> SessionDescription {
    let session_attr = if cryptex { "a=cryptex\n" } else { "" };

    let offer = format!(
        "\
v=0
o=- 34908 21938 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
a=fingerprint:SHA-256 B5:38:75:EC:07:2E:3B:3A:B0:76:5F:4C:53:AD:28:96:B3:42:D1:98:3F:2D:05:A8:D2:1A:DB:E5:C7:AA:41:01
{session_attr}m=audio 1000 UDP/TLS/RTP/SAVP 9
a=sendrecv
a=setup:actpass
a=rtpmap:9 G722/8000/1
"
    );

    SessionDescription::parse(&BytesStr::from(offer)).unwrap()
}

#[test]
fn an_offer_advertises_cryptex_at_the_media_level_by_default() {
    for transport in [TransportType::DtlsSrtp, TransportType::SdesSrtp] {
        let (audio, mut session) = make_session(SdpSessionConfig {
            offer_transport: transport,
            enable_cryptex: true,
            ..Default::default()
        });

        session.add_media(audio, Direction::SendRecv, None, None);
        satisfy_transport_changes(&mut session, 1000);

        let offer = session.create_sdp_offer();

        assert!(offer.media_descriptions[0].cryptex, "{transport:?}");
        assert!(!offer.cryptex, "{transport:?} session level");
    }
}

#[test]
fn non_srtp_doesnt_offer_cryptex() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_transport: TransportType::Rtp,
        enable_cryptex: true,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv, None, None);
    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();

    assert!(!offer.media_descriptions[0].cryptex);
    assert!(!offer.cryptex);
}

#[test]
fn dont_offer_cryptex_when_disabled() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        enable_cryptex: false,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv, None, None);
    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();

    assert!(!offer.media_descriptions[0].cryptex);
    assert!(!offer.cryptex);
}

#[test]
fn an_answer_echoes_a_session_level_cryptex_attribute() {
    let (_audio, mut session) = make_session(SdpSessionConfig {
        enable_cryptex: true,
        ..Default::default()
    });

    let state = session.receive_sdp_offer(offer_with_cryptex(true)).unwrap();
    satisfy_transport_changes(&mut session, 1000);
    let answer = session.create_sdp_answer(state);

    assert!(answer.media_descriptions[0].cryptex);
}

#[test]
fn an_answer_omits_cryptex_when_the_offer_lacked_it() {
    let (_audio, mut session) = make_session(SdpSessionConfig::default());

    let state = session
        .receive_sdp_offer(offer_with_cryptex(false))
        .unwrap();
    satisfy_transport_changes(&mut session, 1000);
    let answer = session.create_sdp_answer(state);

    assert!(!answer.media_descriptions[0].cryptex);
}

#[test]
fn a_disabled_answerer_omits_cryptex() {
    let (_audio, mut session) = make_session(SdpSessionConfig {
        enable_cryptex: false,
        ..Default::default()
    });

    let state = session.receive_sdp_offer(offer_with_cryptex(true)).unwrap();
    satisfy_transport_changes(&mut session, 1000);
    let answer = session.create_sdp_answer(state);

    assert!(!answer.media_descriptions[0].cryptex);
}

#[test]
fn bundled_media_agree_on_cryptex() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_transport: TransportType::DtlsSrtp,
        bundle_policy: BundlePolicy::MaxBundle,
        enable_cryptex: true,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv, None, None);
    session.add_media(audio, Direction::SendRecv, None, None);
    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();

    let bundled: Vec<bool> = offer
        .media_descriptions
        .iter()
        .map(|desc| desc.cryptex)
        .collect();

    assert!(
        bundled.iter().all(|&c| c) || bundled.iter().all(|&cryptex| !cryptex),
        "bundle group disagrees on cryptex: {bundled:?}"
    );
    assert!(bundled.iter().all(|&c| c), "expected cryptex throughout");
}

#[test]
fn a_subsequent_offer_restates_the_negotiated_value() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        enable_cryptex: true,
        ..Default::default()
    });

    let state = session.receive_sdp_offer(offer_with_cryptex(true)).unwrap();
    satisfy_transport_changes(&mut session, 1000);
    let answer = session.create_sdp_answer(state);
    assert!(answer.media_descriptions[0].cryptex);

    session.add_media(audio, Direction::SendRecv, None, None);
    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();

    assert!(
        offer.media_descriptions[0].cryptex,
        "the established transport stopped advertising cryptex"
    );
}

#[test]
fn a_subsequent_offer_does_not_reintroduce_cryptex() {
    let (audio, mut session) = make_session(SdpSessionConfig::default());

    let state = session
        .receive_sdp_offer(offer_with_cryptex(false))
        .unwrap();
    satisfy_transport_changes(&mut session, 1000);
    let answer = session.create_sdp_answer(state);
    assert!(!answer.media_descriptions[0].cryptex);

    session.add_media(audio, Direction::SendRecv, None, None);
    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();

    assert!(!offer.media_descriptions[0].cryptex);
}
