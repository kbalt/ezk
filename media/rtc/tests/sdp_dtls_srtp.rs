use bytesstr::BytesStr;
use common::{make_session, satisfy_transport_changes};
use ezk_rtc::sdp::{SdpSessionConfig, TransportType};
use sdp_types::{Direction, SessionDescription, Setup, TransportProtocol};

mod common;

#[test]
fn dtls_srtp_offer_contains_fingerprint_and_setup_attributes() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_transport: TransportType::DtlsSrtp,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();

    assert_eq!(
        offer.media_descriptions[0].media.proto,
        TransportProtocol::UdpTlsRtpSavp
    );
    // DTLS certificate is the same for every DTLS transport, so the fingerprint should be set in the session level
    assert!(!offer.fingerprint.is_empty());
    assert!(offer.media_descriptions[0].fingerprint.is_empty());

    // Setup attribute must be set on the media level so it can be different per transport
    // depending on which side initiated the (re)-negotiation, the receiver of the offer should be passive
    assert_eq!(offer.setup, None);
    assert_eq!(offer.media_descriptions[0].setup, Some(Setup::ActPass));
}

#[test]
fn dtls_srtp_answer_contains_fingerprint_and_setup_attribute() {
    let (_audio, mut session) = make_session(SdpSessionConfig::default());

    let offer = "\
v=0
o=- 34908 21938 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
a=fingerprint:SHA-256 B5:38:75:EC:07:2E:3B:3A:B0:76:5F:4C:53:AD:28:96:B3:42:D1:98:3F:2D:05:A8:D2:1A:DB:E5:C7:AA:41:01
m=audio 1000 UDP/TLS/RTP/SAVP 9
a=sendrecv
a=setup:actpass
a=rtpmap:9 G722/8000/1
";

    let offer = SessionDescription::parse(&BytesStr::from_static(offer)).unwrap();

    let answer = session.receive_sdp_offer(offer).unwrap();

    satisfy_transport_changes(&mut session, 1000);

    let answer = session.create_sdp_answer(answer);

    assert_eq!(
        answer.media_descriptions[0].media.proto,
        TransportProtocol::UdpTlsRtpSavp
    );

    // Make sure the fingerprint is in the session level
    assert_eq!(answer.fingerprint.len(), 1);
    // No fingerprint in media level
    assert!(answer.media_descriptions[0].fingerprint.is_empty());

    // Setup attribute must be set on the media level so it can be different per transport
    // depending on which side initiated the (re)-negotiation, the receiver of the offer should be passive
    assert_eq!(answer.setup, None);
    assert_eq!(answer.media_descriptions[0].setup, Some(Setup::Passive));
}
