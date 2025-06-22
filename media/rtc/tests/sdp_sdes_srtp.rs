use bytesstr::BytesStr;
use common::{make_session, satisfy_transport_changes};
use ezk_rtc::sdp::{SdpSessionConfig, TransportType};
use sdp_types::{Direction, SessionDescription, TransportProtocol};

mod common;

#[test]
fn sdes_srtp_offer_contains_crypto_attributes() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_transport: TransportType::SdesSrtp,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();

    assert_eq!(
        offer.media_descriptions[0].media.proto,
        TransportProtocol::RtpSavp
    );
    assert!(!offer.media_descriptions[0].crypto.is_empty());
}

#[test]
fn sdes_srtp_answer_contains_crypto_attribute() {
    let (_audio, mut session) = make_session(SdpSessionConfig::default());

    let offer = "\
v=0
o=- 34908 21938 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 1000 RTP/SAVP 9
a=sendrecv
a=rtpmap:9 G722/8000/1
a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:aZjlF+tsZ/epXRgDNHNKNUFpOfjnOVBSmSK2fuhI+fobKOQOrES5ilisKabUgw==
a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:XVvmZsWD2CBI+Nk0lAqjI9tW3/Q9mddT/c6Q4AQx554KqT+6xmqK0KWdATrU3Q==
a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:94NsFrS7r61M6qwn+HncDyy3fBQVtVzAaHc/UwGh
a=crypto:4 AES_CM_128_HMAC_SHA1_32 inline:BWcpA2xdzwrB2EZeXDmr8Tllr4SPnAyvPhXXAV3t
";

    let offer = SessionDescription::parse(&BytesStr::from_static(offer)).unwrap();

    let answer = session.receive_sdp_offer(offer.clone()).unwrap();

    satisfy_transport_changes(&mut session, 1000);

    let answer = session.create_sdp_answer(answer);

    assert_eq!(
        answer.media_descriptions[0].media.proto,
        TransportProtocol::RtpSavp
    );
    assert_eq!(answer.media_descriptions[0].crypto.len(), 1);
    assert!(offer.media_descriptions[0].crypto.iter().any(|c| {
        let answer = &answer.media_descriptions[0].crypto[0];
        c.suite == answer.suite && c.tag == answer.tag
    }));
}
