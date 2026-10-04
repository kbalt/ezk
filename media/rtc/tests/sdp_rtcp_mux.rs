//! Negotiation of rtcp-mux

use bytes::Bytes;
use bytesstr::BytesStr;
use common::{make_session, satisfy_transport_changes};
use ezk_rtc::{
    ReceivedPkt,
    rtp_session::SendRtpPacket,
    rtp_transport::{RtpTransportPorts, TransportConnectionState},
    sdp::{
        RtcpMuxPolicy, SdpError, SdpSessionConfig, SdpSessionEvent, TransportChange,
        TransportCreateError, TransportType,
    },
};
use ice::Component;
use sdp_types::{Direction, SessionDescription};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use stun_types::{
    Class, Message, MessageBuilder, Method, TransactionId,
    attributes::{
        Fingerprint, IceControlling, MessageIntegrity, MessageIntegrityKey, Priority, UseCandidate,
        Username, XorMappedAddress,
    },
};

mod common;

const PEER: &str = "198.51.100.7:4000";
const PEER_PWD: &str = "peerpasswordpeerpassword12";

fn parse(sdp: &str) -> SessionDescription {
    SessionDescription::parse(&BytesStr::from(sdp.replace('\n', "\r\n"))).unwrap()
}

/// Audio offer of a peer without rtcp-mux, which only provides an ICE candidate for RTP
fn offer_without_rtcp_mux() -> SessionDescription {
    parse(
        "v=0
o=- 1 2 IN IP4 198.51.100.7
s=-
c=IN IP4 198.51.100.7
t=0 0
a=ice-ufrag:peer
a=ice-pwd:peerpasswordpeerpassword12
m=audio 4000 RTP/AVP 9
a=rtpmap:9 G722/8000
a=candidate:1 1 UDP 2130706431 198.51.100.7 4000 typ host
",
    )
}

#[test]
fn required_rtcp_mux_rejects_offer_without_it() {
    let (_, mut session) = make_session(SdpSessionConfig {
        rtcp_mux_policy: RtcpMuxPolicy::Require,
        ..Default::default()
    });

    let result = session.receive_sdp_offer(offer_without_rtcp_mux());

    assert!(
        matches!(
            result,
            Err(SdpError::CreateTransport(
                TransportCreateError::RtcpMuxRequired
            ))
        ),
        "{:?}",
        result.err()
    );
}

#[test]
fn required_rtcp_mux_rejects_answer_without_it() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_transport: TransportType::Rtp,
        rtcp_mux_policy: RtcpMuxPolicy::Require,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv, None, None);
    satisfy_transport_changes(&mut session, 1000);

    let offer = session.create_sdp_offer();
    let mid = offer.media_descriptions[0].mid.clone().unwrap();

    let answer = parse(&format!(
        "v=0
o=- 1 2 IN IP4 198.51.100.7
s=-
c=IN IP4 198.51.100.7
t=0 0
m=audio 4000 RTP/AVP 9
a=mid:{mid}
a=rtpmap:9 G722/8000
"
    ));

    let result = session.receive_sdp_answer(answer);

    assert!(
        matches!(
            result,
            Err(SdpError::CreateTransport(
                TransportCreateError::RtcpMuxRequired
            ))
        ),
        "{result:?}"
    );
}

#[test]
fn rtcp_is_dropped_when_the_peer_has_no_rtcp_candidate() {
    let (_, mut session) = make_session(SdpSessionConfig::default());

    let state = session.receive_sdp_offer(offer_without_rtcp_mux()).unwrap();

    let mut transport = None;
    while let Some(change) = session.pop_transport_change() {
        if let TransportChange::CreateSocketPair(id) = change {
            transport = Some(id);
            session.set_transport_ports(
                id,
                &["127.0.0.1".parse().unwrap()],
                RtpTransportPorts::new(30000, 30001),
            );
        }
    }

    let transport = transport.expect("no rtcp-mux, so a socket pair is created");
    let local: SocketAddr = "127.0.0.1:30000".parse().unwrap();
    let peer: SocketAddr = PEER.parse().unwrap();

    let answer = session.create_sdp_answer(state);
    let ufrag = answer.ice_ufrag.unwrap().ufrag.to_string();
    let pwd = answer.ice_pwd.unwrap().pwd.to_string();

    let mut media = None;
    while let Some(event) = session.pop_event() {
        if let SdpSessionEvent::MediaAdded(e) = event {
            media = Some((e.id, e.codec.pt.remote));
        }
    }
    let (media_id, pt) = media.unwrap();

    let deliver = |session: &mut ezk_rtc::sdp::SdpSession, now, data| {
        session.receive(
            now,
            transport,
            ReceivedPkt {
                data,
                source: peer,
                destination: local,
                component: Component::Rtp,
            },
        );
    };

    let start = Instant::now();
    let mut now = start;

    let mut transport_states = vec![];
    let mut rtp_sent = 0;
    let mut rtcp_sent = 0;

    while now < start + Duration::from_secs(12) {
        // The peer nominates the pair once the first checks have been sent
        if now == start + Duration::from_millis(100) {
            let username = format!("{ufrag}:peer");

            let mut builder =
                MessageBuilder::new(Class::Request, Method::Binding, TransactionId::random());
            builder.add_attr(Username::new(&username));
            builder.add_attr(Priority(1845501695));
            builder.add_attr(IceControlling(u64::MAX));
            builder.add_attr(UseCandidate);
            builder.add_attr_with(MessageIntegrity, MessageIntegrityKey::new(&pwd));
            builder.add_attr(Fingerprint);

            deliver(&mut session, now, builder.finish());
        }

        if let Some(mut outbound) = session.outbound_media(media_id) {
            outbound.send_rtp(SendRtpPacket::new(now, pt, Bytes::from_static(&[0; 160])));
        }

        session.poll(now);

        let mut responses = vec![];

        while let Some(event) = session.pop_event() {
            match event {
                SdpSessionEvent::SendData {
                    component,
                    data,
                    target,
                    ..
                } => {
                    assert_eq!(target, peer);

                    match Message::parse(data.clone()) {
                        Ok(msg) if msg.class() == Class::Request => {
                            // The peer answers all checks
                            let mut response = MessageBuilder::new(
                                Class::Success,
                                Method::Binding,
                                msg.transaction_id(),
                            );
                            response.add_attr(XorMappedAddress(local));
                            response.add_attr_with(
                                MessageIntegrity,
                                MessageIntegrityKey::new(PEER_PWD),
                            );
                            response.add_attr(Fingerprint);
                            responses.push(response.finish());
                        }
                        Ok(_) => {}
                        Err(_) => {
                            assert_eq!(component, Component::Rtp);

                            // RTCP packet types are 200 to 206
                            if (200..=206).contains(&data[1]) {
                                rtcp_sent += 1;
                            } else {
                                rtp_sent += 1;
                            }
                        }
                    }
                }
                SdpSessionEvent::TransportConnectionState(e) => transport_states.push(e.new),
                _ => {}
            }
        }

        for response in responses {
            deliver(&mut session, now, response);
        }

        now += Duration::from_millis(20);
    }

    assert_eq!(
        transport_states,
        [
            TransportConnectionState::Connecting,
            TransportConnectionState::Connected
        ]
    );
    assert!(rtp_sent > 500, "{rtp_sent} RTP packets sent");
    assert_eq!(rtcp_sent, 0);
}
