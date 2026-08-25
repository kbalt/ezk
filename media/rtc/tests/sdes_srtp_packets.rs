//! Push real RTP through a negotiated SDES-SRTP transport.
//!
//! The other SDP tests only assert on offer/answer contents. This one runs two sessions
//! against each other and moves protected packets between them, which is what exercises
//! the protect/unprotect call sites and the buffer rotation in `rtp_transport`.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use bytes::Bytes;
use ezk_rtc::{
    rtp_session::SendRtpPacket,
    rtp_transport::RtpTransportPorts,
    sdp::{
        Codec, Codecs, SdpSession, SdpSessionConfig, SdpSessionEvent, TransportChange, TransportId,
        TransportType,
    },
};
use ice::ReceivedPkt;
use sdp_types::{Direction, MediaType};

const PAYLOAD: &[u8] = b"the quick brown fox jumps over the lazy dog";

/// Like the shared `satisfy_transport_changes` helper, but keeps the transport id so
/// received packets can be routed back in
fn satisfy(session: &mut SdpSession, port: u16) -> Option<TransportId> {
    let mut id = None;

    while let Some(change) = session.pop_transport_change() {
        match change {
            TransportChange::CreateSocket(transport_id) => {
                id = Some(transport_id);
                session.set_transport_ports(
                    transport_id,
                    &[Ipv4Addr::LOCALHOST.into()],
                    RtpTransportPorts::mux(port),
                );
            }
            TransportChange::CreateSocketPair(transport_id) => {
                id = Some(transport_id);
                session.set_transport_ports(
                    transport_id,
                    &[Ipv4Addr::LOCALHOST.into()],
                    RtpTransportPorts::new(port, port + 1),
                );
            }
            TransportChange::Remove(..) | TransportChange::RemoveRtcpSocket(..) => {}
        }
    }

    id
}

fn session(port: u16) -> (SdpSession, Option<TransportId>) {
    let mut session = SdpSession::new(
        Ipv4Addr::LOCALHOST.into(),
        SdpSessionConfig {
            offer_transport: TransportType::SdesSrtp,
            ..Default::default()
        },
    );

    let media = session
        .add_local_media(
            Codecs::new(MediaType::Audio).with_codec(Codec::G722),
            Direction::SendRecv,
        )
        .unwrap();

    session.add_media(media, Direction::SendRecv, None, None);
    let id = satisfy(&mut session, port);

    (session, id)
}

#[test]
fn rtp_survives_a_negotiated_sdes_srtp_transport() {
    const PORT1: u16 = 45100;
    const PORT2: u16 = 45200;

    let (mut session1, _) = session(PORT1);
    let (mut session2, _) = session(PORT2);

    let offer = session1.create_sdp_offer();
    let pending = session2.receive_sdp_offer(offer).unwrap();
    let id2 = satisfy(&mut session2, PORT2).expect("session 2 transport");
    let answer = session2.create_sdp_answer(pending);

    session1.receive_sdp_answer(answer).unwrap();
    satisfy(&mut session1, PORT1);

    // Drain the offer/answer bookkeeping so only media events are left
    while session1.pop_event().is_some() {}
    while session2.pop_event().is_some() {}

    let now = Instant::now();
    let media_id = session1.media_iter().next().unwrap().id();

    {
        let mut outbound = session1.outbound_media(media_id).expect("outbound media");
        outbound.send_rtp(SendRtpPacket::new(now, 9, Bytes::from_static(PAYLOAD)));
    }

    // Queued RTP only turns into SendData events on the next poll
    session1.poll(now);

    // Hand everything session 1 wants to send to session 2
    let mut forwarded = 0;
    while let Some(event) = session1.pop_event() {
        if let SdpSessionEvent::SendData {
            component,
            data,
            target,
            ..
        } = event
        {
            forwarded += 1;
            session2.receive(
                now,
                id2,
                ReceivedPkt {
                    data,
                    source: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), PORT1),
                    destination: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), target.port()),
                    component,
                },
            );
        }
    }
    assert!(forwarded > 0, "session 1 did not send anything");

    // Inbound RTP is released by the jitter buffer on a later poll, so advance time
    // until it comes out
    let mut payloads = Vec::new();
    for step in 0..100 {
        session2.poll(now + Duration::from_millis(step * 10));

        while let Some(event) = session2.pop_event() {
            if let SdpSessionEvent::ReceiveRTP { packets, .. } = event {
                payloads.extend(packets.into_iter().map(|p| p.rtp_packet.payload));
            }
        }

        if !payloads.is_empty() {
            break;
        }
    }

    assert!(
        payloads.iter().any(|p| p.as_ref() == PAYLOAD),
        "the RTP payload did not survive protect/unprotect, got {payloads:?}"
    );
}
