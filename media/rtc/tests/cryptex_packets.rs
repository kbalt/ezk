//! End to end check that a negotiated `a=cryptex` reaches the SRTP protector, by inspecting
//! the bytes on the wire. `sdp_cryptex.rs` covers the signalling.

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

fn satisfy_transport_changes(session: &mut SdpSession, port: u16) -> Option<TransportId> {
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

fn session(port: u16, offer_cryptex: bool) -> SdpSession {
    let mut session = SdpSession::new(
        Ipv4Addr::LOCALHOST.into(),
        SdpSessionConfig {
            offer_transport: TransportType::SdesSrtp,
            enable_cryptex: offer_cryptex,
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
    satisfy_transport_changes(&mut session, port);

    session
}

fn is_rtcp(data: &[u8]) -> bool {
    matches!(data.get(1), Some(&b) if (64..=95).contains(&(b & 0x7f)))
}

fn exchange(port1: u16, port2: u16, offer_cryptex: bool) -> (Vec<Vec<u8>>, Vec<Bytes>, bool) {
    let mut session1 = session(port1, offer_cryptex);
    let mut session2 = session(port2, offer_cryptex);

    let offer = session1.create_sdp_offer();
    let pending = session2.receive_sdp_offer(offer).unwrap();
    let id2 = satisfy_transport_changes(&mut session2, port2).unwrap();
    let answer = session2.create_sdp_answer(pending);

    session1.receive_sdp_answer(answer).unwrap();
    satisfy_transport_changes(&mut session1, port1);

    while session1.pop_event().is_some() {}
    while session2.pop_event().is_some() {}

    let now = Instant::now();
    let media_id = session1.media_iter().next().unwrap().id();
    let negotiated = session1.rtp_sessions().next().unwrap().1.cryptex();

    {
        let mut outbound = session1.outbound_media(media_id).unwrap();
        outbound.send_rtp(SendRtpPacket::new(now, 9, Bytes::from_static(PAYLOAD)));
    }

    session1.poll(now);

    let mut sent_rtp = Vec::new();
    while let Some(event) = session1.pop_event() {
        if let SdpSessionEvent::SendData {
            component,
            data,
            target,
            ..
        } = event
        {
            if !is_rtcp(&data) {
                sent_rtp.push(data.to_vec());
            }

            session2.receive(
                now,
                id2,
                ReceivedPkt {
                    data,
                    source: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port1),
                    destination: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), target.port()),
                    component,
                },
            );
        }
    }

    // The jitter buffer releases on a later poll, so advance time
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

    (sent_rtp, payloads, negotiated)
}

#[test]
fn negotiated_cryptex_protects_the_header_extension() {
    const PORT1: u16 = 45300;
    const PORT2: u16 = 45400;

    let (sent, received, negotiated) = exchange(PORT1, PORT2, true);

    assert!(negotiated, "cryptex was not negotiated");
    assert!(!sent.is_empty(), "session 1 sent no RTP");

    for packet in &sent {
        // The mid extension is negotiated, so every packet carries an extension block
        assert_eq!(packet[0] & 0x10, 0x10, "X bit not set: {packet:02x?}");

        let csrcs = usize::from(packet[0] & 0x0f);
        let at = 12 + csrcs * 4;
        let profile = u16::from_be_bytes([packet[at], packet[at + 1]]);

        assert!(
            profile == 0xc0de || profile == 0xc2de,
            "extension tag is {profile:#06x}, not a cryptex one"
        );
    }

    assert_eq!(received, [Bytes::from_static(PAYLOAD)]);
}

#[test]
fn disabled_policy_does_not_affect_header_extension() {
    const PORT1: u16 = 45500;
    const PORT2: u16 = 45600;

    let (sent, received, negotiated) = exchange(PORT1, PORT2, false);

    assert!(!negotiated, "cryptex was negotiated despite being disabled");
    assert!(!sent.is_empty(), "session 1 sent no RTP");

    for packet in &sent {
        let csrcs = usize::from(packet[0] & 0x0f);
        let at = 12 + csrcs * 4;
        let profile = u16::from_be_bytes([packet[at], packet[at + 1]]);

        assert!(
            profile == 0xbede || profile == 0x1000,
            "extension tag is {profile:#06x}, expected a plain RFC 8285 one"
        );
    }

    assert_eq!(received, [Bytes::from_static(PAYLOAD)]);
}
