use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use ezk_rtc::{
    OpenSslContext,
    rtp_session::SendRtpPacket,
    sdp::{
        Codec, Codecs, LocalMediaId, SdpSession, SdpSessionConfig, SdpSessionEvent, TransportType,
    },
    tokio::TokioIoState,
};
use sdp_types::{Direction, MediaType};
use tokio::{select, time::interval};

pub(crate) fn make_session(config: SdpSessionConfig) -> (LocalMediaId, SdpSession) {
    let mut session = SdpSession::new(
        OpenSslContext::try_new().unwrap(),
        Ipv4Addr::LOCALHOST.into(),
        config,
    );

    let audio = session
        .add_local_media(
            Codecs::new(MediaType::Video).with_codec(Codec::H264.with_rtx()),
            Direction::SendRecv,
        )
        .unwrap();

    (audio, session)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::builder().is_test(true).init();

    let (local_media_id1, mut sdp_session1) = make_session(SdpSessionConfig {
        offer_ice: true,
        offer_transport: TransportType::Rtp,
        offer_avpf: true,
        ..Default::default()
    });
    let (_local_media_id2, mut sdp_session2) = make_session(SdpSessionConfig {
        offer_transport: TransportType::Rtp,
        ..Default::default()
    });

    let mut io1 = TokioIoState::new_with_local_ips().unwrap();
    let mut io2 = TokioIoState::new_with_local_ips().unwrap();

    sdp_session1.add_media(local_media_id1, Direction::SendOnly, None, None);

    io1.handle_transport_changes(&mut sdp_session1)
        .await
        .unwrap();

    let offer = sdp_session1.create_sdp_offer();

    println!("Offer:\n{offer}");

    let answer = sdp_session2.receive_sdp_offer(offer).unwrap();
    io2.handle_transport_changes(&mut sdp_session2)
        .await
        .unwrap();
    let answer = sdp_session2.create_sdp_answer(answer);

    println!("Answer:\n{answer}");

    sdp_session1.receive_sdp_answer(answer).unwrap();
    io1.handle_transport_changes(&mut sdp_session1)
        .await
        .unwrap();

    let mut send_interval = interval(Duration::from_millis(16));

    let payload = Bytes::from(vec![0u8; 1300]);

    loop {
        select! {
            event = io1.poll_session(&mut sdp_session1) => {
                handle_event(&mut io1,  event.unwrap());
                continue;
            }
            event = io2.poll_session(&mut sdp_session2) => {
                handle_event(&mut io2,  event.unwrap());
                continue;
            }
            _ = send_interval.tick() => {
                // fallthrough
            }
        }

        let media = sdp_session1.media_iter().next().unwrap();
        let media_id = media.id();

        let now = Instant::now();

        if let Some(mut outbound) = sdp_session1.outbound_media(media_id) {
            for _ in 0..1 {
                outbound.send_rtp(SendRtpPacket::new(now, 96, payload.clone()));
            }
        }
    }
}

fn handle_event(io: &mut TokioIoState, event: SdpSessionEvent) {
    match event {
        SdpSessionEvent::MediaAdded(e) => {
            println!("{e:?}");
        }
        SdpSessionEvent::MediaChanged(e) => {
            println!("{e:?}");
        }
        SdpSessionEvent::MediaRemoved(e) => {
            println!("{e:?}");
        }
        SdpSessionEvent::IceGatheringState(e) => {
            println!("{e:?}");
        }
        SdpSessionEvent::IceConnectionState(e) => {
            println!("{e:?}");
        }
        SdpSessionEvent::TransportConnectionState(e) => {
            println!("{e:?}");
        }
        SdpSessionEvent::SendData {
            transport_id,
            component,
            data,
            source,
            target,
        } => {
            io.send(transport_id, component, data, source, target);
        }
        SdpSessionEvent::ReceiveRTP {
            media_id: _,
            rtp_packet: _,
        } => {}
        SdpSessionEvent::ReceivePictureLossIndication { .. } => {}
        SdpSessionEvent::ReceiveFullIntraRefresh { .. } => {}
    }
}
