use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use ezk_rtc::{
    Mtu, OpenSslContext,
    rtp_session::SendRtpPacket,
    sdp::{
        BundlePolicy, Codec, Codecs, LocalMediaId, RtcpMuxPolicy, SdpSession, SdpSessionConfig,
        SdpSessionEvent, TransportType,
    },
    tokio::TokioIoState,
};
use sdp_types::{Direction, MediaType, SessionDescription};

pub(crate) fn make_session(config: SdpSessionConfig) -> (LocalMediaId, SdpSession) {
    let mut session = SdpSession::new(
        OpenSslContext::try_new().unwrap(),
        Ipv4Addr::LOCALHOST.into(),
        config,
    );

    let audio = session
        .add_local_media(
            Codecs::new(MediaType::Video).with_codec(Codec::VP8.with_rtx()),
            Direction::SendRecv,
        )
        .unwrap();

    (audio, session)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::builder().is_test(true).init();

    let (local_media_id, mut sdp_session) = make_session(SdpSessionConfig {
        offer_transport: TransportType::DtlsSrtp,
        offer_ice: true,
        offer_avpf: true,
        rtcp_mux_policy: RtcpMuxPolicy::Require,
        bundle_policy: BundlePolicy::MaxBundle,
        mtu: Mtu::new(1400),
    });

    let mut io = TokioIoState::new_with_local_ips().unwrap();

    sdp_session.add_media(local_media_id, Direction::SendOnly, None, None);

    io.handle_transport_changes(&mut sdp_session).await.unwrap();

    println!("Paste SDP offer:");
    let mut offer = String::new();
    while !offer.ends_with("\n\n") {
        std::io::stdin().read_line(&mut offer).unwrap();
    }
    let offer = SessionDescription::parse(&offer.into()).unwrap();
    let answer = sdp_session.receive_sdp_offer(offer).unwrap();
    io.handle_transport_changes(&mut sdp_session).await.unwrap();
    let answer = sdp_session.create_sdp_answer(answer);

    println!("SDP Answer:\n{answer}");

    let base_time = Instant::now();

    loop {
        while let Ok(event) = io.poll_session(&mut sdp_session).await {
            handle_event(base_time, &mut io, &mut sdp_session, event);
        }
    }
}

fn handle_event(
    base_time: Instant,
    io: &mut TokioIoState,
    sdp_session: &mut SdpSession,
    event: SdpSessionEvent,
) {
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
            media_id,
            rtp_packet,
        } => {
            let timestamp = Duration::from_secs_f64(rtp_packet.timestamp.0 as f64 / 90_000.0);

            let rtp_time = base_time + timestamp;

            let mut outbound_media = sdp_session.outbound_media(media_id).unwrap();

            outbound_media.send_rtp(
                SendRtpPacket::new(rtp_time, rtp_packet.pt, rtp_packet.payload)
                    .marker(rtp_packet.marker)
                    .send_at(base_time),
            );
        }
        SdpSessionEvent::ReceivePictureLossIndication { .. } => {}
        SdpSessionEvent::ReceiveFullIntraRefresh { .. } => {}
    }
}
