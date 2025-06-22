use std::net::Ipv4Addr;

use ezk_rtc::{
    OpenSslContext,
    rtp_transport::RtpTransportPorts,
    sdp::{Codec, Codecs, LocalMediaId, SdpSession, SdpSessionConfig, TransportChange},
};
use sdp_types::{Direction, MediaType};

pub(crate) fn make_session(config: SdpSessionConfig) -> (LocalMediaId, SdpSession) {
    let mut session = SdpSession::new(
        OpenSslContext::try_new().unwrap(),
        Ipv4Addr::LOCALHOST.into(),
        config,
    );

    let audio = session
        .add_local_media(
            Codecs::new(MediaType::Audio).with_codec(Codec::G722),
            Direction::SendRecv,
        )
        .unwrap();

    (audio, session)
}

pub(crate) fn satisfy_transport_changes(session: &mut SdpSession, port: u16) {
    while let Some(change) = session.pop_transport_change() {
        match change {
            TransportChange::CreateSocket(transport_id) => {
                session.set_transport_ports(
                    transport_id,
                    &[Ipv4Addr::LOCALHOST.into()],
                    RtpTransportPorts::mux(port),
                );
            }
            TransportChange::CreateSocketPair(transport_id) => {
                session.set_transport_ports(
                    transport_id,
                    &[Ipv4Addr::LOCALHOST.into()],
                    RtpTransportPorts::new(port, port + 1),
                );
            }
            TransportChange::Remove(..) => {}
            TransportChange::RemoveRtcpSocket(..) => {}
        }
    }
}
