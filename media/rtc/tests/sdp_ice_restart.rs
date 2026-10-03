//! ICE restarts of SDP sessions

use bytes::Bytes;
use bytesstr::BytesStr;
use ezk_rtc::{
    ReceivedPkt,
    rtp_session::SendRtpPacket,
    rtp_transport::{RtpTransportPorts, TransportConnectionState},
    sdp::{
        Codec, Codecs, Direction, IceConnectionState, LocalMediaId, MediaId, MediaType, SdpSession,
        SdpSessionConfig, SdpSessionEvent, SessionDescription, TransportChange, TransportId,
    },
};
use ice::Component;
use std::{
    cmp::{max, min},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use stun_types::{
    Class, Message,
    attributes::{MessageIntegrity, MessageIntegrityKey, Username},
};

const FRAME_INTERVAL: Duration = Duration::from_millis(20);

fn parse(sdp: &str) -> SessionDescription {
    SessionDescription::parse(&BytesStr::from(sdp.replace('\n', "\r\n"))).unwrap()
}

fn ufrag(sdp: &SessionDescription) -> String {
    sdp.ice_ufrag.as_ref().unwrap().ufrag.to_string()
}

struct Packet {
    data: Vec<u8>,
    source: SocketAddr,
    target: SocketAddr,
}

/// SdpSession with its sockets
struct Endpoint {
    session: SdpSession,
    local_media: LocalMediaId,
    ip: IpAddr,
    rtp_port: u16,
    rtcp_port: Option<u16>,
    transport_id: Option<TransportId>,
    /// Negotiated media and its payload type
    media: Option<(MediaId, u8)>,

    ice_states: Vec<IceConnectionState>,
    transport_states: Vec<TransportConnectionState>,
    received_rtp: usize,
}

impl Endpoint {
    fn new(ip: &str, rtp_port: u16, config: SdpSessionConfig) -> Self {
        let ip: IpAddr = ip.parse().unwrap();

        let mut session = SdpSession::new(ip, config);
        let local_media = session
            .add_local_media(
                Codecs::new(MediaType::Audio).with_codec(Codec::G722),
                Direction::SendRecv,
            )
            .unwrap();

        Self {
            session,
            local_media,
            ip,
            rtp_port,
            rtcp_port: None,
            transport_id: None,
            media: None,
            ice_states: vec![],
            transport_states: vec![],
            received_rtp: 0,
        }
    }

    fn handle_transport_changes(&mut self) {
        while let Some(change) = self.session.pop_transport_change() {
            match change {
                TransportChange::CreateSocket(id) => {
                    self.transport_id = Some(id);
                    self.session.set_transport_ports(
                        id,
                        &[self.ip],
                        RtpTransportPorts::mux(self.rtp_port),
                    );
                }
                TransportChange::CreateSocketPair(id) => {
                    self.transport_id = Some(id);
                    self.rtcp_port = Some(self.rtp_port + 1);
                    self.session.set_transport_ports(
                        id,
                        &[self.ip],
                        RtpTransportPorts::new(self.rtp_port, self.rtp_port + 1),
                    );
                }
                TransportChange::RemoveRtcpSocket(..) => self.rtcp_port = None,
                TransportChange::Remove(..) => {}
            }
        }
    }

    fn answer(&mut self, offer: &SessionDescription) -> SessionDescription {
        let state = self.session.receive_sdp_offer(offer.clone()).unwrap();
        self.handle_transport_changes();
        self.session.create_sdp_answer(state)
    }

    /// Handle all events of the session, returns the packets to send
    fn events(&mut self) -> Vec<Packet> {
        let mut packets = vec![];

        while let Some(event) = self.session.pop_event() {
            match event {
                SdpSessionEvent::SendData {
                    component,
                    data,
                    source,
                    target,
                    ..
                } => {
                    let port = match component {
                        Component::Rtp => self.rtp_port,
                        Component::Rtcp => self.rtcp_port.unwrap(),
                    };

                    packets.push(Packet {
                        data,
                        source: SocketAddr::new(source.unwrap_or(self.ip), port),
                        target,
                    });
                }
                SdpSessionEvent::MediaAdded(e) => self.media = Some((e.id, e.codec.pt.remote)),
                SdpSessionEvent::IceConnectionState(e) => self.ice_states.push(e.new),
                SdpSessionEvent::TransportConnectionState(e) => self.transport_states.push(e.new),
                SdpSessionEvent::ReceiveRTP { packets: rtp, .. } => self.received_rtp += rtp.len(),
                _ => {}
            }
        }

        packets
    }

    fn receive(&mut self, now: Instant, packet: Packet) {
        let component = if packet.target.port() == self.rtp_port {
            Component::Rtp
        } else {
            Component::Rtcp
        };

        self.session.receive(
            now,
            self.transport_id.unwrap(),
            ReceivedPkt {
                data: packet.data,
                source: packet.source,
                destination: packet.target,
                component,
            },
        );
    }
}

/// `a` offers ICE, `b` answers. `a` sends audio to `b`.
struct Call {
    a: Endpoint,
    b: Endpoint,
    offer: SessionDescription,
    answer: SessionDescription,

    now: Instant,
    next_frame: Instant,

    drop_packets: bool,
    /// Usernames of all STUN requests sent
    stun_usernames: Vec<String>,
}

impl Call {
    fn new() -> Self {
        let mut a = Endpoint::new(
            "10.0.0.1",
            5000,
            SdpSessionConfig {
                offer_ice: true,
                ..Default::default()
            },
        );
        let mut b = Endpoint::new("10.0.0.2", 6000, SdpSessionConfig::default());

        a.session
            .add_media(a.local_media, Direction::SendRecv, None, None);
        a.handle_transport_changes();

        let offer = a.session.create_sdp_offer();
        let answer = b.answer(&offer);

        a.session.receive_sdp_answer(answer.clone()).unwrap();
        a.handle_transport_changes();

        let now = Instant::now();

        let mut call = Self {
            a,
            b,
            offer,
            answer,
            now,
            next_frame: now,
            drop_packets: false,
            stun_usernames: vec![],
        };

        call.run(Duration::from_secs(5));
        call.assert_connected();
        call
    }

    /// `a` restarts ICE and creates an offer
    fn offer_restart(&mut self) -> SessionDescription {
        self.a.session.restart_ice();
        assert!(self.a.session.needs_negotiation());

        let offer = self.a.session.create_sdp_offer();
        self.a.handle_transport_changes();
        offer
    }

    /// `b` answers the offer, which `a` receives
    fn answer(&mut self, offer: &SessionDescription) -> SessionDescription {
        let answer = self.b.answer(offer);

        self.a.session.receive_sdp_answer(answer.clone()).unwrap();
        self.a.handle_transport_changes();
        answer
    }

    fn assert_connected(&self) {
        for endpoint in [&self.a, &self.b] {
            assert_eq!(
                endpoint.ice_states.last(),
                Some(&IceConnectionState::Connected)
            );
            assert_eq!(
                endpoint.transport_states.last(),
                Some(&TransportConnectionState::Connected)
            );
        }
    }

    /// Number of state changes of both endpoints
    fn state_changes(&self) -> [usize; 4] {
        [
            self.a.ice_states.len(),
            self.a.transport_states.len(),
            self.b.ice_states.len(),
            self.b.transport_states.len(),
        ]
    }

    /// Poll both endpoints and deliver packets until there are none left
    fn exchange(&mut self) {
        loop {
            self.a.session.poll(self.now);
            self.b.session.poll(self.now);

            let to_b = self.a.events();
            let to_a = self.b.events();

            if to_a.is_empty() && to_b.is_empty() {
                break;
            }

            for packet in to_a.iter().chain(&to_b) {
                if let Ok(mut msg) = Message::parse(packet.data.clone())
                    && msg.class() == Class::Request
                {
                    let username = msg.attribute::<Username>().unwrap().unwrap();
                    self.stun_usernames.push(username.0.to_owned());
                }
            }

            if self.drop_packets {
                continue;
            }

            for packet in to_a {
                assert_eq!(packet.target.ip(), self.a.ip);
                self.a.receive(self.now, packet);
            }

            for packet in to_b {
                assert_eq!(packet.target.ip(), self.b.ip);
                self.b.receive(self.now, packet);
            }
        }
    }

    /// Run for the given duration, `a` sends audio every 20ms once the media is negotiated
    fn run(&mut self, duration: Duration) {
        let until = self.now + duration;

        while self.now < until {
            if self.now >= self.next_frame {
                self.next_frame += FRAME_INTERVAL;

                if let Some((media_id, pt)) = self.a.media
                    && let Some(mut outbound) = self.a.session.outbound_media(media_id)
                {
                    outbound.send_rtp(SendRtpPacket::new(
                        self.now,
                        pt,
                        Bytes::from_static(&[0; 160]),
                    ));
                }
            }

            self.exchange();

            let timeout = [
                self.a.session.timeout(self.now),
                self.b.session.timeout(self.now),
                Some(self.next_frame - self.now),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap();

            self.now = min(self.now + max(timeout, Duration::from_millis(1)), until);
        }
    }

    /// Run and return the number of audio frames received by `b`
    fn received_while_running(&mut self, duration: Duration) -> usize {
        let received = self.b.received_rtp;
        self.run(duration);
        self.b.received_rtp - received
    }
}

#[test]
fn media_continues_during_a_slow_restart() {
    let mut call = Call::new();
    let state_changes = call.state_changes();

    let offer = call.offer_restart();
    assert_ne!(ufrag(&offer), ufrag(&call.offer));

    // The peer takes a while to answer, media is sent on the pair in use
    let received = call.received_while_running(Duration::from_secs(10));
    assert!(received > 450, "{received} frames received");

    // The peer restarts as well, as it must change its credentials
    let answer = call.answer(&offer);
    assert_ne!(ufrag(&answer), ufrag(&call.answer));

    let received = call.received_while_running(Duration::from_secs(1));
    assert!(received > 40, "{received} frames received");

    // Neither the ICE nor the transport connection is interrupted
    assert_eq!(call.state_changes(), state_changes);

    // Only the new credentials are used once the restart concluded
    call.stun_usernames.clear();
    let received = call.received_while_running(Duration::from_secs(10));
    assert!(received > 450, "{received} frames received");

    let a_checks = format!("{}:{}", ufrag(&answer), ufrag(&offer));
    let b_checks = format!("{}:{}", ufrag(&offer), ufrag(&answer));

    assert!(!call.stun_usernames.is_empty());
    for username in &call.stun_usernames {
        assert!(*username == a_checks || *username == b_checks, "{username}");
    }
}

#[test]
fn restart_recovers_after_the_connection_failed() {
    let mut call = Call::new();

    // The network goes down until consent expired
    call.drop_packets = true;
    call.run(Duration::from_secs(35));

    assert_eq!(call.a.ice_states.last(), Some(&IceConnectionState::Failed));
    assert_eq!(call.b.ice_states.last(), Some(&IceConnectionState::Failed));
    assert_eq!(
        call.a.transport_states.last(),
        Some(&TransportConnectionState::Failed)
    );

    call.drop_packets = false;

    let offer = call.offer_restart();
    call.answer(&offer);

    let received = call.received_while_running(Duration::from_secs(5));
    assert!(received > 200, "{received} frames received");

    call.assert_connected();
}

#[test]
fn reoffer_without_restart_keeps_credentials() {
    let mut call = Call::new();
    let state_changes = call.state_changes();

    let offer = call.a.session.create_sdp_offer();
    assert_eq!(ufrag(&offer), ufrag(&call.offer));

    let answer = call.answer(&offer);
    assert_eq!(ufrag(&answer), ufrag(&call.answer));

    call.stun_usernames.clear();
    let received = call.received_while_running(Duration::from_secs(10));
    assert!(received > 450, "{received} frames received");

    assert_eq!(call.state_changes(), state_changes);

    let a_checks = format!("{}:{}", ufrag(&answer), ufrag(&offer));
    for username in &call.stun_usernames {
        assert!(*username == a_checks || username.starts_with(&ufrag(&offer)));
    }
}

#[test]
fn media_level_ice_credentials_take_precedence() {
    let mut b = Endpoint::new("10.0.0.2", 6000, SdpSessionConfig::default());

    let answer = b.answer(&parse(
        "v=0
o=- 1 2 IN IP4 198.51.100.7
s=-
c=IN IP4 198.51.100.7
t=0 0
a=ice-ufrag:session
a=ice-pwd:sessionpasswordsessionpassword
m=audio 4000 RTP/AVP 9
a=rtcp-mux
a=ice-ufrag:media
a=ice-pwd:mediapasswordmediapasswordmedia
a=rtpmap:9 G722/8000
a=candidate:1 1 UDP 2130706431 198.51.100.7 4000 typ host
",
    ));

    b.session.poll(Instant::now());
    let mut packets = b.events();
    assert_eq!(packets.len(), 1);

    let mut check = Message::parse(packets.remove(0).data).unwrap();
    assert_eq!(
        check.attribute::<Username>().unwrap().unwrap().0,
        format!("media:{}", ufrag(&answer))
    );
    assert!(
        check
            .attribute_with::<MessageIntegrity>(MessageIntegrityKey::new(
                "mediapasswordmediapasswordmedia"
            ))
            .is_some_and(|r| r.is_ok())
    );
}

#[test]
fn credentials_are_on_media_level_once_they_differ() {
    let offer = |second_ufrag: &str| {
        parse(&format!(
            "v=0
o=- 1 2 IN IP4 198.51.100.7
s=-
c=IN IP4 198.51.100.7
t=0 0
m=audio 4000 RTP/AVP 9
a=mid:0
a=rtcp-mux
a=ice-ufrag:first
a=ice-pwd:firstpasswordfirstpassword
a=rtpmap:9 G722/8000
a=candidate:1 1 UDP 2130706431 198.51.100.7 4000 typ host
m=audio 4002 RTP/AVP 9
a=mid:1
a=rtcp-mux
a=ice-ufrag:{second_ufrag}
a=ice-pwd:{second_ufrag}passwordpasswordpassword
a=rtpmap:9 G722/8000
a=candidate:1 1 UDP 2130706431 198.51.100.7 4002 typ host
"
        ))
    };

    let mut b = Endpoint::new("10.0.0.2", 6000, SdpSessionConfig::default());

    // Both transports use the same credentials
    let answer = b.answer(&offer("second"));
    assert!(answer.ice_ufrag.is_some());
    assert!(
        answer
            .media_descriptions
            .iter()
            .all(|desc| desc.ice_ufrag.is_none())
    );

    // The peer restarted ICE for the second media only
    let restart_answer = b.answer(&offer("restart"));
    assert!(restart_answer.ice_ufrag.is_none());

    let media_ufrag = |index: usize| {
        restart_answer.media_descriptions[index]
            .ice_ufrag
            .as_ref()
            .unwrap()
            .ufrag
            .to_string()
    };

    assert_eq!(media_ufrag(0), ufrag(&answer));
    assert_ne!(media_ufrag(1), ufrag(&answer));
}

#[test]
fn transports_added_after_a_restart_use_the_new_credentials() {
    let offer = |ufrag: &str, media: &[(u8, u16)]| {
        let mut sdp = format!(
            "v=0
o=- 1 2 IN IP4 198.51.100.7
s=-
c=IN IP4 198.51.100.7
t=0 0
a=ice-ufrag:{ufrag}
a=ice-pwd:{ufrag}passwordpasswordpassword
"
        );

        for (mid, port) in media {
            sdp += &format!(
                "m=audio {port} RTP/AVP 9
a=mid:{mid}
a=rtcp-mux
a=rtpmap:9 G722/8000
a=candidate:1 1 UDP 2130706431 198.51.100.7 {port} typ host
"
            );
        }

        parse(&sdp)
    };

    let mut b = Endpoint::new("10.0.0.2", 6000, SdpSessionConfig::default());

    let answer = b.answer(&offer("first", &[(0, 4000)]));

    // The peer restarts ICE
    let restart_answer = b.answer(&offer("restart", &[(0, 4000)]));
    assert_ne!(ufrag(&restart_answer), ufrag(&answer));

    // A new media with its own transport is added, which uses the same credentials as the restarted transport
    let add_answer = b.answer(&offer("restart", &[(0, 4000), (1, 4002)]));
    assert_eq!(ufrag(&add_answer), ufrag(&restart_answer));
    assert!(
        add_answer
            .media_descriptions
            .iter()
            .all(|desc| desc.ice_ufrag.is_none())
    );
}
