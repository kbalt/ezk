use crate::{Codec, LocalMediaId, MediaId, TransportId};
use bytes::Bytes;
use bytesstr::BytesStr;
use rtp::{RtpSession, Ssrc};
use sdp_types::{Direction, MediaDescription, MediaType};
use slotmap::SlotMap;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use super::{
    opt_min, transport::Transport, DirectionBools, Event, TransportConnectionState, TransportEntry,
};

pub(crate) struct Media {
    id: MediaId,
    local_media_id: LocalMediaId,

    media_type: MediaType,

    /// The RTP session for this media
    rtp_session: RtpSession,
    avpf: bool,

    /// When to send the next RTCP report
    // TODO: do not start rtcp transmitting until transport is ready
    next_rtcp: Instant,
    rtcp_interval: Duration,

    /// Optional mid, this is only Some if both offer and answer have the mid attribute set
    mid: Option<BytesStr>,

    /// SDP Send/Recv direction
    direction: DirectionBools,

    /// Which transport is used by this media
    transport: TransportId,

    /// Which codec is negotiated
    codec_pt: u8,
    codec: Codec,

    dtmf_pt: Option<u8>,
}

impl Media {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: MediaId,
        local_media_id: LocalMediaId,
        media_type: MediaType,
        mid: Option<BytesStr>,
        direction: DirectionBools,
        avpf: bool,
        transport: TransportId,
        codec_pt: u8,
        codec: Codec,
        dtmf_pt: Option<u8>,
    ) -> Self {
        Self {
            id,
            local_media_id,
            media_type,
            rtp_session: RtpSession::new(Ssrc(rand::random()), codec.clock_rate),
            avpf,
            next_rtcp: Instant::now() + Duration::from_secs(5),
            rtcp_interval: rtcp_interval(media_type),
            mid,
            direction,
            transport,
            codec_pt,
            codec,
            dtmf_pt,
        }
    }

    pub(crate) fn id(&self) -> MediaId {
        self.id
    }

    pub(crate) fn transport_id(&self) -> TransportId {
        self.transport
    }

    pub(crate) fn local_media_id(&self) -> LocalMediaId {
        self.local_media_id
    }

    pub(crate) fn mid(&self) -> Option<&str> {
        self.mid.as_deref()
    }

    pub(crate) fn direction(&self) -> Direction {
        self.direction.into()
    }

    pub(crate) fn set_direction(&mut self, direction: DirectionBools) {
        self.direction = direction;
    }

    pub(crate) fn remote_ssrc(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.rtp_session.remote_ssrc()
    }

    pub(crate) fn remote_payload_types(&self) -> &[u8] {
        std::slice::from_ref(&self.codec_pt)
    }

    pub(crate) fn codec_with_pt(&self) -> (&Codec, u8) {
        (&self.codec, self.codec_pt)
    }

    pub(crate) fn use_avpf(&self) -> bool {
        self.avpf
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        let jt = self.rtp_session.pop_rtp_after(now, None);

        let rtcp_send_timeout = self
            .next_rtcp
            .checked_duration_since(now)
            .unwrap_or_default();

        opt_min(jt, Some(rtcp_send_timeout))
    }

    pub(crate) fn poll(
        &mut self,
        now: Instant,
        transport: &mut Transport,
        events: &mut VecDeque<Event>,
    ) {
        if let Some(rtp_packet) = self.rtp_session.pop_rtp(None) {
            events.push_back(Event::ReceiveRTP {
                media_id: self.id,
                packet: rtp_packet,
            });
        }

        if self.next_rtcp <= now {
            self.next_rtcp += self.rtcp_interval;

            if transport.connection_state() != TransportConnectionState::Connected {
                return;
            }

            self.send_rtcp_report(transport);
        }
    }

    fn send_rtcp_report(&mut self, transport: &mut Transport) {
        let mut encode_buf = vec![0u8; 65535];

        let len = match self.rtp_session.write_rtcp_report(&mut encode_buf) {
            Ok(len) => len,
            Err(e) => {
                log::warn!("Failed to write RTCP packet, {e:?}");
                return;
            }
        };

        encode_buf.truncate(len);
        transport.send_rtcp(encode_buf);
    }

    pub(crate) fn matches(
        &self,
        transports: &SlotMap<TransportId, TransportEntry>,
        desc: &MediaDescription,
    ) -> bool {
        if self.media_type != desc.media.media_type {
            return false;
        }

        if let Some((self_mid, desc_mid)) = self.mid.as_ref().zip(desc.mid.as_ref()) {
            return self_mid == desc_mid;
        }

        if let TransportEntry::Transport(transport) = &transports[self.transport] {
            transport.remote_rtp_address.port() == desc.media.port
        } else {
            false
        }
    }

    pub(crate) fn recv_rtp(&mut self, packet: rtp::RtpPacket) {
        self.rtp_session.recv_rtp(packet);
    }

    pub(crate) fn recv_rtcp(&mut self, packets: Vec<rtp::rtcp_types::Packet>) {
        for packet in packets {
            // TODO: handle the RTCP packets properly
            self.rtp_session.recv_rtcp(packet);
        }
    }

    pub(crate) fn send_rtp(&mut self, transport: &mut Transport, mut packet: rtp::RtpPacket) {
        packet.ssrc = self.rtp_session.ssrc();
        packet.extensions.mid = self.mid.as_ref().map(AsRef::<Bytes>::as_ref).cloned();

        // Tell the RTP session that a packet is being sent
        self.rtp_session.send_rtp(&packet);

        transport.send_rtp(packet);
    }
}

fn rtcp_interval(media_type: MediaType) -> Duration {
    match media_type {
        MediaType::Video => Duration::from_secs(1),
        _ => Duration::from_secs(5),
    }
}
