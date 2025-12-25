//! # RTP session
//!
//! See [`RtpSession`].
//!
//! It is intended to be used alongside [`RtpTransport`](crate::rtp_transport::RtpTransport).

use super::opt_min;
use crate::{
    Mtu,
    rtp_session::twcc::{TwccRxState, TwccTxState},
};
use report::ReportsQueue;
use rtp::{
    RtpPacket, Ssrc,
    rtcp_types::{Compound, Fir, Nack, Packet as RtcpPacket, Pli, RtcpPacketParser, Twcc},
};
use ssrc_hasher::SsrcHasher;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

mod inbound;
mod ntp_timestamp;
mod outbound;
mod report;
mod ssrc_hasher;
mod twcc;

pub use inbound::{
    RtpInboundRemoteStats, RtpInboundStats, RtpInboundStream, RtpInboundStreamEvent,
};
pub use outbound::{
    RtpOutboundRemoteStats, RtpOutboundStats, RtpOutboundStream, RtpOutboundStreamEvent,
    SendRtpPacket,
};

/// Contains multiple RTP send/receive streams.
///
/// Exists once per RTP transport
pub struct RtpSession {
    next_tx_ssrc: Ssrc,

    /// All RTP outbound streams
    tx: HashMap<Ssrc, RtpOutboundStream, SsrcHasher>,

    /// All RTP inbound streams
    rx: HashMap<Ssrc, RxStream, SsrcHasher>,

    /// RTCP reports that are queued to be sent
    reports: ReportsQueue,

    /// Transport wide congestion control state
    twcc_tx: Option<TwccTxState>,
    twcc_rx: Option<TwccRxState>,
}

/// Receive stream
#[allow(clippy::large_enum_variant)]
pub enum RxStream {
    /// Original rtp inbound stream
    Original(RtpInboundStream),
    /// SSRC belongs to the retransmission stream of the original ssrc
    Rtx(Ssrc),
}

impl RxStream {
    pub fn expect_original(&mut self) -> &mut RtpInboundStream {
        match self {
            RxStream::Original(stream) => stream,
            RxStream::Rtx(..) => panic!("expected original stream"),
        }
    }
}

impl RtpSession {
    /// Create a new RTP session
    pub fn new(rtcp_rsize: bool, transport_cc: bool) -> Self {
        Self {
            next_tx_ssrc: Ssrc(rand::random()),
            tx: HashMap::default(),
            rx: HashMap::default(),
            reports: ReportsQueue::new(rtcp_rsize),
            twcc_tx: transport_cc.then(TwccTxState::new),
            twcc_rx: transport_cc.then(TwccRxState::new),
        }
    }

    /// Is reduced size RTCP allowed
    pub fn rtcp_rsize(&self) -> bool {
        self.reports.rtcp_rsize()
    }

    fn generate_random_next_ssrc(&mut self) {
        self.next_tx_ssrc = Ssrc(rand::random());
        while self.tx.contains_key(&self.next_tx_ssrc) {
            self.next_tx_ssrc = Ssrc(rand::random());
        }
    }

    /// Create a new outbound RTP stream with the given parameters
    pub fn new_tx_stream(&mut self, clock_rate: u32, rtx_pt: Option<u8>) -> &mut RtpOutboundStream {
        let ssrc = self.next_tx_ssrc;

        // Generate the next outbound SSRC, making sure to avoid collision
        self.generate_random_next_ssrc();

        let rtx = if let Some(rtx_pt) = rtx_pt {
            let rtx_ssrc = self.next_tx_ssrc;
            self.generate_random_next_ssrc();
            Some((rtx_pt, rtx_ssrc))
        } else {
            None
        };

        // TODO: correct RTCP interval
        let stream = RtpOutboundStream::new(ssrc, clock_rate, Duration::from_secs(1), rtx);

        self.tx.entry(ssrc).insert_entry(stream).into_mut()
    }

    /// Create new inbound RTP stream from the given SSRC and parameters
    pub fn new_rx_stream(
        &mut self,
        pt: u8,
        ssrc: Ssrc,
        clock_rate: u32,
        emit_nack: bool,
    ) -> &mut RtpInboundStream {
        // TODO: correct RTCP interval
        let stream = RtpInboundStream::new(pt, ssrc, clock_rate, Duration::from_secs(1), emit_nack);

        self.rx
            .entry(ssrc)
            .insert_entry(RxStream::Original(stream))
            .into_mut()
            .expect_original()
    }

    /// Create new inbound RTP stream from the given SSRC and parameters
    pub fn new_rx_rtx_stream(&mut self, ssrc: Ssrc, original_ssrc: Ssrc) -> &mut RtpInboundStream {
        self.rx.insert(ssrc, RxStream::Rtx(original_ssrc));
        self.rx.get_mut(&original_ssrc).unwrap().expect_original()
    }

    /// Access the RTP send stream identified by the given SSRC
    pub fn tx_stream(&mut self, ssrc: Ssrc) -> Option<&mut RtpOutboundStream> {
        self.tx.get_mut(&ssrc)
    }

    /// Access the RTP receive stream identified by the remote-ssrc
    pub fn rx_stream(&mut self, ssrc: Ssrc) -> Option<&mut RxStream> {
        self.rx.get_mut(&ssrc)
    }

    /// Remove the RTP send stream identified by the given SSRC
    pub fn remove_tx_stream(&mut self, ssrc: Ssrc) {
        if self.tx.remove(&ssrc).is_some() {
            self.reports.add_bye(ssrc);
        }
    }

    /// Remove the RTP receive stream identified by the remote-ssrc
    pub fn remove_rx_stream(&mut self, ssrc: Ssrc) {
        self.rx.remove(&ssrc);
    }

    /// Returns an iterator over all outbound streams
    pub fn tx_streams(&self) -> impl Iterator<Item = &RtpOutboundStream> {
        self.tx.values()
    }

    /// Returns an iterator over all inbound streams (excluding rtx SSRCs as they're included in the original RtpInboundStream)
    pub fn rx_streams(&self) -> impl Iterator<Item = &RtpInboundStream> {
        self.rx.values().filter_map(|rx| match rx {
            RxStream::Original(rx) => Some(rx),
            RxStream::Rtx(..) => None,
        })
    }

    /// Hand of the RTCP packet to the RTP session
    #[must_use]
    pub fn receive_rtcp(
        &mut self,
        now: Instant,
        rtcp_packet: Compound<'_>,
    ) -> Vec<RtpSessionReceiveRtcpEvent> {
        let mut events = vec![];

        for rtcp_packet in rtcp_packet {
            let rtcp_packet = match rtcp_packet {
                Ok(rtcp_packet) => rtcp_packet,
                Err(e) => {
                    log::warn!("Failed to parse RTCP packet in compound packet, {e}");
                    return events;
                }
            };

            match rtcp_packet {
                RtcpPacket::App(..) => {}
                RtcpPacket::Bye(_bye) => {
                    // TODO: handle BYE
                }
                RtcpPacket::Rr(receiver_report) => {
                    for report_block in receiver_report.report_blocks() {
                        if let Some(tx) = self.tx_stream(Ssrc(report_block.ssrc())) {
                            tx.handle_report_block(now, report_block);
                        }
                    }
                }
                RtcpPacket::Sdes(_sdes) => {
                    // TODO: handle SDES
                }
                RtcpPacket::Sr(sender_report) => {
                    if let Some(rx) = self.rx_stream(Ssrc(sender_report.ssrc())) {
                        match rx {
                            RxStream::Original(stream) => {
                                stream.handle_sender_report(now, &sender_report);
                            }
                            RxStream::Rtx(..) => {
                                log::warn!(
                                    "Unexpected SenderReport for RTX ssrc {}",
                                    sender_report.ssrc()
                                );
                            }
                        }
                    } else {
                        log::warn!("Unhandled SenderReport for ssrc {}", sender_report.ssrc());
                    }

                    for report_block in sender_report.report_blocks() {
                        if let Some(tx) = self.tx_stream(Ssrc(report_block.ssrc())) {
                            tx.handle_report_block(now, report_block);
                        } else {
                            log::warn!("Unhandled report block for ssrc {}", report_block.ssrc());
                        }
                    }
                }
                RtcpPacket::TransportFeedback(transport_feedback) => {
                    if let Ok(nack) = transport_feedback.parse_fci::<Nack>() {
                        if let Some(tx) = self.tx_stream(Ssrc(transport_feedback.media_ssrc())) {
                            tx.handle_nack(nack.entries());
                        } else {
                            log::warn!(
                                "Unhandled nack for ssrc {}",
                                transport_feedback.media_ssrc()
                            );
                        }
                    } else if let Some(twcc_tx) = &mut self.twcc_tx
                        && let Ok(twcc) = transport_feedback.parse_fci::<Twcc>()
                    {
                        twcc_tx.receive_feedback(now, twcc);
                    } else {
                        log::debug!(
                            "Unhandled transport feedback header={:02X?}",
                            transport_feedback.header_data()
                        );
                    }
                }
                RtcpPacket::PayloadFeedback(payload_feedback) => {
                    if payload_feedback.parse_fci::<Pli>().is_ok() {
                        events.push(RtpSessionReceiveRtcpEvent::NackPliReceived(Ssrc(
                            payload_feedback.media_ssrc(),
                        )));
                    } else if let Ok(fir) = payload_feedback.parse_fci::<Fir>() {
                        for entry in fir.entries() {
                            events.push(RtpSessionReceiveRtcpEvent::CcmFirReceived(Ssrc(
                                entry.ssrc(),
                            )));
                        }
                    } else {
                        log::debug!(
                            "Unhandled payload feedback header={:02X?}",
                            payload_feedback.header_data()
                        );
                    }
                }
                RtcpPacket::Xr(_xr) => {
                    // ignore
                }
                RtcpPacket::Unknown(..) => {
                    // ignore
                }
            }
        }

        events
    }

    /// Returns the duration to wait from the given Instant before polling again
    pub fn timeout(&self, now: Instant) -> Option<Duration> {
        let mut timeout = None;

        for tx in self.tx.values() {
            timeout = opt_min(timeout, tx.timeout(now));
        }

        for rx in self.rx.values() {
            if let RxStream::Original(stream) = rx {
                timeout = opt_min(timeout, stream.timeout(now));
            }
        }

        if let Some(twcc_rx) = &self.twcc_rx {
            timeout = opt_min(timeout, twcc_rx.timeout(now));
        }

        timeout
    }

    /// Poll the session for any new events
    pub fn poll(&mut self, now: Instant, mtu: Mtu) -> Option<RtpSessionPollEvent> {
        let fallback_sender_ssrc = *self.tx.keys().next().unwrap_or(&self.next_tx_ssrc);

        // Make RTCP reports if necessary
        for tx in self.tx.values_mut() {
            tx.collect_reports(now, &mut self.reports);
        }

        for rx in self.rx.values_mut() {
            if let RxStream::Original(stream) = rx {
                stream.collect_reports(now, fallback_sender_ssrc, &mut self.reports);
            }
        }

        if let Some(twcc_rx) = &mut self.twcc_rx {
            twcc_rx.poll_reports(now, mtu, &mut self.reports);
        }

        if let Some(report) = self.reports.make_report(fallback_sender_ssrc, mtu) {
            return Some(RtpSessionPollEvent::SendRtcp(report));
        }

        // Poll all outbound streams
        for tx in self.tx.values_mut() {
            match tx.poll(now) {
                Some(RtpOutboundStreamEvent::SendRtpPacket {
                    mut rtp_packet,
                    is_rtx,
                }) => {
                    if !is_rtx && let Some(twcc_tx) = &mut self.twcc_tx {
                        twcc_tx.send_packet(now, &mut rtp_packet);
                    }

                    return Some(RtpSessionPollEvent::SendRtp(rtp_packet));
                }
                None => continue,
            }
        }

        // Poll all inbound streams
        for rx in self.rx.values_mut() {
            let RxStream::Original(rx) = rx else {
                continue;
            };

            if let Some(event) = rx.poll(now) {
                match event {
                    RtpInboundStreamEvent::ReceiveRtpPacket {
                        received_at,
                        rtp_packet,
                    } => {
                        // If the packet has a received_at timestamp its not a retransmission, pass it to twcc when set
                        if let Some(twcc_rx) = &mut self.twcc_rx
                            && let Some(received_at) = received_at
                        {
                            twcc_rx.receive_packet(received_at, &rtp_packet);
                        }

                        return Some(RtpSessionPollEvent::ReceiveRtp(rtp_packet));
                    }
                }
            }
        }

        None
    }
}

/// Event returned by [`RtpSession::poll`]
pub enum RtpSessionPollEvent {
    ReceiveRtp(RtpPacket),
    SendRtp(RtpPacket),
    SendRtcp(Vec<u8>),
}

/// Event returned by [`RtpSession::receive_rtcp`]
pub enum RtpSessionReceiveRtcpEvent {
    NackPliReceived(Ssrc),
    CcmFirReceived(Ssrc),
}
