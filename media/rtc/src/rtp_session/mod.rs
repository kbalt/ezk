//! # RTP session
//!
//! See [`RtpSession`].
//!
//! It is intended to be used alongside [`RtpTransport`](crate::rtp_transport::RtpTransport).

use super::opt_min;
use crate::Mtu;
use report::ReportsQueue;
use rtp::{
    RtpPacket, Ssrc,
    rtcp_types::{Compound, Fir, Packet as RtcpPacket, Pli, RtcpPacketParser},
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

pub use inbound::{RtpInboundRemoteStats, RtpInboundStats, RtpInboundStream};
pub use outbound::{RtpOutboundRemoteStats, RtpOutboundStats, RtpOutboundStream, SendRtpPacket};

/// Contains multiple RTP send/receive streams.
///
/// Exists once per RTP transport
pub struct RtpSession {
    next_tx_ssrc: Ssrc,

    /// All RTP outbound streams
    tx: HashMap<Ssrc, RtpOutboundStream, SsrcHasher>,

    /// All RTP inbound streams
    rx: HashMap<Ssrc, RtpInboundStream, SsrcHasher>,

    /// RTCP reports that are queued to be sent
    reports: ReportsQueue,
}

impl RtpSession {
    /// Create a new RTP session
    pub fn new(rtcp_rsize: bool) -> Self {
        Self {
            next_tx_ssrc: Ssrc(rand::random()),
            tx: HashMap::default(),
            rx: HashMap::default(),
            reports: ReportsQueue::new(rtcp_rsize),
        }
    }

    /// Is reduced size RTCP allowed
    pub fn rtcp_rsize(&self) -> bool {
        self.reports.rtcp_rsize()
    }

    /// Create a new outbound RTP stream with the given parameters
    pub fn new_tx_stream(&mut self, clock_rate: u32) -> &mut RtpOutboundStream {
        let ssrc = self.next_tx_ssrc;

        // Generate the next outbound SSRC, making sure to avoid collision
        self.next_tx_ssrc = Ssrc(rand::random());
        while self.tx.contains_key(&self.next_tx_ssrc) {
            self.next_tx_ssrc = Ssrc(rand::random());
        }

        // TODO: correct RTCP interval
        let stream = RtpOutboundStream::new(ssrc, clock_rate, Duration::from_secs(1));

        self.tx.entry(ssrc).insert_entry(stream).into_mut()
    }

    /// Create new inbound RTP stream from the given SSRC and parameters
    pub fn new_rx_stream(&mut self, ssrc: Ssrc, clock_rate: u32) -> &mut RtpInboundStream {
        // TODO: correct RTCP interval
        let stream = RtpInboundStream::new(ssrc, clock_rate, Duration::from_secs(1));

        self.rx.entry(ssrc).insert_entry(stream).into_mut()
    }

    /// Access the RTP send stream identified by the given SSRC
    pub fn tx_stream(&mut self, ssrc: Ssrc) -> Option<&mut RtpOutboundStream> {
        self.tx.get_mut(&ssrc)
    }

    /// Access the RTP receive stream identified by the remote-ssrc
    pub fn rx_stream(&mut self, ssrc: Ssrc) -> Option<&mut RtpInboundStream> {
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
                        rx.handle_sender_report(now, &sender_report);
                    }

                    for report_block in sender_report.report_blocks() {
                        if let Some(tx) = self.tx_stream(Ssrc(report_block.ssrc())) {
                            tx.handle_report_block(now, report_block);
                        }
                    }
                }
                RtcpPacket::TransportFeedback(_transport_feedback) => {
                    // TODO: handle feedback
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
                        log::warn!(
                            "Received unknown RTCP payload feedback packet header={:02X?} sender_ssrc={} media_ssrc={}",
                            payload_feedback.header_data(),
                            payload_feedback.sender_ssrc(),
                            payload_feedback.media_ssrc(),
                        )
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
            timeout = opt_min(timeout, rx.timeout(now));
        }

        timeout
    }

    /// Poll the session for any new events
    pub fn poll(&mut self, now: Instant, mtu: Mtu) -> Option<RtpSessionPollEvent> {
        let fallback_sender_ssrc = *self.tx.keys().next().unwrap_or(&self.next_tx_ssrc);

        for tx in self.tx.values_mut() {
            tx.collect_reports(now, &mut self.reports);
        }

        for rx in self.rx.values_mut() {
            rx.collect_reports(now, &mut self.reports);
        }

        if let Some(report) = self.reports.make_report(fallback_sender_ssrc, mtu) {
            return Some(RtpSessionPollEvent::SendRtcp(report));
        }

        for tx in self.tx.values_mut() {
            if let Some(rtp_packet) = tx.pop(now) {
                return Some(RtpSessionPollEvent::SendRtp(rtp_packet));
            }
        }

        for rx in self.rx.values_mut() {
            if let Some(rtp_packet) = rx.pop(now) {
                return Some(RtpSessionPollEvent::ReceiveRtp(rtp_packet));
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
