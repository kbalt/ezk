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
    rtcp_types::{Compound, Packet as RtcpPacket},
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
    last_reports_collected: Option<Instant>,
}

impl RtpSession {
    /// Create a new RTP session
    pub fn new() -> Self {
        Self {
            next_tx_ssrc: Ssrc(rand::random()),
            tx: HashMap::default(),
            rx: HashMap::default(),
            reports: ReportsQueue::default(),
            last_reports_collected: None,
        }
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
    pub fn receive_rtcp(&mut self, now: Instant, rtcp_packet: Compound<'_>) {
        for rtcp_packet in rtcp_packet {
            let rtcp_packet = match rtcp_packet {
                Ok(rtcp_packet) => rtcp_packet,
                Err(e) => {
                    log::warn!("Failed to parse RTCP packet in compound packet, {e}");
                    return;
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
                RtcpPacket::PayloadFeedback(_payload_feedback) => {
                    // TODO: handle feedback
                }
                RtcpPacket::Unknown(..) => {
                    // ignore
                }
            }
        }
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
    pub fn poll(&mut self, now: Instant, mtu: Mtu) -> Option<RtpSessionEvent> {
        let fallback_sender_ssrc = *self.tx.keys().next().unwrap_or(&self.next_tx_ssrc);

        let collect_reports = self
            .last_reports_collected
            .is_none_or(|instant| now > instant + Duration::from_secs(1));

        if collect_reports {
            for tx in self.tx.values_mut() {
                tx.collect_reports(now, &mut self.reports);
            }

            for rx in self.rx.values_mut() {
                rx.collect_reports(now, &mut self.reports);
            }

            if !self.reports.is_empty() {
                self.last_reports_collected = Some(now);
            }
        }

        if let Some(report) = self.reports.make_report(fallback_sender_ssrc, mtu) {
            return Some(RtpSessionEvent::SendRtcp(report));
        }

        for tx in self.tx.values_mut() {
            if let Some(rtp_packet) = tx.pop(now) {
                return Some(RtpSessionEvent::SendRtp(rtp_packet));
            }
        }

        for rx in self.rx.values_mut() {
            if let Some(rtp_packet) = rx.pop(now) {
                return Some(RtpSessionEvent::ReceiveRtp(rtp_packet));
            }
        }

        None
    }
}

impl Default for RtpSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Event returned by [`RtpSession::poll`]
pub enum RtpSessionEvent {
    ReceiveRtp(RtpPacket),
    SendRtp(RtpPacket),
    SendRtcp(Vec<u8>),
}
