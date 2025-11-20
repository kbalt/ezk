use crate::Mtu;
use rtp::{
    Ssrc,
    rtcp_types::{
        Bye, CompoundBuilder, PayloadFeedbackBuilder, ReceiverReport, ReportBlock,
        ReportBlockBuilder, RtcpPacket, RtcpPacketWriter, SenderReport, SenderReportBuilder,
        TransportFeedbackBuilder,
    },
};
use std::{cmp, collections::VecDeque};

/// Collection of RTCP packets to be sent out
pub(super) struct ReportsQueue {
    sender_reports: VecDeque<SenderReportBuilder>,
    report_blocks: VecDeque<ReportBlockBuilder>,

    payload_feedback: Vec<PayloadFeedbackBuilder<'static>>,
    transport_feedback: Vec<TransportFeedbackBuilder<'static>>,

    bye: Vec<Ssrc>,

    /// If reduced size RTCP is allows, (RTCP packets without SR/RR)
    rtcp_rsize: bool,
}

impl ReportsQueue {
    pub(super) fn new(rtcp_rsize: bool) -> ReportsQueue {
        ReportsQueue {
            sender_reports: VecDeque::new(),
            report_blocks: VecDeque::new(),
            payload_feedback: Vec::new(),
            transport_feedback: Vec::new(),
            bye: Vec::new(),
            rtcp_rsize,
        }
    }

    pub(super) fn rtcp_rsize(&self) -> bool {
        self.rtcp_rsize
    }

    pub(super) fn is_empty(&self) -> bool {
        let ReportsQueue {
            sender_reports,
            report_blocks,
            payload_feedback,
            transport_feedback,
            bye,
            rtcp_rsize: _,
        } = self;

        sender_reports.is_empty()
            && report_blocks.is_empty()
            && payload_feedback.is_empty()
            && transport_feedback.is_empty()
            && bye.is_empty()
    }

    pub(super) fn has_feedback(&self) -> bool {
        !self.payload_feedback.is_empty() || !self.transport_feedback.is_empty()
    }

    pub(super) fn add_sender_report(&mut self, sr: SenderReportBuilder) {
        self.sender_reports.push_back(sr);
    }

    pub(super) fn add_report_block(&mut self, rb: ReportBlockBuilder) {
        self.report_blocks.push_back(rb);
    }

    pub(super) fn add_payload_feedback(&mut self, feedback: PayloadFeedbackBuilder<'static>) {
        self.payload_feedback.push(feedback);
    }

    pub(super) fn add_transport_feedback(&mut self, feedback: TransportFeedbackBuilder<'static>) {
        self.transport_feedback.push(feedback);
    }

    pub(super) fn add_bye(&mut self, ssrc: Ssrc) {
        self.bye.push(ssrc);
    }

    pub(super) fn make_report(&mut self, fallback_sender_ssrc: Ssrc, mtu: Mtu) -> Option<Vec<u8>> {
        self.make_report_compound(fallback_sender_ssrc, mtu)
            .map(|compound| {
                let mut buf = vec![0u8; compound.calculate_size().unwrap()];
                let len = compound.write_into_unchecked(&mut buf);
                buf.truncate(len);
                buf
            })
    }

    fn make_report_compound(
        &mut self,
        fallback_sender_ssrc: Ssrc,
        mtu: Mtu,
    ) -> Option<CompoundBuilder<'static>> {
        if self.is_empty() {
            return None;
        }

        let mut compound = CompoundBuilder::default();

        let mtu = mtu.for_rtcp_packets();

        let mtu = if !self.sender_reports.is_empty() {
            mtu.saturating_sub(SenderReport::MIN_PACKET_LEN)
        } else if !self.report_blocks.is_empty() {
            mtu.saturating_sub(ReceiverReport::MIN_PACKET_LEN)
        } else if self.rtcp_rsize {
            mtu
        } else {
            return None;
        };

        let (mtu, num_report_blocks) = calculate_num_of_packet_type(
            mtu,
            0,
            ReportBlock::EXPECTED_SIZE,
            self.report_blocks.len(),
            usize::from(SenderReport::MAX_COUNT),
        );

        if let Some(mut sr) = self.sender_reports.pop_front() {
            // Add Report Blocks
            for report_block in self.report_blocks.drain(..num_report_blocks) {
                sr = sr.add_report_block(report_block);
            }

            compound = compound.add_packet(sr);
        } else if num_report_blocks > 0 {
            let mut rr = ReceiverReport::builder(fallback_sender_ssrc.0);

            // Add Report Blocks
            for report_block in self.report_blocks.drain(..num_report_blocks) {
                rr = rr.add_report_block(report_block);
            }

            compound = compound.add_packet(rr);
        }

        let mut remaining_mtu = mtu;
        while let Some(fb) = self
            .payload_feedback
            .pop_if(|fb| remaining_mtu >= fb.calculate_size().unwrap())
        {
            compound = compound.add_packet(fb);
            remaining_mtu = mtu.saturating_sub(compound.calculate_size().unwrap());
        }

        while let Some(fb) = self
            .transport_feedback
            .pop_if(|fb| remaining_mtu >= fb.calculate_size().unwrap())
        {
            compound = compound.add_packet(fb);
            remaining_mtu = mtu.saturating_sub(compound.calculate_size().unwrap());
        }

        let (_remaining_mtu, num_bye) = calculate_num_of_packet_type(
            remaining_mtu,
            Bye::MIN_PACKET_LEN,
            4,
            self.bye.len(),
            usize::from(Bye::MAX_COUNT),
        );

        // Add Bye packets
        if num_bye > 0 {
            let mut bye = Bye::builder();

            for ssrc in self.bye.drain(0..num_bye) {
                bye = bye.add_source(ssrc.0);
            }

            compound = compound.add_packet(bye);
        }

        Some(compound)
    }
}

fn calculate_num_of_packet_type(
    mtu: usize,
    base_packet_len: usize,
    len_per_entry: usize,
    num_entries: usize,
    max_entries: usize,
) -> (usize, usize) {
    let num = mtu.saturating_sub(base_packet_len) / len_per_entry;
    let num = cmp::min(num, max_entries);
    let num = cmp::min(num, num_entries);

    let mtu = if num == 0 {
        mtu
    } else {
        mtu.saturating_sub(base_packet_len + num * len_per_entry)
    };

    (mtu, num)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtp::rtcp_types::{Compound, Packet};

    #[test]
    fn single_sr() {
        let mut reports = ReportsQueue::new(false);

        assert!(reports.make_report(Ssrc(0), Mtu::new(1200)).is_none());

        // Single SR
        reports.add_sender_report(SenderReport::builder(0));

        let report = reports.make_report(Ssrc(0), Mtu::new(1200)).unwrap();
        assert!(report.len() <= 1200);
        let mut compound = Compound::parse(&report).unwrap();

        let Packet::Sr(..) = compound.next().unwrap().unwrap() else {
            panic!()
        };
        assert!(compound.next().is_none());
        assert!(reports.is_empty());
    }

    #[test]
    fn single_sr_with_report_block() {
        let mut reports = ReportsQueue::new(false);

        // Single SR with 1 report block
        reports.add_sender_report(SenderReport::builder(0));
        reports.add_report_block(ReportBlock::builder(0));

        let report = reports.make_report(Ssrc(0), Mtu::new(1200)).unwrap();
        assert!(report.len() <= 1200);
        let mut compound = Compound::parse(&report).unwrap();

        let Packet::Sr(sr) = compound.next().unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(sr.n_reports(), 1);
        assert!(compound.next().is_none());
        assert!(reports.is_empty());
    }
}
