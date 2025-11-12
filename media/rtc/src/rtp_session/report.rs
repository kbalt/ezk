use crate::Mtu;
use rtp::{
    Ssrc,
    rtcp_types::{
        Bye, CompoundBuilder, Fir, PayloadFeedback, Pli, ReceiverReport, ReportBlock,
        ReportBlockBuilder, RtcpPacket, RtcpPacketWriter, SenderReport, SenderReportBuilder,
    },
};
use std::{cmp, collections::VecDeque};

/// Collection of RTCP packets to be sent out
pub(super) struct ReportsQueue {
    sender_reports: VecDeque<SenderReportBuilder>,
    report_blocks: VecDeque<ReportBlockBuilder>,

    nack_pli: Vec<Ssrc>,
    ccm_fir: Vec<(Ssrc, u8)>,

    sources_to_bye: Vec<Ssrc>,

    /// If reduced size RTCP is allows, (RTCP packets without SR/RR)
    rtcp_rsize: bool,
}

impl ReportsQueue {
    pub(super) fn new(rtcp_rsize: bool) -> ReportsQueue {
        ReportsQueue {
            sender_reports: VecDeque::new(),
            report_blocks: VecDeque::new(),
            nack_pli: Vec::new(),
            ccm_fir: Vec::new(),
            sources_to_bye: Vec::new(),
            rtcp_rsize,
        }
    }

    pub(super) fn rtcp_rsize(&self) -> bool {
        self.rtcp_rsize
    }

    pub(super) fn is_empty(&self) -> bool {
        let Self {
            sender_reports,
            report_blocks,
            sources_to_bye,
            nack_pli,
            ccm_fir,
            rtcp_rsize: _,
        } = self;

        sender_reports.is_empty()
            && report_blocks.is_empty()
            && sources_to_bye.is_empty()
            && nack_pli.is_empty()
            && ccm_fir.is_empty()
    }

    pub(super) fn has_feedback(&self) -> bool {
        !self.nack_pli.is_empty() || !self.ccm_fir.is_empty()
    }

    pub(super) fn add_sender_report(&mut self, sr: SenderReportBuilder) {
        self.sender_reports.push_back(sr);
    }

    pub(super) fn add_report_block(&mut self, rb: ReportBlockBuilder) {
        self.report_blocks.push_back(rb);
    }

    pub(super) fn add_nack_pli(&mut self, ssrc: Ssrc) {
        self.nack_pli.push(ssrc);
    }

    pub(super) fn add_ccm_fir(&mut self, ssrc: Ssrc, seq: u8) {
        self.ccm_fir.push((ssrc, seq));
    }

    pub(super) fn add_bye(&mut self, ssrc: Ssrc) {
        self.sources_to_bye.push(ssrc);
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

        let (mtu, num_pli) = calculate_num_of_packet_type(
            mtu,
            0,
            PayloadFeedback::MIN_PACKET_LEN,
            self.nack_pli.len(),
            usize::MAX,
        );

        let (mtu, num_fir) = calculate_num_of_packet_type(
            mtu,
            PayloadFeedback::MIN_PACKET_LEN,
            8,
            self.ccm_fir.len(),
            usize::from(u16::MAX) / 2 - 2,
        );

        let (mtu, num_bye) = calculate_num_of_packet_type(
            mtu,
            Bye::MIN_PACKET_LEN,
            4,
            self.sources_to_bye.len(),
            usize::from(Bye::MAX_COUNT),
        );

        let (_mtu, num_report_blocks) = calculate_num_of_packet_type(
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

        // Add PLI payload feedback
        for media_ssrc in self.nack_pli.drain(0..num_pli) {
            compound = compound.add_packet(
                PayloadFeedback::builder_owned(Pli::builder())
                    .sender_ssrc(fallback_sender_ssrc.0)
                    .media_ssrc(media_ssrc.0),
            );
        }

        // Add FIR payload feedback
        if num_fir > 0 {
            let mut fir = Fir::builder();

            for (ssrc, sequence) in self.ccm_fir.drain(0..num_fir) {
                fir = fir.add_ssrc(ssrc.0, sequence);
            }

            compound = compound.add_packet(
                PayloadFeedback::builder_owned(fir)
                    // https://datatracker.ietf.org/doc/html/rfc5104#section-4.3.1.2:
                    //    Within the common packet header for feedback messages (as defined in
                    //    indicates the source of the request, and the "SSRC of media source"
                    //    is not used and SHALL be set to 0
                    .sender_ssrc(fallback_sender_ssrc.0)
                    .media_ssrc(0),
            );
        }

        // Add Bye packets
        if num_bye > 0 {
            let mut bye = Bye::builder();

            for ssrc in self.sources_to_bye.drain(0..num_bye) {
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
