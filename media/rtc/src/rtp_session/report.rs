use crate::Mtu;
use rtp::{
    Ssrc,
    rtcp_types::{
        Bye, CompoundBuilder, ReceiverReport, ReceiverReportBuilder, ReportBlock,
        ReportBlockBuilder, RtcpPacket, RtcpPacketWriter, SenderReport, SenderReportBuilder,
    },
};
use std::collections::VecDeque;

const BYE_BYTES_PER_SOURCE: usize = 4;

/// Collection of RTCP packets to be sent out
#[derive(Default)]
pub(crate) struct ReportsQueue {
    sender_reports: VecDeque<SenderReportBuilder>,
    report_blocks: VecDeque<ReportBlockBuilder>,

    sources_to_bye: Vec<Ssrc>,
}

impl ReportsQueue {
    pub(crate) fn is_empty(&self) -> bool {
        let Self {
            sender_reports,
            report_blocks,
            sources_to_bye,
        } = self;

        sender_reports.is_empty() && report_blocks.is_empty() && sources_to_bye.is_empty()
    }

    pub(crate) fn add_sender_report(&mut self, sr: SenderReportBuilder) {
        self.sender_reports.push_back(sr);
    }

    pub(crate) fn add_report_block(&mut self, rb: ReportBlockBuilder) {
        self.report_blocks.push_back(rb);
    }

    pub(crate) fn add_bye(&mut self, ssrc: Ssrc) {
        self.sources_to_bye.push(ssrc);
    }

    pub(crate) fn make_report(&mut self, fallback_sender_ssrc: Ssrc, mtu: Mtu) -> Option<Vec<u8>> {
        self.make_report_compund(fallback_sender_ssrc, mtu)
            .map(|compound| {
                let mut buf = vec![0u8; compound.calculate_size().unwrap()];
                let len = compound.write_into_unchecked(&mut buf);
                buf.truncate(len);
                buf
            })
    }

    fn make_report_compund(
        &mut self,
        fallback_sender_ssrc: Ssrc,
        mtu: Mtu,
    ) -> Option<CompoundBuilder<'static>> {
        if self.is_empty() {
            return None;
        }

        let mtu = mtu.for_rtcp_packets();

        let mut compound = CompoundBuilder::default();

        loop {
            let compound_size = compound.calculate_size().unwrap();

            let compound_has_size_for_sr = compound_size + SenderReport::MIN_PACKET_LEN <= mtu;
            let compound_has_size_for_rr =
                compound_size + ReceiverReport::MIN_PACKET_LEN + ReportBlock::EXPECTED_SIZE <= mtu;
            let compound_has_size_for_bye =
                compound_size + (Bye::MIN_PACKET_LEN + BYE_BYTES_PER_SOURCE) <= mtu;

            if !self.sender_reports.is_empty() && compound_has_size_for_sr {
                // If there's a sender report, fill it with report blocks and add it to the compound
                let sender_report = self
                    .sender_reports
                    .pop_front()
                    .expect("sender_reports is not empty");
                compound = self.extend_and_add_report(mtu, compound, sender_report);
            } else if self.sender_reports.is_empty()
                && !self.report_blocks.is_empty()
                && compound_has_size_for_rr
            {
                // If there's no sender reports left, put the remaining report blocks in a receiver report
                let receiver_report = ReceiverReport::builder(fallback_sender_ssrc.0);
                compound = self.extend_and_add_report(mtu, compound, receiver_report);
            } else if !self.sources_to_bye.is_empty() && compound_has_size_for_bye {
                compound = self.add_bye_to_compound(mtu, compound, compound_size);
            } else {
                return Some(compound);
            }
        }
    }

    fn add_bye_to_compound(
        &mut self,
        mtu: usize,
        compound: CompoundBuilder<'static>,
        compound_size: usize,
    ) -> CompoundBuilder<'static> {
        let mut bye = Bye::builder();

        let mut sources_added = 0;
        while sources_added < 31
            && compound_size + bye.calculate_size().unwrap() + BYE_BYTES_PER_SOURCE <= mtu
        {
            let Some(ssrc) = self.sources_to_bye.pop() else {
                break;
            };

            bye = bye.add_source(ssrc.0);
            sources_added += 1;
        }

        compound.add_packet(bye)
    }

    fn extend_and_add_report(
        &mut self,
        mtu: usize,
        compound: CompoundBuilder<'static>,
        mut report: impl AnyReportBuilder,
    ) -> CompoundBuilder<'static> {
        let compound_size = compound.calculate_size().unwrap();

        let mut blocks_added = 0;
        while blocks_added < 31
            && compound_size + report.calculate_size().unwrap() + ReportBlock::EXPECTED_SIZE <= mtu
        {
            match self.report_blocks.pop_front() {
                Some(report_block) => {
                    report = report.add_report_block(report_block);
                    blocks_added += 1;
                }
                None => break,
            }
        }

        compound.add_packet(report)
    }
}

trait AnyReportBuilder: RtcpPacketWriter + 'static {
    fn add_report_block(self, report_block: ReportBlockBuilder) -> Self;
}

impl AnyReportBuilder for SenderReportBuilder {
    fn add_report_block(self, report_block: ReportBlockBuilder) -> Self {
        SenderReportBuilder::add_report_block(self, report_block)
    }
}

impl AnyReportBuilder for ReceiverReportBuilder {
    fn add_report_block(self, report_block: ReportBlockBuilder) -> Self {
        ReceiverReportBuilder::add_report_block(self, report_block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtp::rtcp_types::{Compound, Packet};

    #[test]
    fn single_sr() {
        let mut reports = ReportsQueue::default();

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
        let mut reports = ReportsQueue::default();

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

    #[test]
    fn two_sr_with_many_report_blocks() {
        let mut reports = ReportsQueue::default();

        reports.add_sender_report(SenderReport::builder(0));
        reports.add_sender_report(SenderReport::builder(1));

        for i in 0..64 {
            reports.add_report_block(ReportBlock::builder(i));
        }

        // First RTCP packet
        let report = reports.make_report(Ssrc(0), Mtu::new(1200)).unwrap();
        assert!(report.len() <= 1200);
        let mut compound = Compound::parse(&report).unwrap();

        let Packet::Sr(sr) = compound.next().unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(sr.n_reports(), 31);
        assert_eq!(sr.ssrc(), 0);

        let Packet::Sr(sr) = compound.next().unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(sr.n_reports(), 16);
        assert_eq!(sr.ssrc(), 1);
        assert!(compound.next().is_none());

        // Second RTCP packet
        let report = reports.make_report(Ssrc(0), Mtu::new(1200)).unwrap();
        assert!(report.len() <= 1200);
        let mut compound = Compound::parse(&report).unwrap();

        let Packet::Rr(rr) = compound.next().unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(rr.n_reports(), 17);
        assert!(compound.next().is_none());
        assert!(reports.is_empty());
    }
}
