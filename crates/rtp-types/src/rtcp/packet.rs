use super::app::App;
use super::bye::Bye;
use super::report::{ReceiverReport, SenderReport};
use super::sdes::SourceDescription;
use super::DecodeError;
use super::Header;
use bytes::{Buf, BufMut};

pub struct Packet {
    pub header: Header,
    pub kind: PacketKind,
}

pub enum PacketKind {
    SenderReport(SenderReport),
    ReceiverReport(ReceiverReport),
    SourceDescription(SourceDescription),
    Bye(Bye),
    App(App),
}

impl Packet {
    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        self.header.encode(dst);

        match &self.kind {
            PacketKind::SenderReport(sr) => sr.encode(dst),
            PacketKind::ReceiverReport(rr) => rr.encode(dst),
            PacketKind::SourceDescription(sd) => sd.encode(dst),
            PacketKind::Bye(bye) => bye.encode(dst),
            PacketKind::App(app) => app.encode(dst),
        }
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        let header = Header::decode(&mut buf)?;

        let kind = match header.pt {
            200 => PacketKind::SenderReport(SenderReport::decode(&mut buf, &header)?),
            201 => PacketKind::ReceiverReport(ReceiverReport::decode(&mut buf, &header)?),
            202 => PacketKind::SourceDescription(SourceDescription::decode(&mut buf)?),
            203 => PacketKind::Bye(Bye::decode(&mut buf, &header)?),
            204 => PacketKind::App(App::decode(&mut buf)?),
            _ => todo!(),
        };

        Ok(Self { header, kind })
    }
}
