use crate::{RtpExtensionsWriter, RtpTimestamp, SequenceNumber, Ssrc, parse_extensions};
use bytes::Bytes;
use rtp_types::{RtpPacketBuilder, prelude::RtpPacketWriter};

#[derive(Debug, Clone)]
pub struct RtpPacket {
    pub pt: u8,
    pub sequence_number: SequenceNumber,
    pub ssrc: Ssrc,
    pub timestamp: RtpTimestamp,
    pub extensions: RtpExtensions,
    pub payload: Bytes,
}

#[derive(Debug, Default, Clone)]
pub struct RtpExtensions {
    pub mid: Option<Bytes>,
}

/// ID to attribute type map to use when parsing or serializing RTP packets
#[derive(Debug, Default, Clone, Copy)]
pub struct RtpExtensionIds {
    pub mid: Option<u8>,
}

impl RtpPacket {
    pub fn write_vec(&self, extension_ids: RtpExtensionIds, vec: &mut Vec<u8>) {
        let builder = RtpPacketBuilder::<_, Vec<u8>>::new()
            .payload_type(self.pt)
            .sequence_number(self.sequence_number.0)
            .ssrc(self.ssrc.0)
            .timestamp(self.timestamp.0)
            .payload(&self.payload[..]);

        let builder = self.extensions.write(extension_ids, builder);

        vec.reserve(builder.calculate_size().unwrap());

        let mut writer = RtpPacketWriterVec {
            output: vec,
            padding: None,
        };
        builder.write(&mut writer).unwrap();
    }

    pub fn to_vec(&self, extension_ids: RtpExtensionIds) -> Vec<u8> {
        let mut vec = Vec::with_capacity(1500);
        self.write_vec(extension_ids, &mut vec);
        vec
    }

    pub fn parse(
        extension_ids: RtpExtensionIds,
        bytes: impl Into<Bytes>,
    ) -> Result<Self, rtp_types::RtpParseError> {
        let packet: Bytes = bytes.into();

        let parsed = rtp_types::RtpPacket::parse(&packet[..])?;

        let extensions = if let Some((profile, extension_data)) = parsed.extension() {
            RtpExtensions::from_packet(extension_ids, &packet, profile, extension_data)
        } else {
            RtpExtensions { mid: None }
        };

        Ok(Self {
            pt: parsed.payload_type(),
            sequence_number: SequenceNumber(parsed.sequence_number()),
            ssrc: Ssrc(parsed.ssrc()),
            timestamp: RtpTimestamp(parsed.timestamp()),
            extensions,
            payload: packet.slice_ref(parsed.payload()),
        })
    }
}

impl RtpExtensions {
    fn from_packet(
        ids: RtpExtensionIds,
        bytes: &Bytes,
        profile: u16,
        extension_data: &[u8],
    ) -> Self {
        let mut this = Self { mid: None };

        for (id, data) in parse_extensions(profile, extension_data) {
            if Some(id) == ids.mid {
                this.mid = Some(bytes.slice_ref(data));
            }
        }

        this
    }

    fn write<'b>(
        &self,
        ids: RtpExtensionIds,
        packet_builder: RtpPacketBuilder<&'b [u8], Vec<u8>>,
    ) -> RtpPacketBuilder<&'b [u8], Vec<u8>> {
        let Some((id, mid)) = ids.mid.zip(self.mid.as_ref()) else {
            return packet_builder;
        };

        let mut buf = vec![];

        let profile = RtpExtensionsWriter::new(&mut buf, mid.len() <= 16)
            .with(id, mid)
            .finish();

        packet_builder.extension(profile, buf)
    }
}

struct RtpPacketWriterVec<'a> {
    output: &'a mut Vec<u8>,
    padding: Option<u8>,
}

impl<'a> RtpPacketWriter for RtpPacketWriterVec<'a> {
    type Output = ();
    type Payload = &'a [u8];
    type Extension = Vec<u8>;

    fn reserve(&mut self, size: usize) {
        if self.output.len() < size {
            self.output.reserve(size - self.output.len());
        }
    }

    fn push(&mut self, data: &[u8]) {
        self.output.extend_from_slice(data)
    }

    fn push_extension(&mut self, extension_data: &Self::Extension) {
        self.push(extension_data)
    }

    fn push_payload(&mut self, data: &Self::Payload) {
        self.push(data)
    }

    fn padding(&mut self, size: u8) {
        self.padding = Some(size);
    }

    fn finish(&mut self) -> Self::Output {
        if let Some(padding) = self.padding.take() {
            self.output
                .resize(self.output.len() + padding as usize - 1, 0);
            self.output.push(padding);
        }
    }
}
