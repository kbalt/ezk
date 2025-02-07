#[derive(Debug)]
pub(crate) enum PacketKind {
    Rtp,
    Rtcp,
    Stun,
    Dtls,
    Unknown,
}

impl PacketKind {
    pub(crate) fn identify(bytes: &[u8]) -> Self {
        if bytes.len() < 2 {
            return PacketKind::Unknown;
        }

        let byte = bytes[0];

        match byte {
            0 | 1 => PacketKind::Stun,
            20..=63 => PacketKind::Dtls,
            128..=191 => {
                let pt = bytes[1];

                if let 64..=95 = pt & 0x7F {
                    PacketKind::Rtcp
                } else {
                    PacketKind::Rtp
                }
            }
            _ => PacketKind::Unknown,
        }
    }
}
