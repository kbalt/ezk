pub mod libg722;

/// G.722 audio encoder using sane defaults
///
/// Supports encoding i16 audio samples at 16kHz
pub struct G722Encoder {
    encoder: libg722::Encoder,
}

impl G722Encoder {
    /// Create a new encoder
    pub fn new() -> Self {
        Self {
            encoder: libg722::Encoder::new(libg722::Bitrate::Mode1_64000, false, false),
        }
    }

    /// Encode the given samples, the encoded G.722 data will be appended to `out`
    pub fn encode(&mut self, samples: &[i16], out: &mut Vec<u8>) {
        self.encoder.encode(samples, out);
    }
}

impl Default for G722Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// G.722 audio decoder using sane defaults
///
/// Supports decoding i16 audio samples at 16kHz
pub struct G722Decoder {
    decoder: libg722::Decoder,
}

impl G722Decoder {
    /// Create a new decoder
    pub fn new() -> Self {
        Self {
            decoder: libg722::Decoder::new(libg722::Bitrate::Mode1_64000, false, false),
        }
    }

    /// Decode the given G.722 data, the decoded audio samples will be appended to `out`
    pub fn decode(&mut self, samples: &[u8], out: &mut Vec<i16>) {
        self.decoder.decode(samples, out);
    }
}

impl Default for G722Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Split the encoded G.722 into RTP payloads
pub fn packetize(g722_data: &[u8], mtu: usize) -> impl Iterator<Item = &[u8]> {
    g722_data.chunks(mtu)
}
