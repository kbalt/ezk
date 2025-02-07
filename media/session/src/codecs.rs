use sdp_types::MediaType;
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct NegotiatedCodec {
    pub send_pt: u8,
    pub recv_pt: u8,
    pub name: Cow<'static, str>,
    pub clock_rate: u32,
    pub channels: Option<u32>,
    pub send_fmtp: Option<String>,
    pub recv_fmtp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Codec {
    /// Either set by the codec itself if it's static, or assigned later when added to a session
    pub(crate) pt: Option<u8>,
    pub(crate) pt_is_static: bool,
    pub(crate) name: Cow<'static, str>,
    pub(crate) clock_rate: u32,
    pub(crate) channels: Option<u32>,
    pub(crate) fmtp: Option<String>,
}

impl Codec {
    pub const PCMU: Self = Self::new("PCMU", 8000).with_static_pt(0);
    pub const PCMA: Self = Self::new("PCMA", 8000).with_static_pt(8);
    pub const G722: Self = Self::new("G722", 8000).with_static_pt(9).with_channels(1);
    pub const OPUS: Self = Self::new("OPUS", 48_000).with_channels(2);

    pub const H264: Self = Self::new("H264", 90_000);
    pub const VP8: Self = Self::new("VP8", 90_000);
    pub const VP9: Self = Self::new("VP9", 90_000);
    pub const AV1: Self = Self::new("AV1", 90_000);

    pub const fn new(name: &'static str, clock_rate: u32) -> Self {
        Codec {
            pt: None,
            pt_is_static: false,
            name: Cow::Borrowed(name),
            clock_rate,
            channels: None,
            fmtp: None,
        }
    }

    pub const fn with_static_pt(mut self, static_pt: u8) -> Self {
        assert!(
            static_pt < 35,
            "static payload type must not be in the dynamic/rtcp range"
        );
        self.pt = Some(static_pt);
        self.pt_is_static = true;
        self
    }

    /// Sets the payload type number to use for this codec.
    ///
    /// **This will circumvent the dynamic assignments made by the crate, so use with caution.**
    pub const fn with_pt(mut self, pt: u8) -> Self {
        assert!(
            pt > 96 && pt <= 127,
            "payload type must be in the dynamic range"
        );

        self.pt = Some(pt);
        self
    }

    pub const fn with_channels(mut self, channels: u32) -> Self {
        self.channels = Some(channels);
        self
    }

    pub fn with_fmtp(mut self, fmtp: String) {
        self.fmtp = Some(fmtp);
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub struct Codecs {
    pub(crate) media_type: MediaType,
    pub(crate) codecs: Vec<Codec>,
    pub(crate) allow_dtmf: bool,
}

impl Codecs {
    pub fn new(media_type: MediaType) -> Self {
        Self {
            media_type,
            codecs: vec![],
            allow_dtmf: false,
        }
    }

    pub fn allow_dtmf(mut self, dtmf: bool) -> Self {
        self.allow_dtmf = dtmf;
        self
    }

    pub fn with_codec(mut self, codec: Codec) -> Self {
        self.add_codec(codec);
        self
    }

    pub fn add_codec(&mut self, codec: Codec) -> &mut Self {
        self.codecs.push(codec);
        self
    }
}
