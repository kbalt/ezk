use crate::{
    Level, Profile,
    fmtp::{FmtpOptions, PacketizationMode},
};

pub mod libva;
#[cfg(feature = "openh264")]
pub mod openh264;
pub mod vulkan;

mod frame_pattern;

pub use frame_pattern::{FramePattern, FrameType};

struct H264EncoderState {
    frame_pattern: FramePattern,

    /// Number of bits to use for the picture_order_count
    log2_max_pic_order_cnt_lsb: i32,
    /// Maximum value of picture_order_count
    max_pic_order_cnt_lsb: i32,

    /// Number of frames that have been submitted to the encoder (but not necessarily encoded)
    num_submitted_frames: u32,

    /// Display index (nth submitted frame) of the last IDR frame
    current_idr_display: u32,
    /// ID of the last IDR frame (incremented with each IDR frame)
    idr_pic_id: u16,

    /// Frame index in the current GOP, not incremented for B Frames
    current_frame_num: u16,

    pic_order_cnt_msb_ref: i32,
    pic_order_cnt_lsb_ref: i32,
}

impl H264EncoderState {
    fn new(frame_pattern: FramePattern) -> Self {
        let intra_idr_period = frame_pattern.intra_idr_period;
        let log2_max_pic_order_cnt_lsb =
            ((intra_idr_period as f32).log2().ceil() as i32).clamp(4, 12);
        let max_pic_order_cnt_lsb = 1 << log2_max_pic_order_cnt_lsb;

        Self {
            frame_pattern,
            log2_max_pic_order_cnt_lsb,
            max_pic_order_cnt_lsb,
            num_submitted_frames: 0,
            current_idr_display: 0,
            idr_pic_id: 0,
            current_frame_num: 0,
            pic_order_cnt_msb_ref: 0,
            pic_order_cnt_lsb_ref: 0,
        }
    }

    fn calc_top_field_order_cnt(&mut self, frame_type: FrameType, pic_order_cnt_lsb: i32) -> i32 {
        let (prev_pic_order_cnt_msb, prev_pic_order_cnt_lsb) = if frame_type == FrameType::Idr {
            (0, 0)
        } else {
            (self.pic_order_cnt_msb_ref, self.pic_order_cnt_lsb_ref)
        };

        let pic_order_cnt_msb = if (pic_order_cnt_lsb < prev_pic_order_cnt_lsb)
            && ((prev_pic_order_cnt_lsb - pic_order_cnt_lsb) >= (self.max_pic_order_cnt_lsb / 2))
        {
            prev_pic_order_cnt_msb + self.max_pic_order_cnt_lsb
        } else if (pic_order_cnt_lsb > prev_pic_order_cnt_lsb)
            && ((pic_order_cnt_lsb - prev_pic_order_cnt_lsb) > (self.max_pic_order_cnt_lsb / 2))
        {
            prev_pic_order_cnt_msb - self.max_pic_order_cnt_lsb
        } else {
            prev_pic_order_cnt_msb
        };

        let top_field_order_cnt = pic_order_cnt_msb + pic_order_cnt_lsb;

        if frame_type != FrameType::B {
            self.pic_order_cnt_msb_ref = pic_order_cnt_msb;
            self.pic_order_cnt_lsb_ref = pic_order_cnt_lsb;
        }

        top_field_order_cnt
    }

    fn next(&mut self) -> FrameEncodeInfo {
        let frame_type = self
            .frame_pattern
            .frame_type_of_nth_frame(self.num_submitted_frames);
        if frame_type == FrameType::Idr {
            self.current_frame_num = 0;
            self.current_idr_display = self.num_submitted_frames;
            self.idr_pic_id += 1;
        }

        let poc_lsb = (self.num_submitted_frames as i32 - self.current_idr_display as i32)
            % self.max_pic_order_cnt_lsb;
        let poc = self.calc_top_field_order_cnt(frame_type, poc_lsb);

        let info = FrameEncodeInfo {
            frame_type,
            frame_num: self.current_frame_num,
            pic_order_cnt_lsb: poc.try_into().unwrap(),
            idr_pic_id: self.idr_pic_id,
        };

        if frame_type != FrameType::B {
            self.current_frame_num += 1;
        }
        self.num_submitted_frames += 1;

        info
    }
}

#[derive(Debug)]
struct FrameEncodeInfo {
    frame_type: FrameType,
    frame_num: u16,
    pic_order_cnt_lsb: u16,
    idr_pic_id: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum H264RateControlConfig {
    /// CBR (Constant Bit Rate)
    ConstantBitRate { bitrate: u32 },

    /// VBR (Variable Bit Rate)
    VariableBitRate {
        average_bitrate: u32,
        max_bitrate: u32,
    },

    /// Constant Quality
    ConstantQuality {
        const_qp: u8,
        max_bitrate: Option<u32>,
    },
}

/// Generic H.264 encoder config
#[derive(Debug, Clone, Copy)]
pub struct H264EncoderConfig {
    /// H.264 encoding profile to use. Defines the feature-set the encoder may use.
    pub profile: Profile,

    /// H264 encoding level. Defines default constraints like frame size, fps and more.
    pub level: Level,

    /// width & height of the image to be encoded.
    ///
    /// This value is only used for the initialization and should represent to largest allowed resolution.
    /// Some encoders will not be able to handle larger resolutions later without being reinitialized.
    pub resolution: (u32, u32),

    /// Define the range of QP values the encoder is allowed use.
    ///
    /// Allowed values range from 0 to 51, where 0 is the best quality and 51 the worst with the most compression.
    ///
    /// Default is (17..=28) but manual tuning is recommended!
    pub qp: Option<(u32, u32)>,

    /// Pattern of frames to emit
    pub frame_pattern: FramePattern,

    /// Target bitrate in bits/s
    pub bitrate: Option<u32>,

    /// Override the level's maximum bitrate in bits/s
    pub max_bitrate: Option<u32>,

    /// Limit the output slice size.
    ///
    /// Required if the packetization mode is SingleNAL which doesn't support fragmentation units.
    pub max_slice_len: Option<usize>,
}

impl H264EncoderConfig {
    /// Create a encoder config from the peer's H.264 decoder capabilities, communicated through SDP's fmtp attribute
    pub fn from_fmtp(fmtp: FmtpOptions, mtu: usize) -> Self {
        Self {
            profile: fmtp.profile_level_id.profile,
            level: fmtp.profile_level_id.level,
            resolution: fmtp.max_resolution(1, 1),
            qp: None,
            frame_pattern: FramePattern {
                intra_idr_period: 60,
                intra_period: 30,
                ip_period: 1,
            },
            bitrate: None,
            max_bitrate: Some(fmtp.max_bitrate()),
            max_slice_len: {
                match fmtp.packetization_mode {
                    PacketizationMode::SingleNAL => Some(mtu),
                    PacketizationMode::NonInterleavedMode | PacketizationMode::InterleavedMode => {
                        None
                    }
                }
            },
        }
    }
}
