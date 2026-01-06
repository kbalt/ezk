use crate::encoder::config::{FramePattern, H264FrameType};

#[derive(Debug)]
pub(crate) struct H264EncoderState {
    frame_pattern: FramePattern,

    /// Number of bits to use for picture_order_count_lsb
    pub(crate) log2_max_pic_order_cnt_lsb: u8,
    /// Number of bits to use for frame_num
    pub(crate) log2_max_frame_num: u8,

    /// Number of frames that have been submitted to the encoder (but not necessarily encoded)
    num_submitted_frames: u64,

    /// Display index (nth submitted frame) of the last IDR frame
    current_idr_display: u64,

    /// ID of the last IDR frame (incremented with each IDR frame)
    idr_pic_id: u16,

    /// Frame index in the current GOP, not incremented for B Frames
    current_frame_num: u16,
}

impl H264EncoderState {
    pub(crate) fn new(frame_pattern: FramePattern) -> Self {
        let max_frame_num = frame_pattern.intra_idr_period / frame_pattern.ip_period;
        let log2_max_frame_num = ((max_frame_num as f32).log2().ceil() as u8).clamp(4, 16);

        let max_pic_order_cnt_lsb = frame_pattern.intra_idr_period;
        let log2_max_pic_order_cnt_lsb =
            ((max_pic_order_cnt_lsb as f32).log2().ceil() as u8).clamp(4, 16);

        H264EncoderState {
            frame_pattern,
            log2_max_pic_order_cnt_lsb,
            log2_max_frame_num,
            num_submitted_frames: 0,
            current_idr_display: 0,
            idr_pic_id: 0,
            current_frame_num: 0,
        }
    }

    pub(crate) fn begin_new_gop(&mut self) {
        self.num_submitted_frames = self
            .num_submitted_frames
            .next_multiple_of(self.frame_pattern.intra_idr_period.into());
    }

    pub(crate) fn next(&mut self) -> FrameEncodeInfo {
        let frame_type = self
            .frame_pattern
            .frame_type_of_nth_frame(self.num_submitted_frames);

        if frame_type == H264FrameType::Idr {
            self.current_frame_num = 0;
            self.current_idr_display = self.num_submitted_frames;
            self.idr_pic_id = self.idr_pic_id.wrapping_add(1);
        }

        let picture_order_count = self.num_submitted_frames - self.current_idr_display;

        let info = FrameEncodeInfo {
            frame_type,
            frame_num: self.current_frame_num,
            picture_order_count: picture_order_count.try_into().unwrap(),
            idr_pic_id: self.idr_pic_id - 1, // idr_pic_id is always incremented once at start
        };

        if frame_type != H264FrameType::B {
            self.current_frame_num = self.current_frame_num.wrapping_add(1);
        }

        self.num_submitted_frames += 1;

        info
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameEncodeInfo {
    pub(crate) frame_type: H264FrameType,
    pub(crate) frame_num: u16,
    pub(crate) picture_order_count: u16,
    pub(crate) idr_pic_id: u16,
}
