use crate::encoder::{H264FramePattern, H264FrameType};

pub(crate) fn macro_block_align(v: u32) -> u32 {
    (v + 0xF) & !0xF
}

pub(crate) struct H264EncoderState {
    frame_pattern: H264FramePattern,

    /// Number of bits to use for the picture_order_count
    pub(crate) log2_max_pic_order_cnt_lsb: i32,
    /// Maximum value of picture_order_count
    pub(crate) max_pic_order_cnt_lsb: i32,

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
    pub(crate) fn new(frame_pattern: H264FramePattern) -> Self {
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

    fn calc_top_field_order_cnt(
        &mut self,
        frame_type: H264FrameType,
        pic_order_cnt_lsb: i32,
    ) -> i32 {
        let (prev_pic_order_cnt_msb, prev_pic_order_cnt_lsb) = if frame_type == H264FrameType::Idr {
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

        if frame_type != H264FrameType::B {
            self.pic_order_cnt_msb_ref = pic_order_cnt_msb;
            self.pic_order_cnt_lsb_ref = pic_order_cnt_lsb;
        }

        top_field_order_cnt
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

        let poc_lsb = (self.num_submitted_frames as i32 - self.current_idr_display as i32)
            % self.max_pic_order_cnt_lsb;

        let poc = self.calc_top_field_order_cnt(frame_type, poc_lsb);

        let info = FrameEncodeInfo {
            frame_type,
            frame_num: self.current_frame_num,
            pic_order_cnt_lsb: poc as u16,
            idr_pic_id: self.idr_pic_id,
        };

        if frame_type != H264FrameType::B {
            self.current_frame_num += 1;
        }

        self.num_submitted_frames += 1;

        info
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameEncodeInfo {
    pub(crate) frame_type: H264FrameType,
    pub(crate) frame_num: u16,
    pub(crate) pic_order_cnt_lsb: u16,
    pub(crate) idr_pic_id: u16,
}
