#[derive(Debug, Clone, Copy)]
pub struct AV1FramePattern {
    pub keyframe_interval: u16,
}

#[derive(Debug)]
pub(crate) struct AV1EncoderState {
    frame_pattern: AV1FramePattern,
    keyframe_index: u16,
    current_frame_id: u16,
}

impl AV1EncoderState {
    pub(crate) fn new(frame_pattern: AV1FramePattern) -> Self {
        AV1EncoderState {
            frame_pattern,
            keyframe_index: 0,
            current_frame_id: 0,
        }
    }

    pub(crate) fn request_keyframe(&mut self) {
        self.keyframe_index = 0;
    }

    pub(crate) fn next(&mut self) -> FrameEncodeInfo {
        let mut is_key = false;

        if self
            .keyframe_index
            .is_multiple_of(self.frame_pattern.keyframe_interval)
        {
            self.keyframe_index = 0;
            is_key = true;
        }

        let info = FrameEncodeInfo {
            is_key,
            current_frame_id: self.current_frame_id.into(),
            order_hint: (self.current_frame_id & 0xFF) as u8,
        };

        self.current_frame_id = self.current_frame_id.wrapping_add(1);
        self.keyframe_index = self.keyframe_index.wrapping_add(1);

        info
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameEncodeInfo {
    pub(crate) is_key: bool,
    pub(crate) current_frame_id: u32,
    pub(crate) order_hint: u8,
}
