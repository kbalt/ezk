use ezk_image::ImageRef;

use crate::encoder::{
    H264EncoderConfig, H264FrameType,
    util::{FrameEncodeInfo, H264EncoderState},
};
use std::{collections::VecDeque, mem::take};

pub(super) struct H264EncoderBackendResources<B: H264EncoderBackend> {
    pub(super) backend: B,
    pub(super) encode_slots: Vec<B::EncodeSlot>,
    pub(super) dpb_slots: Vec<B::DpbSlot>,
}

pub(super) trait H264EncoderBackend: Sized {
    type EncodeSlot;
    type DpbSlot;

    type Error: std::error::Error;

    fn wait_encode_slot(&mut self, encode_slot: &mut Self::EncodeSlot) -> Result<(), Self::Error>;
    fn poll_encode_slot(&mut self, encode_slot: &mut Self::EncodeSlot)
    -> Result<bool, Self::Error>;

    fn read_out_encode_slot(
        &mut self,
        encode_slot: &mut Self::EncodeSlot,
        output: &mut VecDeque<Vec<u8>>,
    ) -> Result<(), Self::Error>;

    fn upload_image_to_slot(
        &mut self,
        encode_slot: &mut Self::EncodeSlot,
        image: &dyn ImageRef,
    ) -> Result<(), Self::Error>;

    fn encode_slot(
        &mut self,
        frame_info: FrameEncodeInfo,
        encode_slot: &mut Self::EncodeSlot,
        setup_reference: &mut Self::DpbSlot,
        l0_references: &[&Self::DpbSlot],
        l1_references: &[&Self::DpbSlot],
    ) -> Result<(), Self::Error>;
}

pub(super) struct H264StatelessEncoder<B: H264EncoderBackend> {
    backend: B,

    state: H264EncoderState,

    max_l0_p_ref_images: u32,
    max_l0_b_ref_images: u32,
    max_l1_b_ref_images: u32,

    available_encode_slots: Vec<B::EncodeSlot>,
    in_flight: VecDeque<B::EncodeSlot>,

    active_dpb_slots: VecDeque<(u16, B::DpbSlot)>,
    available_dpb_slots: Vec<B::DpbSlot>,

    backlogged_b_frames: Vec<(FrameEncodeInfo, B::EncodeSlot)>,

    output: VecDeque<Vec<u8>>,
}

impl<B: H264EncoderBackend> H264StatelessEncoder<B> {
    pub(super) fn new(
        config: H264EncoderConfig,
        resources: H264EncoderBackendResources<B>,
    ) -> Self {
        let H264EncoderBackendResources {
            backend,
            encode_slots,
            dpb_slots,
        } = resources;

        H264StatelessEncoder {
            backend,
            state: H264EncoderState::new(config.frame_pattern),
            max_l0_p_ref_images: config.max_l0_p_references,
            max_l0_b_ref_images: config.max_l0_b_references,
            max_l1_b_ref_images: config.max_l1_b_references,
            available_encode_slots: encode_slots,
            in_flight: VecDeque::new(),
            active_dpb_slots: VecDeque::new(),
            available_dpb_slots: dpb_slots,
            backlogged_b_frames: Vec::new(),
            output: VecDeque::new(),
        }
    }

    pub(super) fn wait_result(&mut self) -> Result<Option<Vec<u8>>, B::Error> {
        if let Some(buf) = self.output.pop_front() {
            return Ok(Some(buf));
        }

        if let Some(mut encode_slot) = self.in_flight.pop_front() {
            self.backend.wait_encode_slot(&mut encode_slot)?;
            self.backend
                .read_out_encode_slot(&mut encode_slot, &mut self.output)?;
            self.available_encode_slots.push(encode_slot);
        }

        Ok(self.output.pop_front())
    }

    pub(super) fn poll_result(&mut self) -> Result<Option<Vec<u8>>, B::Error> {
        if let Some(buf) = self.output.pop_front() {
            return Ok(Some(buf));
        }

        if let Some(encode_slot) = self.in_flight.front_mut() {
            let completed = self.backend.poll_encode_slot(encode_slot).unwrap();
            if !completed {
                return Ok(None);
            }

            let mut encode_slot = self.in_flight.pop_front().unwrap();

            self.backend
                .read_out_encode_slot(&mut encode_slot, &mut self.output)?;

            self.available_encode_slots.push(encode_slot);
        }

        Ok(self.output.pop_front())
    }

    pub(super) fn encode_frame(&mut self, image: &dyn ImageRef) -> Result<(), B::Error> {
        let frame_info = self.state.next();
        log::debug!("Submit frame {frame_info:?}");

        let mut encode_slot = if let Some(encode_slot) = self.available_encode_slots.pop() {
            encode_slot
        } else if let Some(mut encode_slot) = self.in_flight.pop_back() {
            self.backend.wait_encode_slot(&mut encode_slot)?;
            self.backend
                .read_out_encode_slot(&mut encode_slot, &mut self.output)?;
            encode_slot
        } else {
            unreachable!()
        };

        self.backend.upload_image_to_slot(&mut encode_slot, image)?;

        // B-Frames are not encoded immediately, they are queued until after an I or P-frame is encoded
        if frame_info.frame_type == H264FrameType::B {
            self.backlogged_b_frames.push((frame_info, encode_slot));
            return Ok(());
        }

        if frame_info.frame_type == H264FrameType::Idr {
            assert!(self.backlogged_b_frames.is_empty());

            // Just encoded an IDR frame, put all reference surfaces back into the surface pool,
            self.available_dpb_slots.extend(
                self.active_dpb_slots
                    .drain(..)
                    .map(|(_, reference)| reference),
            );
        }

        self.encode_slot(frame_info, encode_slot);

        if matches!(
            frame_info.frame_type,
            H264FrameType::Idr | H264FrameType::I | H264FrameType::P
        ) {
            let backlogged_b_frames = take(&mut self.backlogged_b_frames);

            // Process backlogged B-Frames
            for (frame_info, encode_slot) in backlogged_b_frames {
                self.encode_slot(frame_info, encode_slot);
            }
        }

        Ok(())
    }

    fn encode_slot(&mut self, frame_info: FrameEncodeInfo, mut encode_slot: B::EncodeSlot) {
        log::trace!("Encode slot {frame_info:?}");

        let mut setup_dpb_slot = if let Some(dpb_slot) = self.available_dpb_slots.pop() {
            dpb_slot
        } else if let Some((_, dpb_slot)) = self.active_dpb_slots.pop_back() {
            dpb_slot
        } else {
            unreachable!()
        };

        let l0 = self
            .active_dpb_slots
            .iter()
            .filter(|(display_index, _)| *display_index < frame_info.picture_order_count)
            .map(|(_, dpb_slot)| dpb_slot);

        let l1 = self
            .active_dpb_slots
            .iter()
            .rev()
            .filter(|(display_index, _)| *display_index > frame_info.picture_order_count)
            .map(|(_, dpb_slots)| dpb_slots);

        let (l0_references, l1_references) = match frame_info.frame_type {
            H264FrameType::P => (l0.take(self.max_l0_p_ref_images as usize).collect(), vec![]),
            H264FrameType::B => (
                l0.take(self.max_l0_b_ref_images as usize).collect(),
                l1.take(self.max_l1_b_ref_images as usize).collect(),
            ),
            H264FrameType::I | H264FrameType::Idr => (vec![], vec![]),
        };

        self.backend
            .encode_slot(
                frame_info,
                &mut encode_slot,
                &mut setup_dpb_slot,
                &l0_references,
                &l1_references,
            )
            .unwrap();

        if frame_info.frame_type != H264FrameType::B {
            self.active_dpb_slots
                .push_front((frame_info.picture_order_count, setup_dpb_slot));
        } else {
            self.available_dpb_slots.push(setup_dpb_slot);
        }

        self.in_flight.push_back(encode_slot);
    }
}
