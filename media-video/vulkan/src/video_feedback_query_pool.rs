use crate::Device;
use ash::vk::{self, TaggedStructure};

pub struct VideoFeedbackQueryPool {
    device: Device,
    query_pool: vk::QueryPool,
}

impl VideoFeedbackQueryPool {
    pub fn create(
        device: &Device,
        query_count: u32,
        video_profile_info: vk::VideoProfileInfoKHR,
    ) -> Self {
        unsafe {
            let mut query_pool_video_encode_feedback_create_info =
                vk::QueryPoolVideoEncodeFeedbackCreateInfoKHR::default().encode_feedback_flags(
                    vk::VideoEncodeFeedbackFlagsKHR::BITSTREAM_BYTES_WRITTEN,
                );

            let mut video_profile_info = video_profile_info;
            let query_create_info = vk::QueryPoolCreateInfo::default()
                .query_type(vk::QueryType::VIDEO_ENCODE_FEEDBACK_KHR)
                .query_count(query_count)
                .extend(&mut video_profile_info)
                .push(&mut query_pool_video_encode_feedback_create_info);

            let query_pool = device
                .device()
                .create_query_pool(&query_create_info, None)
                .unwrap();

            Self {
                device: device.clone(),
                query_pool,
            }
        }
    }

    pub unsafe fn get_bytes_written(&mut self, index: u32) -> u64 {
        let mut bytes_written = [[0u64; 2]; 1];

        self.device
            .device()
            .get_query_pool_results(
                self.query_pool,
                index,
                &mut bytes_written,
                vk::QueryResultFlags::TYPE_64 | vk::QueryResultFlags::WAIT,
            )
            .unwrap();

        bytes_written[0][1]
    }

    pub unsafe fn cmd_reset_query(&mut self, command_buffer: vk::CommandBuffer, index: u32) {
        self.device
            .device()
            .cmd_reset_query_pool(command_buffer, self.query_pool, index, 1);
    }

    pub unsafe fn cmd_begin_query(&mut self, command_buffer: vk::CommandBuffer, index: u32) {
        self.device.device().cmd_begin_query(
            command_buffer,
            self.query_pool,
            index,
            vk::QueryControlFlags::empty(),
        );
    }

    pub unsafe fn cmd_end_query(&mut self, command_buffer: vk::CommandBuffer, index: u32) {
        self.device
            .device()
            .cmd_end_query(command_buffer, self.query_pool, index);
    }
}

impl Drop for VideoFeedbackQueryPool {
    fn drop(&mut self) {
        unsafe {
            self.device
                .device()
                .destroy_query_pool(self.query_pool, None);
        }
    }
}
