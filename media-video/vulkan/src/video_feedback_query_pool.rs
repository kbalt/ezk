use crate::{Device, VulkanError};
use ash::vk::{self};

pub struct VideoFeedbackQueryPool {
    device: Device,
    query_pool: vk::QueryPool,
}

impl VideoFeedbackQueryPool {
    pub fn create(
        device: &Device,
        query_count: u32,
        video_profile_info: vk::VideoProfileInfoKHR,
    ) -> Result<Self, VulkanError> {
        unsafe {
            let mut query_pool_video_encode_feedback_create_info =
                vk::QueryPoolVideoEncodeFeedbackCreateInfoKHR::default().encode_feedback_flags(
                    vk::VideoEncodeFeedbackFlagsKHR::BITSTREAM_BYTES_WRITTEN
                        | vk::VideoEncodeFeedbackFlagsKHR::BITSTREAM_BUFFER_OFFSET,
                );

            let mut video_profile_info = video_profile_info;
            let query_create_info = vk::QueryPoolCreateInfo::default()
                .query_type(vk::QueryType::VIDEO_ENCODE_FEEDBACK_KHR)
                .query_count(query_count)
                .push_next(&mut video_profile_info)
                .push_next(&mut query_pool_video_encode_feedback_create_info);

            let query_pool = device
                .device()
                .create_query_pool(&query_create_info, None)?;

            Ok(Self {
                device: device.clone(),
                query_pool,
            })
        }
    }

    pub unsafe fn get_bytes_written(&mut self, index: u32) -> Result<u32, VulkanError> {
        let mut feedback = [EncodeFeedback {
            offset: 0,
            bytes_written: 0,
            status: vk::QueryResultStatusKHR::NOT_READY,
        }];

        self.device.device().get_query_pool_results(
            self.query_pool,
            index,
            &mut feedback,
            vk::QueryResultFlags::WITH_STATUS_KHR | vk::QueryResultFlags::WAIT,
        )?;

        let [feedback] = feedback;

        if feedback.status != vk::QueryResultStatusKHR::COMPLETE {
            return Err(VulkanError::QueryFailed {
                status: feedback.status,
            });
        }

        Ok(feedback.bytes_written)
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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EncodeFeedback {
    offset: u32,
    bytes_written: u32,
    status: vk::QueryResultStatusKHR,
}
