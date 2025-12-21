use crate::{Device, VulkanError};
use ash::vk;

#[derive(Debug)]
pub(crate) struct VideoFeedbackQueryPool {
    device: Device,
    query_pool: vk::QueryPool,
}

impl VideoFeedbackQueryPool {
    pub(crate) fn create(
        device: &Device,
        query_count: u32,
        video_profile_info: &vk::VideoProfileInfoKHR<'_>,
    ) -> Result<Self, VulkanError> {
        unsafe {
            let mut query_pool_video_encode_feedback_create_info =
                vk::QueryPoolVideoEncodeFeedbackCreateInfoKHR::default().encode_feedback_flags(
                    vk::VideoEncodeFeedbackFlagsKHR::BITSTREAM_BYTES_WRITTEN
                        | vk::VideoEncodeFeedbackFlagsKHR::BITSTREAM_BUFFER_OFFSET,
                );

            let mut query_create_info = vk::QueryPoolCreateInfo::default()
                .query_type(vk::QueryType::VIDEO_ENCODE_FEEDBACK_KHR)
                .query_count(query_count);

            query_pool_video_encode_feedback_create_info.p_next =
                (video_profile_info as *const vk::VideoProfileInfoKHR<'_>).cast();
            query_create_info.p_next =
                (&raw const query_pool_video_encode_feedback_create_info).cast();

            let query_pool = device.ash().create_query_pool(&query_create_info, None)?;

            Ok(Self {
                device: device.clone(),
                query_pool,
            })
        }
    }

    pub(crate) unsafe fn get_bytes_written(&mut self, index: u32) -> Result<u32, VulkanError> {
        let mut feedback = [EncodeFeedback {
            offset: 0,
            bytes_written: 0,
            status: vk::QueryResultStatusKHR::NOT_READY,
        }];

        self.device.ash().get_query_pool_results(
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

    pub(crate) unsafe fn cmd_reset_query(&mut self, command_buffer: vk::CommandBuffer, index: u32) {
        self.device
            .ash()
            .cmd_reset_query_pool(command_buffer, self.query_pool, index, 1);
    }

    pub(crate) unsafe fn cmd_begin_query(&mut self, command_buffer: vk::CommandBuffer, index: u32) {
        self.device.ash().cmd_begin_query(
            command_buffer,
            self.query_pool,
            index,
            vk::QueryControlFlags::empty(),
        );
    }

    pub(crate) unsafe fn cmd_end_query(&mut self, command_buffer: vk::CommandBuffer, index: u32) {
        self.device
            .ash()
            .cmd_end_query(command_buffer, self.query_pool, index);
    }
}

impl Drop for VideoFeedbackQueryPool {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_query_pool(self.query_pool, None);
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
