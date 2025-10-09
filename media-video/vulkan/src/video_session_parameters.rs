use std::ptr::{null, null_mut};

use crate::{VideoSession, VulkanError};
use ash::vk::{self, ExtendsVideoEncodeSessionParametersGetInfoKHR, TaggedStructure};

pub struct VideoSessionParameters {
    video_session: VideoSession,
    video_session_parameters: vk::VideoSessionParametersKHR,
}

impl VideoSessionParameters {
    pub unsafe fn create(
        video_session: &VideoSession,
        create_info: &vk::VideoSessionParametersCreateInfoKHR<'_>,
    ) -> Result<Self, VulkanError> {
        let device = video_session.device();

        let fun = device
            .video_queue_device()
            .fp()
            .create_video_session_parameters_khr;

        let mut video_session_parameters = vk::VideoSessionParametersKHR::null();
        (fun)(
            device.device().handle(),
            &raw const *create_info,
            null_mut(),
            &raw mut video_session_parameters,
        )
        .result()?;

        Ok(Self {
            video_session: video_session.clone(),
            video_session_parameters,
        })
    }

    pub unsafe fn update(
        &mut self,
        update_info: &vk::VideoSessionParametersUpdateInfoKHR<'_>,
    ) -> Result<(), vk::Result> {
        let device = self.video_session().device();

        let update_video_session_parameters = device
            .video_queue_device()
            .fp()
            .update_video_session_parameters_khr;

        update_video_session_parameters(
            device.device().handle(),
            self.video_session_parameters,
            update_info,
        )
        .result()
    }

    pub unsafe fn get_encoded_video_session_parameters<T>(
        &self,
        ext: &mut T,
    ) -> Result<Vec<u8>, VulkanError>
    where
        T: TaggedStructure,
        T: ExtendsVideoEncodeSessionParametersGetInfoKHR,
    {
        let device = self.video_session.device();

        let session_parameters_info = vk::VideoEncodeSessionParametersGetInfoKHR::default()
            .video_session_parameters(self.video_session_parameters)
            .push_next(ext);

        let get_encoded_video_session_parameters = device
            .video_encode_queue_device()
            .fp()
            .get_encoded_video_session_parameters_khr;

        let mut len = 0;
        (get_encoded_video_session_parameters)(
            device.device().handle(),
            &session_parameters_info,
            null_mut(),
            &raw mut len,
            null_mut(),
        )
        .result()?;

        let mut buf = vec![0u8; len];
        (get_encoded_video_session_parameters)(
            device.device().handle(),
            &session_parameters_info,
            null_mut(),
            &raw mut len,
            buf.as_mut_ptr().cast(),
        )
        .result()?;

        Ok(buf)
    }

    pub fn video_session(&self) -> &VideoSession {
        &self.video_session
    }

    pub unsafe fn video_session_parameters(&self) -> vk::VideoSessionParametersKHR {
        self.video_session_parameters
    }
}

impl Drop for VideoSessionParameters {
    fn drop(&mut self) {
        let device = self.video_session.device();

        unsafe {
            let destroy_video_session_parameters_khr = device
                .video_queue_device()
                .fp()
                .destroy_video_session_parameters_khr;

            destroy_video_session_parameters_khr(
                device.device().handle(),
                self.video_session_parameters,
                null(),
            );
        }
    }
}
