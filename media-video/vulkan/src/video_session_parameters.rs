use std::ptr::{null, null_mut};

use crate::{VideoSession, VulkanError};
use ash::vk::{self, ExtendsVideoSessionParametersUpdateInfoKHR};

#[derive(Debug)]
pub(crate) struct VideoSessionParameters {
    video_session: VideoSession,
    update_count: u32,
    video_session_parameters: vk::VideoSessionParametersKHR,
}

impl VideoSessionParameters {
    pub(crate) fn create<P>(
        video_session: &VideoSession,
        parameters: &mut P,
    ) -> Result<Self, VulkanError>
    where
        P: vk::ExtendsVideoSessionParametersCreateInfoKHR,
    {
        let device = video_session.device();

        let create_info = vk::VideoSessionParametersCreateInfoKHR::default()
            .video_session(unsafe { video_session.video_session() })
            .push_next(parameters);

        let mut video_session_parameters = vk::VideoSessionParametersKHR::null();

        let create_video_session_parameters = device
            .ash_video_queue_device()
            .fp()
            .create_video_session_parameters_khr;

        unsafe {
            (create_video_session_parameters)(
                device.ash().handle(),
                &raw const create_info,
                null_mut(),
                &raw mut video_session_parameters,
            )
            .result()?;
        }

        Ok(Self {
            video_session: video_session.clone(),
            update_count: 0,
            video_session_parameters,
        })
    }

    pub(crate) fn update<P>(&mut self, parameters: &mut P) -> Result<(), vk::Result>
    where
        P: ExtendsVideoSessionParametersUpdateInfoKHR,
    {
        self.update_count += 1;

        let device = self.video_session().device();

        let update_info = vk::VideoSessionParametersUpdateInfoKHR::default()
            .update_sequence_count(self.update_count)
            .push_next(parameters);

        let update_video_session_parameters = device
            .ash_video_queue_device()
            .fp()
            .update_video_session_parameters_khr;

        unsafe {
            update_video_session_parameters(
                device.ash().handle(),
                self.video_session_parameters,
                &raw const update_info,
            )
            .result()
        }
    }

    pub(crate) unsafe fn get_encoded_video_session_parameters<T>(
        &self,
        ext: &mut T,
    ) -> Result<Vec<u8>, VulkanError>
    where
        T: vk::TaggedStructure,
        T: vk::ExtendsVideoEncodeSessionParametersGetInfoKHR,
    {
        let device = self.video_session.device();

        let session_parameters_info = vk::VideoEncodeSessionParametersGetInfoKHR::default()
            .video_session_parameters(self.video_session_parameters)
            .push_next(ext);

        let get_encoded_video_session_parameters = device
            .ash_video_encode_queue_device()
            .fp()
            .get_encoded_video_session_parameters_khr;

        let mut len = 0;
        (get_encoded_video_session_parameters)(
            device.ash().handle(),
            &session_parameters_info,
            null_mut(),
            &raw mut len,
            null_mut(),
        )
        .result()?;

        let mut buf = vec![0u8; len];
        (get_encoded_video_session_parameters)(
            device.ash().handle(),
            &session_parameters_info,
            null_mut(),
            &raw mut len,
            buf.as_mut_ptr().cast(),
        )
        .result()?;

        Ok(buf)
    }

    pub(crate) fn video_session(&self) -> &VideoSession {
        &self.video_session
    }

    pub(crate) unsafe fn video_session_parameters(&self) -> vk::VideoSessionParametersKHR {
        self.video_session_parameters
    }
}

impl Drop for VideoSessionParameters {
    fn drop(&mut self) {
        let device = self.video_session.device();

        unsafe {
            let destroy_video_session_parameters_khr = device
                .ash_video_queue_device()
                .fp()
                .destroy_video_session_parameters_khr;

            destroy_video_session_parameters_khr(
                device.ash().handle(),
                self.video_session_parameters,
                null(),
            );
        }
    }
}
