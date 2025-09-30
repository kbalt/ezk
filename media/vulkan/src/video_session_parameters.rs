use std::mem::{MaybeUninit, transmute};

use crate::VideoSession;
use ash::vk::{self, Extends, TaggedStructure};

pub struct VideoSessionParameters {
    video_session: VideoSession,
    video_session_parameters: vk::VideoSessionParametersKHR,
}

impl VideoSessionParameters {
    pub unsafe fn create(
        video_session: &VideoSession,
        create_info: &vk::VideoSessionParametersCreateInfoKHR<'_>,
    ) -> Self {
        let device = video_session.device();

        let video_session_parameters = device
            .video_queue_device()
            .create_video_session_parameters(create_info, None)
            .unwrap();

        Self {
            video_session: video_session.clone(),
            video_session_parameters,
        }
    }

    pub unsafe fn get_encoded_video_session_parameters<'a, T>(&self, ext: &'a mut T) -> Vec<u8>
    where
        T: TaggedStructure<'a>,
        T: Extends<vk::VideoEncodeSessionParametersGetInfoKHR<'a>>,
    {
        let device = self.video_session.device();

        let session_parameters_info = vk::VideoEncodeSessionParametersGetInfoKHR::default()
            .video_session_parameters(self.video_session_parameters)
            .push(ext);

        let len = device
            .video_encode_queue_device()
            .get_encoded_video_session_parameters_len(&session_parameters_info, None)
            .unwrap();

        let mut buf = vec![MaybeUninit::uninit(); len];
        device
            .video_encode_queue_device()
            .get_encoded_video_session_parameters(&session_parameters_info, None, &mut buf)
            .unwrap();

        transmute::<Vec<MaybeUninit<u8>>, Vec<u8>>(buf)
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
            device
                .video_queue_device()
                .destroy_video_session_parameters(self.video_session_parameters, None);
        }
    }
}
