use ash::khr::{video_encode_queue, video_queue};

use super::Instance;
use std::sync::Arc;

#[derive(Clone)]
pub struct Device {
    inner: Arc<Inner>,
}

struct Inner {
    instance: Instance,
    device: ash::Device,
    video_queue_device: video_queue::Device,
    video_encode_queue_device: video_encode_queue::Device,
}

impl Device {
    pub fn new(instance: Instance, device: ash::Device) -> Self {
        let video_queue_device = ash::khr::video_queue::Device::new(instance.instance(), &device);
        let video_encode_queue_device =
            video_encode_queue::Device::new(instance.instance(), &device);

        Self {
            inner: Arc::new(Inner {
                instance,
                device,
                video_queue_device,
                video_encode_queue_device,
            }),
        }
    }

    pub fn instance(&self) -> &Instance {
        &self.inner.instance
    }

    pub fn device(&self) -> &ash::Device {
        &self.inner.device
    }

    pub fn video_queue_device(&self) -> &video_queue::Device {
        &self.inner.video_queue_device
    }

    pub fn video_encode_queue_device(&self) -> &video_encode_queue::Device {
        &self.inner.video_encode_queue_device
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device.destroy_device(None);
        }
    }
}
