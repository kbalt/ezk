//! Some convenience types for working with vulkan, not intended for use outside of ezk's use

#![allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
use ash::vk;

mod buffer;
mod device;
mod image;
mod image_view;
mod instance;
mod video_feedback_query_pool;
mod video_session;
mod video_session_parameters;

pub use buffer::Buffer;
pub use device::Device;
pub use image::Image;
pub use image_view::ImageView;
pub use instance::Instance;
pub use video_feedback_query_pool::VideoFeedbackQueryPool;
pub use video_session::VideoSession;
pub use video_session_parameters::VideoSessionParameters;

pub use ash;

fn find_memory_type(
    memory_type_bits: u32,
    properties: vk::MemoryPropertyFlags,
    mem_properties: &vk::PhysicalDeviceMemoryProperties,
) -> Option<u32> {
    for (i, memory_type) in mem_properties.memory_types.iter().enumerate() {
        let type_supported = (memory_type_bits & (1 << i)) != 0;
        let has_properties = memory_type.property_flags.contains(properties);
        if type_supported && has_properties {
            return Some(i as u32);
        }
    }
    None
}
