//! Some convenience types for working with vulkan, not intended for use outside of ezk's use

#![allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]

mod buffer;
mod command_buffer;
mod device;
mod dpb;
mod error;
mod fence;
mod image;
mod image_view;
mod instance;
mod semaphore;
mod video_feedback_query_pool;
mod video_session;
mod video_session_parameters;

pub use buffer::Buffer;
pub use command_buffer::CommandBuffer;
pub use device::Device;
pub use dpb::create_dpb;
pub use error::VulkanError;
pub use fence::Fence;
pub use image::Image;
pub use image_view::ImageView;
pub use instance::Instance;
pub use semaphore::Semaphore;
pub use video_feedback_query_pool::VideoFeedbackQueryPool;
pub use video_session::VideoSession;
pub use video_session_parameters::VideoSessionParameters;

pub use ash;

use std::ffi::CStr;

pub const REQUIRED_EXTENSIONS_BASE: &[&CStr] = &[c"VK_KHR_video_queue"];
pub const REQUIRED_EXTENSIONS_ENCODE: &[&CStr] = &[c"VK_KHR_video_encode_queue"];
pub const REQUIRED_EXTENSIONS_DECODE: &[&CStr] = &[c"VK_KHR_video_decode_queue"];
