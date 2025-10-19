//! Some convenience types for working with vulkan, not intended for use outside of ezk's own use

#![allow(
    unsafe_op_in_unsafe_fn,
    clippy::missing_safety_doc,
    clippy::upper_case_acronyms
)]
#![warn(missing_debug_implementations)]

pub mod encoder;

mod buffer;
mod command_buffer;
mod descriptor_set;
mod device;
mod dpb;
mod error;
mod fence;
mod image;
mod image_view;
mod instance;
mod physical_device;
mod pipeline;
mod sampler;
mod semaphore;
mod shader_module;
mod video_feedback_query_pool;
mod video_session;
mod video_session_parameters;

pub use device::Device;
pub use error::VulkanError;
pub use image::Image;
pub use image_view::ImageView;
pub use instance::Instance;
pub use physical_device::PhysicalDevice;
pub use semaphore::Semaphore;

// reexport ash for convenience
pub use ash;

pub(crate) use buffer::Buffer;
pub(crate) use command_buffer::{CommandBuffer, RecordingCommandBuffer};
pub(crate) use descriptor_set::{DescriptorSet, DescriptorSetLayout};
pub(crate) use dpb::create_dpb;
pub(crate) use fence::Fence;
pub(crate) use pipeline::{Pipeline, PipelineLayout};
pub(crate) use sampler::Sampler;
pub(crate) use shader_module::ShaderModule;
pub(crate) use video_feedback_query_pool::VideoFeedbackQueryPool;
pub(crate) use video_session::VideoSession;
pub(crate) use video_session_parameters::VideoSessionParameters;
