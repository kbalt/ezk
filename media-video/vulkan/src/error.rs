use std::{backtrace::Backtrace, error::Error, fmt};

use ash::vk;

#[derive(Debug)]
pub enum VulkanError {
    Native {
        backtrace: Backtrace,
        result: vk::Result,
    },

    CannotFindMemoryType {
        memory_type_bits: u32,
        properties: vk::MemoryPropertyFlags,
    },

    InvalidArgument {
        message: &'static str,
    },
}

impl From<vk::Result> for VulkanError {
    #[track_caller]
    fn from(result: vk::Result) -> Self {
        VulkanError::Native {
            backtrace: Backtrace::capture(),
            result,
        }
    }
}

impl fmt::Display for VulkanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulkanError::Native { backtrace, result } => {
                write!(
                    f,
                    "Vulkan call failed with result={result}, backtrace={backtrace}"
                )
            }
            VulkanError::CannotFindMemoryType {
                memory_type_bits,
                properties,
            } => write!(
                f,
                "Failed to find memory type that can be used with the constraints memory_type_bits={memory_type_bits:b}, properties={properties:?}"
            ),
            VulkanError::InvalidArgument { message } => {
                write!(f, "Invalid argument, {message}")
            }
        }
    }
}

impl Error for VulkanError {}
