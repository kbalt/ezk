use std::{
    marker::PhantomData,
    slice::{from_raw_parts, from_raw_parts_mut},
};

use ash::vk;

use crate::{Device, VulkanError};

#[derive(Debug)]
pub(crate) struct Buffer<T = u8> {
    device: Device,
    buffer: vk::Buffer,
    memory: vk::DeviceMemory,
    capacity: usize,
    _m: PhantomData<T>,
}

impl<T> Buffer<T> {
    pub(crate) unsafe fn create(
        device: &Device,
        create_info: &vk::BufferCreateInfo<'_>,
    ) -> Result<Self, VulkanError> {
        if !create_info
            .size
            .is_multiple_of(size_of::<T>() as vk::DeviceSize)
        {
            return Err(VulkanError::InvalidArgument {
                message: "Buffer size is not a multiple of T",
            });
        }

        let capacity = create_info.size as usize / size_of::<T>();

        let buffer = device.ash().create_buffer(create_info, None)?;

        let memory_requirements = device.ash().get_buffer_memory_requirements(buffer);

        let output_alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(device.find_memory_type(
                memory_requirements.memory_type_bits,
                vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT,
            )?);

        let memory = device.ash().allocate_memory(&output_alloc_info, None)?;

        device.ash().bind_buffer_memory(buffer, memory, 0)?;

        Ok(Self {
            device: device.clone(),
            buffer,
            memory,
            capacity,
            _m: PhantomData,
        })
    }

    pub(crate) unsafe fn buffer(&self) -> vk::Buffer {
        self.buffer
    }

    #[allow(clippy::len_without_is_empty)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn map(&mut self, len: usize) -> Result<MappedBuffer<'_, T>, VulkanError> {
        if len == 0 {
            return Err(VulkanError::InvalidArgument {
                message: "Cannot map buffer with size 0",
            });
        }

        if len > self.capacity {
            return Err(VulkanError::InvalidArgument {
                message: "Tried to map buffer with size larger than buffer size",
            });
        }

        let ptr = unsafe {
            self.device.ash().map_memory(
                self.memory,
                0,
                (size_of::<T>() * len) as vk::DeviceSize,
                vk::MemoryMapFlags::empty(),
            )?
        };

        Ok(MappedBuffer {
            buffer: self,
            ptr: ptr.cast::<T>(),
            len,
        })
    }
}

impl<T> Drop for Buffer<T> {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_buffer(self.buffer, None);
            self.device.ash().free_memory(self.memory, None);
        }
    }
}

#[derive(Debug)]
pub(crate) struct MappedBuffer<'a, T> {
    buffer: &'a mut Buffer<T>,
    ptr: *mut T,
    len: usize,
}

impl<'a, T> MappedBuffer<'a, T> {
    pub(crate) fn data(&self) -> &'a [T] {
        unsafe { from_raw_parts(self.ptr.cast(), self.len) }
    }

    pub(crate) fn data_mut(&mut self) -> &'a mut [T] {
        unsafe { from_raw_parts_mut(self.ptr.cast(), self.len) }
    }
}

impl<T> Drop for MappedBuffer<'_, T> {
    fn drop(&mut self) {
        unsafe {
            self.buffer.device.ash().unmap_memory(self.buffer.memory);
        }
    }
}
