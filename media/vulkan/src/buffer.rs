use std::ffi::c_void;

use ash::vk;

use crate::Device;

pub struct Buffer {
    device: Device,
    buffer: vk::Buffer,
    memory: vk::DeviceMemory,
}

impl Buffer {
    pub unsafe fn create(
        device: &Device,
        physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
        create_info: &vk::BufferCreateInfo<'_>,
    ) -> Self {
        let buffer = device.device().create_buffer(create_info, None).unwrap();

        let memory_requirements = device.device().get_buffer_memory_requirements(buffer);

        let output_alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(
                crate::find_memory_type(
                    memory_requirements.memory_type_bits,
                    vk::MemoryPropertyFlags::HOST_VISIBLE,
                    physical_device_memory_properties,
                )
                .unwrap(),
            );

        let memory = device
            .device()
            .allocate_memory(&output_alloc_info, None)
            .unwrap();

        device
            .device()
            .bind_buffer_memory(buffer, memory, 0)
            .unwrap();

        Self {
            device: device.clone(),
            buffer,
            memory,
        }
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    pub fn buffer(&self) -> vk::Buffer {
        self.buffer
    }

    pub unsafe fn map(&mut self, size: vk::DeviceSize) -> MappedBuffer<'_> {
        let ptr = self
            .device
            .device()
            .map_memory(self.memory, 0, size, vk::MemoryMapFlags::empty())
            .unwrap();

        MappedBuffer { buffer: self, ptr }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            self.device.device().destroy_buffer(self.buffer, None);
            self.device.device().free_memory(self.memory, None);
        }
    }
}

pub struct MappedBuffer<'a> {
    buffer: &'a mut Buffer,
    ptr: *mut c_void,
}

impl MappedBuffer<'_> {
    pub fn ptr(&self) -> *mut c_void {
        self.ptr
    }
}

impl Drop for MappedBuffer<'_> {
    fn drop(&mut self) {
        unsafe {
            self.buffer.device.device().unmap_memory(self.buffer.memory);
        }
    }
}
