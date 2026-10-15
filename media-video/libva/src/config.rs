use std::sync::Arc;

use crate::{Handle, VaError, ffi};

pub struct Config {
    pub(crate) display: Arc<Handle>,
    pub(crate) config_id: ffi::VAConfigID,
}

impl Drop for Config {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = VaError::try_(ffi::vaDestroyConfig(self.display.dpy, self.config_id)) {
                log::error!("Failed to destroy VAConfig: {e}");
            }
        }
    }
}
