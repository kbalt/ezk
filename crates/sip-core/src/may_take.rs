use std::ops::{Deref, DerefMut};

/// Wrapper over `&mut Option<T>` for a nice typed API
pub struct MayTake<'a, T> {
    to_take: &'a mut Option<T>,
}

impl<'a, T> MayTake<'a, T> {
    pub fn new(to_take: &'a mut Option<T>) -> Self {
        debug_assert!(to_take.is_some());

        Self { to_take }
    }

    /// Assume ownership of the object
    pub fn take(self) -> T {
        unwrap(self.to_take.take())
    }

    pub fn inner(&mut self) -> &mut Option<T> {
        self.to_take
    }
}

impl<T> Deref for MayTake<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unwrap(self.to_take.as_ref())
    }
}

impl<T> DerefMut for MayTake<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unwrap(self.to_take.as_mut())
    }
}

fn unwrap<T>(opt: Option<T>) -> T {
    opt.expect("to_take must be some")
}
