pub(crate) fn defer(f: impl FnOnce()) -> impl Drop {
    Defer { f: Some(f) }
}

struct Defer<F: FnOnce()> {
    f: Option<F>,
}

impl<F: FnOnce()> Drop for Defer<F> {
    fn drop(&mut self) {
        if let Some(f) = self.f.take() {
            f();
        }
    }
}
