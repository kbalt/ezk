use std::hash::{BuildHasher, Hasher};

#[derive(Default)]
pub(crate) struct SsrcHasher(u32);

impl BuildHasher for SsrcHasher {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        Self(0)
    }
}

impl Hasher for SsrcHasher {
    fn finish(&self) -> u64 {
        self.0.into()
    }

    fn write(&mut self, _bytes: &[u8]) {}

    fn write_u32(&mut self, i: u32) {
        self.0 = i;
    }
}
