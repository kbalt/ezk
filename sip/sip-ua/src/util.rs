use bytesstr::BytesStr;
use rand::{Rng, distr::Alphanumeric, rng};

pub fn random_string() -> BytesStr {
    rng()
        .sample_iter(Alphanumeric)
        .take(30)
        .map(char::from)
        .collect::<String>()
        .into()
}

pub fn random_sequence_number() -> u32 {
    rand::rng().random_range(0..(u32::MAX >> 1))
}
