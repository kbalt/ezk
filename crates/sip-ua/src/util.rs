use bytesstr::BytesStr;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn random_string() -> BytesStr {
    thread_rng()
        .sample_iter(Alphanumeric)
        .take(30)
        .map(char::from)
        .collect::<String>()
        .into()
}

pub fn random_sequence_number() -> u32 {
    rand::thread_rng().gen_range(0..(u32::MAX >> 1))
}
