macro_rules! encode_set {
    ($fn:ident, $name:ident) => {
        lazy_static::lazy_static! {
            static ref $name: AsciiSet = {
                let mut set = percent_encoding::CONTROLS.add(0);

                for b in 0..=127u8 {
                    if !$fn(b as char) {
                        set = set.add(b);
                    }
                }

                set
            };
        }
    };
}
