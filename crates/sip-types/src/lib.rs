#![forbid(unsafe_code)]

macro_rules! lookup_table {
    ($c:expr => $($set:ident;)* $($lit:literal),*) => {{
        const fn init_table() -> [bool; 128] {
            let mut v = [false; 128];

            $(
            lookup_table!(@inner v, $set);
            )*

            $(
            v[$lit as usize] = true;
            )*

            v
        }

        static LOOKUP_TABLE: [bool; 128] = init_table();

        $c.is_ascii() && {
            let c = $c as usize;

            LOOKUP_TABLE[c]
        }
    }};
    (@inner $v:ident, alpha) => {{
        $v[b'A' as usize] = true;
        $v[b'B' as usize] = true;
        $v[b'C' as usize] = true;
        $v[b'D' as usize] = true;
        $v[b'E' as usize] = true;
        $v[b'F' as usize] = true;
        $v[b'G' as usize] = true;
        $v[b'H' as usize] = true;
        $v[b'I' as usize] = true;
        $v[b'J' as usize] = true;
        $v[b'K' as usize] = true;
        $v[b'L' as usize] = true;
        $v[b'M' as usize] = true;
        $v[b'N' as usize] = true;
        $v[b'O' as usize] = true;
        $v[b'P' as usize] = true;
        $v[b'Q' as usize] = true;
        $v[b'R' as usize] = true;
        $v[b'S' as usize] = true;
        $v[b'T' as usize] = true;
        $v[b'U' as usize] = true;
        $v[b'V' as usize] = true;
        $v[b'W' as usize] = true;
        $v[b'X' as usize] = true;
        $v[b'Y' as usize] = true;
        $v[b'Z' as usize] = true;
        $v[b'a' as usize] = true;
        $v[b'b' as usize] = true;
        $v[b'c' as usize] = true;
        $v[b'd' as usize] = true;
        $v[b'e' as usize] = true;
        $v[b'f' as usize] = true;
        $v[b'g' as usize] = true;
        $v[b'h' as usize] = true;
        $v[b'i' as usize] = true;
        $v[b'j' as usize] = true;
        $v[b'k' as usize] = true;
        $v[b'l' as usize] = true;
        $v[b'm' as usize] = true;
        $v[b'n' as usize] = true;
        $v[b'o' as usize] = true;
        $v[b'p' as usize] = true;
        $v[b'q' as usize] = true;
        $v[b'r' as usize] = true;
        $v[b's' as usize] = true;
        $v[b't' as usize] = true;
        $v[b'u' as usize] = true;
        $v[b'v' as usize] = true;
        $v[b'w' as usize] = true;
        $v[b'x' as usize] = true;
        $v[b'y' as usize] = true;
        $v[b'z' as usize] = true;
    }};
    (@inner $v:ident, num) => {{
        $v[b'0' as usize] = true;
        $v[b'1' as usize] = true;
        $v[b'2' as usize] = true;
        $v[b'3' as usize] = true;
        $v[b'4' as usize] = true;
        $v[b'5' as usize] = true;
        $v[b'6' as usize] = true;
        $v[b'7' as usize] = true;
        $v[b'8' as usize] = true;
        $v[b'9' as usize] = true;
    }};
}

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

#[macro_use]
pub mod print;
#[macro_use]
pub mod uri;
mod code;
pub mod header;
pub mod host;
mod method;
pub mod msg;
pub mod parse;

pub use code::Code;
pub use code::CodeKind;

pub use method::Method;

pub use header::headers::Headers;
pub use header::name::Name;

// #[cfg(test)]
// mod tests;
