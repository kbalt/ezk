use crate::header::name::Name;
use crate::header::{Header, Kind};
use crate::parse::Parser;
use crate::print::PrintCtx;
use anyhow::Result;
use bytesstr::BytesStr;
use std::borrow::Cow;
use std::iter::once;

impl<H> Header for Vec<H>
where
    H: Header<Kind = Kind>,
{
    type Kind = ();

    fn name() -> &'static Name {
        H::name()
    }

    fn kind() -> Self::Kind {}

    fn decode<'i, I>(parser: Parser, values: &mut I) -> Result<(Option<&'i str>, Self)>
    where
        I: Iterator<Item = &'i BytesStr>,
    {
        match H::kind() {
            Kind::CSV => {
                let mut vec = Vec::new();

                for mut value in values.map(Cow::Borrowed) {
                    while let Ok((remaining, hdr)) = H::decode(parser, &mut once(value.as_ref())) {
                        vec.push(hdr);

                        if let Some(remaining) = remaining {
                            let mut rem = remaining.trim_start_matches(char::is_whitespace);

                            if rem.starts_with(',') {
                                rem =
                                    rem.trim_start_matches(|c: char| c == ',' || c.is_whitespace());

                                value = Cow::Owned(value.slice_ref(rem));
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }

                Ok((None, vec))
            }
            Kind::Single => {
                let mut vec = vec![];

                loop {
                    match H::decode(parser, values) {
                        Ok((rem, hdr)) => {
                            vec.push(hdr);

                            if rem.is_some() {
                                return Ok((rem, vec));
                            }
                        }
                        Err(err) => {
                            if vec.is_empty() {
                                return Err(err);
                            } else {
                                return Ok((None, vec));
                            }
                        }
                    }
                }
            }
        }
    }

    fn encode<E>(&self, ctx: PrintCtx<'_>, ext: &mut E)
    where
        E: Extend<BytesStr>,
    {
        match H::kind() {
            Kind::CSV => {
                let mut value = String::new();

                for (header_index, header) in self.iter().enumerate() {
                    let mut extend_buf = vec![];

                    header.encode(ctx, &mut extend_buf);

                    let len = extend_buf.len();

                    for (val_idx, bytes) in extend_buf.into_iter().enumerate() {
                        value.push_str(&bytes);

                        if val_idx < len - 1 || header_index < self.len() - 1 {
                            value.push_str(", ")
                        }
                    }
                }

                if !value.is_empty() {
                    ext.extend(once(BytesStr::from(value)));
                }
            }
            Kind::Single => {
                for h in self {
                    h.encode(ctx, ext)
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    decl_from_str_header!(
        SingleHeader,
        u32,
        Single,
        Name::custom("Single-Header", &["single-header"])
    );

    decl_from_str_header!(
        CsvHeader,
        u32,
        CSV,
        Name::custom("Csv-Header", &["csv-header"])
    );

    static STRINGS: [BytesStr; 3] = [
        BytesStr::from_static("1, 2, 3"),
        BytesStr::from_static("4, 5"),
        BytesStr::from_static("6"),
    ];

    static STRINGS_SPACED: [BytesStr; 3] = [
        BytesStr::from_static("1  , 2   , 3"),
        BytesStr::from_static("4  , 5"),
        BytesStr::from_static("6"),
    ];

    static STRINGS_SPACED_EMPTY: [BytesStr; 6] = [
        BytesStr::from_static(""),
        BytesStr::from_static("1  , 2   , 3"),
        BytesStr::from_static(""),
        BytesStr::from_static("4  , 5"),
        BytesStr::from_static(""),
        BytesStr::from_static("6"),
    ];

    #[test]
    fn csv_multiple_parse() {
        let (rem, multiple) =
            Vec::<CsvHeader>::decode(Default::default(), &mut STRINGS.iter()).unwrap();

        assert!(rem.is_none());

        assert_eq!(multiple[0].0, 1);
        assert_eq!(multiple[1].0, 2);
        assert_eq!(multiple[2].0, 3);
        assert_eq!(multiple[3].0, 4);
        assert_eq!(multiple[4].0, 5);
        assert_eq!(multiple[5].0, 6);
    }

    #[test]
    fn csv_multiple_parse_trim() {
        let (rem, multiple) =
            Vec::<CsvHeader>::decode(Default::default(), &mut STRINGS_SPACED.iter()).unwrap();

        assert!(rem.is_none());

        assert_eq!(multiple[0].0, 1);
        assert_eq!(multiple[1].0, 2);
        assert_eq!(multiple[2].0, 3);
        assert_eq!(multiple[3].0, 4);
        assert_eq!(multiple[4].0, 5);
        assert_eq!(multiple[5].0, 6);
    }

    #[test]
    fn csv_multiple_parse_empty() {
        let (rem, multiple) =
            Vec::<CsvHeader>::decode(Default::default(), &mut STRINGS_SPACED_EMPTY.iter()).unwrap();

        assert!(rem.is_none());

        assert_eq!(multiple[0].0, 1);
        assert_eq!(multiple[1].0, 2);
        assert_eq!(multiple[2].0, 3);
        assert_eq!(multiple[3].0, 4);
        assert_eq!(multiple[4].0, 5);
        assert_eq!(multiple[5].0, 6);
    }

    #[test]
    fn csv_multiple_parse_empty_iter() {
        let strings = [];

        let (rem, multiple) =
            Vec::<CsvHeader>::decode(Default::default(), &mut strings.iter()).unwrap();

        assert!(rem.is_none());
        assert!(multiple.is_empty());
    }
}
