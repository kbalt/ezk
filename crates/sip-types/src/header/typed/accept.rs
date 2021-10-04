use crate::header::name::Name;
use crate::parse::text::{CsvTextSpec, Text};
use bytesstr::BytesStr;

impl_wrap_header!(
    /// `Accept` header, contains only one supported format.
    /// To get all supported extension use [`Vec`].
    Text<CsvTextSpec>,
    BytesStr,
    Accept,
    CSV,
    Name::ACCEPT
);
