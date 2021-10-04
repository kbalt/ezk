use crate::header::name::Name;
use crate::parse::text::{CsvTextSpec, Text};
use bytesstr::BytesStr;

impl_wrap_header!(
    /// `Supported` header, contains only one supported extension.
    /// To get all supported extension use [`Vec`].
    #[derive(Default)]
    Text<CsvTextSpec>,
    BytesStr,
    Supported,
    CSV,
    Name::SUPPORTED
);

impl_wrap_header!(
    /// `Require` header, contains only one required extension.
    /// To get all required extension use [`Vec`].
    #[derive(Default)]
    Text<CsvTextSpec>,
    BytesStr,
    Require,
    CSV,
    Name::REQUIRE
);

impl_wrap_header!(
    /// `Unsupported` header, contains only one unsupported extension.
    /// To get all unsupported extension use [`Vec`].
    #[derive(Default)]
    Text<CsvTextSpec>,
    BytesStr,
    Unsupported,
    CSV,
    Name::UNSUPPORTED
);
