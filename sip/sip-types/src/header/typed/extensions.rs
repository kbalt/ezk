use crate::header::name::Name;
use bytesstr::BytesStr;

csv_header! {
    /// `Supported` header, contains only one supported extension.
    /// To get all supported extension use [`Vec`].
    Supported,
    BytesStr,
    Name::SUPPORTED
}

csv_header! {
    /// `Require` header, contains only one required extension.
    /// To get all required extension use [`Vec`].
    Require,
    BytesStr,
    Name::REQUIRE
}

csv_header! {
    /// `Unsupported` header, contains only one unsupported extension.
    /// To get all unsupported extension use [`Vec`].
    Unsupported,
    BytesStr,
    Name::UNSUPPORTED
}
