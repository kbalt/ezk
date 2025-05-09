//! Contains everything header related

use crate::print::PrintCtx;
use bytes::Bytes;
use bytesstr::BytesStr;
use headers::OneOrMore;
use internal::IResult;
use name::Name;
use nom::error::{VerboseError, VerboseErrorKind};

mod error;
pub mod headers;
pub mod multiple;
pub(crate) mod name;

pub use error::HeaderError;

// ==== PARSE TRAITS ====

/// Assign a constant header name to a type.
///
/// Is used by [`Headers`](headers::Headers)'s `(get/take)_named` API so no
/// name has to be provided by the caller.
pub trait ConstNamed {
    const NAME: Name;
}

/// Decode a header from one or more values. Used to parse headers from [`Headers`](headers::Headers).
pub trait DecodeValues: Sized {
    /// Decode a header from a iterator of [`BytesStr`].
    ///
    /// Implementations should assume that `values` will always yield at least one value
    fn decode<'i, I>(values: &mut I) -> IResult<&'i str, Self>
    where
        I: Iterator<Item = &'i BytesStr>;
}

/// Simplified parse trait which plays nicer with nom parsers. Should be implemented
/// by any header that only cares about a single header value.
pub trait HeaderParse: Sized {
    fn parse<'i>(src: &'i Bytes, i: &'i str) -> IResult<&'i str, Self>;
}

// ==== PRINT TRAITS ====

/// Assign a dynamic header name to a type.
/// Used for [`Headers`](headers::Headers)'s `insert_named(_front)` API.
///
/// Can be used for enum holding different header variants.
pub trait DynNamed {
    fn name(&self) -> Name;
}

impl<T: ConstNamed> DynNamed for T {
    fn name(&self) -> Name {
        T::NAME
    }
}

/// Insert a header type into [`Header`](headers::Headers).
pub trait ExtendValues {
    /// Called when there already existing values.
    ///
    /// Implementations may want to override or extend
    /// `values`, depending on the type of header.
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore);

    /// Called when there are no existing values.
    ///
    /// Must generate header value to be inserted into [`Headers`](headers::Headers).
    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore;
}

// ==== BLANKED IMPL ===-

impl<H: HeaderParse> DecodeValues for H {
    fn decode<'i, I>(values: &mut I) -> IResult<&'i str, Self>
    where
        I: Iterator<Item = &'i BytesStr>,
    {
        let Some(value) = values.next() else {
            return Err(nom::Err::Failure(VerboseError {
                errors: vec![(
                    "",
                    VerboseErrorKind::Context("No input to DecodeValues provided"),
                )],
            }));
        };

        H::parse(value.as_ref(), value.as_str())
    }
}

#[macro_export]
macro_rules! csv_header {
    ($(#[$meta:meta])* $struct_name:ident, $wrapping:ty, $header_name:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $struct_name(pub $wrapping);

        impl $crate::header::ConstNamed for $struct_name {
            const NAME: Name = $header_name;
        }

        impl $crate::header::HeaderParse for $struct_name {
            fn parse<'i>(src: &$crate::_private_reexport::Bytes, i: &'i str) -> $crate::_private_reexport::IResult<&'i str, Self> {
                if let Some(comma_idx) = i.find(',') {
                    Ok((
                        &i[comma_idx..],
                        Self(<$wrapping>::from_parse(src, &i[..comma_idx])),
                    ))
                } else {
                    Ok(("", Self(<$wrapping>::from_parse(src, i))))
                }
            }
        }

        impl $crate::header::ExtendValues for $struct_name {
            fn extend_values(&self, _: $crate::print::PrintCtx<'_>, values: &mut $crate::header::headers::OneOrMore) {
                let value = match values {
                    $crate::header::headers::OneOrMore::One(value) => value,
                    $crate::header::headers::OneOrMore::More(values) => {
                        values.last_mut().expect("empty OneOrMore::More variant")
                    }
                };

                *value = format!("{}, {}", value, self.0).into();
            }

            fn create_values(&self, _: $crate::print::PrintCtx<'_>) -> $crate::header::headers::OneOrMore {
                $crate::header::headers::OneOrMore::One(self.0.to_string().into())
            }
        }
    };
}

#[macro_export]
macro_rules! from_str_header {
    ($(#[$meta:meta])* $struct_name:ident, $header_name:expr, $from_str_ty:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $struct_name(pub $from_str_ty);

        impl $crate::header::ConstNamed for $struct_name {
            const NAME: Name =  $header_name;
        }

        impl $crate::header::HeaderParse for $struct_name {
            fn parse<'i>(_: &$crate::_private_reexport::Bytes, i: &'i str) -> $crate::_private_reexport::IResult<&'i str, Self> {
                use $crate::_private_reexport::nom;
                use $crate::_private_reexport::identity;
                use nom::combinator::map_res;

                let (i, o) = map_res(identity(), |x| x.parse())(i.trim())?;

                Ok((i, Self(o)))
            }
        }

        impl $crate::header::ExtendValues for $struct_name {
            fn extend_values(&self, ctx: $crate::print::PrintCtx<'_>, values: &mut $crate::header::headers::OneOrMore) {
                *values = self.create_values(ctx)
            }

            fn create_values(&self, _: $crate::print::PrintCtx<'_>) -> $crate::header::headers::OneOrMore {
                $crate::header::headers::OneOrMore::One(self.0.to_string().into())
            }
        }

    }
}

pub mod typed;
