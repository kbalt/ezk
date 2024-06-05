//! Contains everything header related

use crate::parse::{ParseCtx, Parser};
use crate::print::PrintCtx;
use anyhow::{Context, Result};
use bytesstr::BytesStr;
use headers::OneOrMore;
use name::Name;

mod error;
pub(crate) mod headers;
pub mod multiple;
pub(crate) mod name;

pub use error::HeaderError;

// ==== PARSE TRAITS ====

/// Assign a constant header name to a type.
///
/// Is used by [`Headers`]'s `(get/take)_named` API so no
/// name has to be provided by the caller.
pub trait ConstNamed {
    const NAME: Name;
}

/// Decode a header from one or more values. Used to parse headers from [`Headers`].
pub trait DecodeValues: Sized {
    /// Decode a header from a iterator of [`BytesStr`].
    ///
    /// Implementations should assume that `values` will always yield at least one value
    fn decode<'i, I>(parser: Parser, values: &mut I) -> Result<(&'i str, Self)>
    where
        I: Iterator<Item = &'i BytesStr>;
}

/// Simplified parse trait which plays nicer with nom parsers. Should be implemented
/// by any header that only cares about a single header value.
pub trait HeaderParse: Sized {
    fn parse<'i>(ctx: ParseCtx, i: &'i str) -> Result<(&'i str, Self)>;
}

// ==== PRINT TRAITS ====

/// Assign a dynamic header name to a type.
/// Used for [`Headers`]'s `insert_named(_front)` API.
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

/// Insert a header type into [`Header`].
pub trait ExtendValues {
    /// Called when there already existing values.
    ///
    /// Implementations may want to override or extend
    /// `values`, depending on the type of header.
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore);

    /// Called when there are no existing values.
    ///
    /// Must generate header value to be inserted into [`Headers`].
    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore;
}

// ==== BLANKED IMPL ===-

impl<H: HeaderParse> DecodeValues for H {
    fn decode<'i, I>(parser: Parser, values: &mut I) -> Result<(&'i str, Self)>
    where
        I: Iterator<Item = &'i BytesStr>,
    {
        let value = values.next().context("no items in values")?;

        let ctx = ParseCtx {
            src: value.as_ref(),
            parser,
        };

        H::parse(ctx, value.as_str())
    }
}

macro_rules! csv_header {
    ($(#[$meta:meta])* $struct_name:ident, $wrapping:ty, $header_name:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $struct_name(pub $wrapping);

        impl ConstNamed for $struct_name {
            const NAME: Name = $header_name;
        }

        impl HeaderParse for $struct_name {
            fn parse<'i>(ctx: ParseCtx, i: &'i str) -> Result<(&'i str, Self)> {
                if let Some(comma_idx) = i.find(',') {
                    Ok((
                        &i[comma_idx..],
                        Self(<$wrapping>::from_parse(ctx.src, &i[..comma_idx])),
                    ))
                } else {
                    Ok(("", Self(<$wrapping>::from_parse(ctx.src, i))))
                }
            }
        }

        impl ExtendValues for $struct_name {
            fn extend_values(&self, _: PrintCtx<'_>, values: &mut OneOrMore) {
                let value = match values {
                    OneOrMore::One(value) => value,
                    OneOrMore::More(values) => {
                        values.last_mut().expect("empty OneOrMore::More variant")
                    }
                };

                *value = format!("{}, {}", value, self.0).into();
            }

            fn create_values(&self, _: PrintCtx<'_>) -> OneOrMore {
                OneOrMore::One(self.0.to_string().into())
            }
        }
    };
}

macro_rules! from_str_header {
    ($(#[$meta:meta])* $struct_name:ident, $header_name:expr, $from_str_ty:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $struct_name(pub $from_str_ty);

        impl ConstNamed for $struct_name {
            const NAME: Name =  $header_name;
        }

        impl HeaderParse for $struct_name {
            fn parse<'i>(_: ParseCtx, i: &'i str) -> Result<(&'i str, Self)> {
                Ok(("", Self(i.trim().parse()?)))
            }
        }

        impl ExtendValues for $struct_name {
            fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
                *values = self.create_values(ctx)
            }

            fn create_values(&self, _: PrintCtx<'_>) -> OneOrMore {
                OneOrMore::One(self.0.to_string().into())
            }
        }

    }
}

pub mod typed;
