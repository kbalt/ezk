//! Contains everything header related

use crate::parse::Parser;
use crate::print::PrintCtx;
use anyhow::Result;
use bytesstr::BytesStr;
use name::Name;

mod error;
pub(crate) mod headers;
pub(crate) mod name;

pub use error::HeaderError;

/// Describes how multiple header values have to be treated.
///
/// There is (at least) two types of SIP headers.
///
/// The ones that may have multiple values in one or more header-values and are comma separated. (CSV)
///
/// And the ones that may not be comma separated and may be spread over multiple header-values. (Single)
///
/// This information is only used by the [Header] implementation of [Vec] in this crate.
#[derive(Copy, Clone)]
pub enum Kind {
    CSV,
    Single,
}

/// Trait for typed headers.
/// It is used to en/decode headers into and from [BytesStr] stored inside [Headers].
///
/// [Headers]: headers::Headers
pub trait Header: std::fmt::Debug {
    type Kind;

    /// Returns the [Name] of the Header.
    fn name() -> &'static Name;

    /// Returns the [Kind] of the header see its documentation for more information.
    fn kind() -> Self::Kind;

    /// Decode the header from one or more Values inside the iterator.
    /// Bytes taken from the iterator but not used when parsing should be returned.
    fn decode<'i, I>(parser: Parser, values: &mut I) -> Result<(Option<&'i str>, Self)>
    where
        I: Iterator<Item = &'i BytesStr>,
        Self: Sized;

    /// Encode the Header into a collection containing values.
    fn encode<E>(&self, ctx: PrintCtx<'_>, ext: &mut E)
    where
        E: Extend<BytesStr>;
}

#[doc(hidden)]
#[macro_export]
macro_rules! __impl_header {
    ($ty:ty, $kind:ident, $name:expr) => {
        impl $crate::header::Header for $ty {
            type Kind = $crate::header::Kind;

            #[inline]
            fn name() -> &'static Name {
                static MY_NAME: $crate::Name = $name;
                &MY_NAME
            }

            fn decode<'i, I: Iterator<Item = &'i bytesstr::BytesStr>>(
                parser: $crate::parse::Parser,
                values: &mut I,
            ) -> anyhow::Result<(Option<&'i str>, Self)>
            where
                Self: Sized,
            {
                use anyhow::Context as _;
                let val = values.next().context("no items to decode in iterator")?;

                let ctx = $crate::parse::ParseCtx::new(val.as_ref(), parser);

                let parse_fn = <$ty>::parse(ctx);

                let (rem, hdr) =
                    parse_fn(val.as_ref()).map_err(|_| anyhow::anyhow!("invalid input"))?;

                if rem.is_empty() {
                    Ok((None, hdr))
                } else {
                    Ok((Some(rem), hdr))
                }
            }

            fn encode<E: Extend<bytesstr::BytesStr>>(
                &self,
                ctx: $crate::print::PrintCtx<'_>,
                ext: &mut E,
            ) {
                ext.extend(::std::iter::once(
                    $crate::print::AppendCtx::print_ctx(self, ctx)
                        .to_string()
                        .into(),
                ))
            }

            fn kind() -> $crate::header::Kind {
                $crate::header::Kind::$kind
            }
        }
    };
}

macro_rules! impl_wrap_header {
    ($(#[$meta:meta])* $to_wrap:ty, $wrapper:ident, $kind:ident, $name:expr) => {
        impl_wrap_header!($(#[$meta])* $to_wrap, $to_wrap, $wrapper, $kind, $name);
    };
    ($(#[$meta:meta])* $to_parse:ty, $to_wrap:ty, $wrapper:ident, $kind:ident, $name:expr) => {
        #[derive(Debug, Clone)]
        $(#[$meta])*
        pub struct $wrapper(pub $to_wrap);

        impl $crate::print::Print for $wrapper {
            fn print(
                &self,
                f: &mut ::std::fmt::Formatter<'_>,
                ctx: $crate::print::PrintCtx<'_>,
            ) -> ::std::fmt::Result {
                $crate::print::Print::print(&self.0, f, ctx)
            }
        }

        impl $wrapper {
            pub(crate) fn parse<'p>(ctx: $crate::parse::ParseCtx<'p>) -> impl Fn(&'p str) -> nom::IResult<&'p str, Self> + 'p {
                move |i| nom::combinator::map(<$to_parse>::parse(ctx), $wrapper)(i)
            }
        }

        impl<T: Into<$to_wrap>> std::convert::From<T> for $wrapper {
            fn from(t: T) -> $wrapper {
                $wrapper(t.into())
            }
        }

        impl std::ops::Deref for $wrapper {
            type Target = $to_wrap;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::ops::DerefMut for $wrapper {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        $crate::__impl_header!($wrapper, $kind, $name);
    };
}

/// Declare a header type that just wraps a single type which implements [FromStr].
///
/// [FromStr]: std::str::FromStr
///
/// # Example
///
/// ```
/// use ezk_sip_types::{decl_from_str_header, Headers, Name};
/// use bytesstr::BytesStr;
///
/// decl_from_str_header!(
///     #[derive(PartialEq)]    // optional meta like derives or doc comments
///     Custom,                 // type name
///     u32,                    // the type to be wrapped
///     Single,                 // the kind of header either `Single` or `CSV`
///     Name::custom("Custom", &["custom"])   // and the name
/// );
///
/// let custom = Custom(120);
///
/// let mut headers = Headers::new();
///
/// headers.insert_type(&custom);
///
/// assert_eq!(headers.get::<Custom>().unwrap(), Custom(120));
///
/// ```
#[macro_export]
macro_rules! decl_from_str_header {
    ($(#[$meta:meta])* $name:ident, $from_str:ty, $kind:ident, $hdr_name:expr) => {
        #[derive(Debug, Clone)]
        $(#[$meta])*
        pub struct $name(pub $from_str);

        impl $crate::print::Print for $name {
            fn print(
                &self,
                f: &mut ::std::fmt::Formatter<'_>,
                _: $crate::print::PrintCtx<'_>,
            ) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl $name {
            pub(crate) fn parse(_: $crate::parse::ParseCtx<'_>) -> impl Fn(&str) -> nom::IResult<&str, Self> {
                decl_from_str_header!(@impl_ $name, $kind)
            }
        }

        $crate::__impl_header!($name, $kind, $hdr_name);
    };
    (@impl_ $name:ident, CSV) => {
        move |i| {
            nom::combinator::map(
                nom::combinator::map_res(
                    nom::bytes::complete::take_while(|c: char| c != ','),
                    |i| std::str::FromStr::from_str(str::trim(i)).map(|item| ("", item))
                ),
                |(_, item)| $name(item)
            )(i)
        }
    };
    (@impl_ $name:ident, Single) => {
        move |i| {
            nom::combinator::map(
                nom::combinator::map_res(
                    |i| Ok(("", str::trim(i))),
                    std::str::FromStr::from_str,
                ),
                $name,
            )(i)
        }
    }
}

pub mod multiple;
pub mod typed;
