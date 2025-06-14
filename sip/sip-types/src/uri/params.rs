use crate::parse::parse_quoted;
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use internal::ws;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while};
use nom::combinator::{map, map_res, opt};
use nom::multi::many0;
use percent_encoding::{AsciiSet, percent_decode, percent_encode};
use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;
use std::str::Utf8Error;

/// A list of parameters
pub struct Params<S> {
    params: Vec<Param>,
    marker: PhantomData<S>,
}

impl<S> Clone for Params<S> {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
            marker: self.marker,
        }
    }
}

impl<S: ParamsSpec> Params<S> {
    pub fn new() -> Params<S> {
        Params {
            params: Vec::new(),
            marker: PhantomData,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    #[inline]
    pub fn with(mut self, param: Param) -> Self {
        self.push(param);
        self
    }

    #[inline]
    pub fn push(&mut self, param: Param) {
        self.params.push(param);
    }

    #[inline]
    pub fn get<N>(&self, name: N) -> Option<&Param>
    where
        N: AsRef<str>,
    {
        self.params.iter().find(|p| p.name == name.as_ref())
    }

    #[inline]
    pub fn get_mut<N>(&mut self, name: N) -> Option<&mut Param>
    where
        N: AsRef<str>,
    {
        self.params.iter_mut().find(|p| p.name == name.as_ref())
    }

    #[inline]
    pub fn get_val<N>(&self, name: N) -> Option<&BytesStr>
    where
        N: AsRef<str>,
    {
        self.get(name.as_ref()).and_then(|p| p.value.as_ref())
    }

    #[inline]
    pub fn take<N>(&mut self, name: N) -> Option<BytesStr>
    where
        N: AsRef<str>,
    {
        let pos = self.params.iter().position(|p| p.name == name.as_ref())?;

        self.params.remove(pos).value
    }

    #[inline]
    pub fn push_or_edit<N, V>(&mut self, name: N, value: V)
    where
        N: Into<BytesStr> + AsRef<str>,
        V: Into<BytesStr>,
    {
        if let Some(param) = self.get_mut(name.as_ref()) {
            param.value = Some(value.into());
        } else {
            self.push(Param::value(name, value));
        }
    }

    pub fn filtered_print<F>(&self, filter: F) -> FilteredPrint<'_, S, F>
    where
        F: Fn(&str) -> bool,
    {
        FilteredPrint {
            params: self,
            filter,
        }
    }

    pub(crate) fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                opt(map(
                    ws((
                        tag(S::FIRST_DELIMITER),
                        Param::do_parse(src, S::CHAR_SPEC),
                        many0(map(
                            ws((tag(S::DELIMITER), Param::do_parse(src, S::CHAR_SPEC))),
                            |(_, param)| param,
                        )),
                    )),
                    |(_, first, mut params)| {
                        params.insert(0, first);
                        Params {
                            params,
                            marker: Default::default(),
                        }
                    },
                )),
                Option::unwrap_or_default,
            )(i)
        }
    }
}

impl<S: ParamsSpec> fmt::Debug for Params<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Params")
            .field("params", &self.params)
            .finish()
    }
}

impl<S: ParamsSpec> fmt::Display for Params<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.filtered_print(|_| true).fmt(f)
    }
}

/// used to print `Params` while filtering specific parameters
pub struct FilteredPrint<'p, S, F>
where
    S: ParamsSpec,
    F: Fn(&str) -> bool,
{
    params: &'p Params<S>,
    filter: F,
}

impl<S, F> fmt::Display for FilteredPrint<'_, S, F>
where
    S: ParamsSpec,
    F: Fn(&str) -> bool,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;

        for param in &self.params.params {
            if !(self.filter)(&param.name) {
                continue;
            }

            if first {
                first = false;
                f.write_str(S::FIRST_DELIMITER)?;
            } else {
                f.write_str(S::DELIMITER)?;
            }

            param.write(f, S::ENCODE_SET())?;
        }

        Ok(())
    }
}

impl<S> Default for Params<S> {
    fn default() -> Self {
        Params {
            params: Default::default(),
            marker: PhantomData,
        }
    }
}

/// Specification how the parameter in params are to be parsed / printed
pub trait ParamsSpec {
    const FIRST_DELIMITER: &'static str;
    const DELIMITER: &'static str;
    const CHAR_SPEC: fn(char) -> bool;
    const ENCODE_SET: fn() -> &'static AsciiSet;
}

/// Header Param Specification in uris (?SomeHeader=SomeValue&SomeOtherHeader=SomeOtherValue)
pub enum HPS {}

fn header_char(c: char) -> bool {
    c.is_alphanumeric()
        || matches!(
            c,
            '['| ']'| '/'| /*'=' |*/ ':'| '+'| '$'| '-'| '_'| '.'| '!'| '~'| '*'| '\''| '(' | ')'
        )
}

encode_set!(header_char, HPS_SET);

impl ParamsSpec for HPS {
    const FIRST_DELIMITER: &'static str = "?";
    const DELIMITER: &'static str = "&";
    const CHAR_SPEC: fn(char) -> bool = header_char;
    const ENCODE_SET: fn() -> &'static AsciiSet = || &HPS_SET;
}

/// Common Param Specification for URIs (;some=value;other=value)
pub enum CPS {}

#[rustfmt::skip]
fn param_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '%' | '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')' | '[' | ']' | '/' | ':' | '&' | '+' | '$' | '`')
}

encode_set!(param_char, CPS_SET);

impl ParamsSpec for CPS {
    const FIRST_DELIMITER: &'static str = ";";
    const DELIMITER: &'static str = ";";
    const CHAR_SPEC: fn(char) -> bool = param_char;
    const ENCODE_SET: fn() -> &'static AsciiSet = || &CPS_SET;
}

/// Represents a Parameter `name[=(value|"value")]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: BytesStr,
    pub value: Option<BytesStr>,
}

impl Param {
    #[inline]
    pub fn name<N>(name: N) -> Param
    where
        N: Into<BytesStr>,
    {
        Param {
            name: name.into(),
            value: None,
        }
    }

    #[inline]
    pub fn value<N, V>(name: N, value: V) -> Param
    where
        N: Into<BytesStr>,
        V: Into<BytesStr>,
    {
        Param {
            name: name.into(),
            value: Some(value.into()),
        }
    }

    pub(crate) fn write(&self, f: &mut fmt::Formatter<'_>, set: &'static AsciiSet) -> fmt::Result {
        match (&self.name, &self.value) {
            (name, None) => write!(f, "{}", percent_encode(name.as_bytes(), set)),
            (name, Some(value)) => write!(
                f,
                "{}={}",
                percent_encode(name.as_bytes(), set),
                percent_encode(value.as_bytes(), set)
            ),
        }
    }

    pub(crate) fn do_parse(
        src: &Bytes,
        spec: fn(char) -> bool,
    ) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map_res(
                ws((
                    take_while(spec),
                    opt(ws((tag("="), alt((parse_quoted, take_while(spec)))))),
                )),
                move |(name, value)| -> Result<_, Utf8Error> {
                    Ok(Param {
                        name: match percent_decode(name.as_bytes()).decode_utf8()? {
                            Cow::Borrowed(slice) => BytesStr::from_parse(src, slice),
                            Cow::Owned(owned) => BytesStr::from(owned),
                        },
                        value: match value {
                            None => None,
                            Some((_, value)) => {
                                Some(match percent_decode(value.as_bytes()).decode_utf8()? {
                                    Cow::Borrowed(slice) => BytesStr::from_parse(src, slice),
                                    Cow::Owned(owned) => BytesStr::from(owned),
                                })
                            }
                        },
                    })
                },
            )(i)
        }
    }
}

// helper macro to implement param functions on types that contain one or more Params
#[doc(hidden)]
#[macro_export]
macro_rules! impl_with_params {
    ($field:ident, $name_fn:ident, $value_fn:ident) => {
        #[inline]
        pub fn $name_fn<N>(mut self, name: N) -> Self
        where
            N: Into<bytesstr::BytesStr> + AsRef<str>,
        {
            self.$field.push($crate::uri::params::Param::name(name));
            self
        }

        #[inline]
        pub fn $value_fn<N, V>(mut self, name: N, value: V) -> Self
        where
            N: Into<bytesstr::BytesStr> + AsRef<str>,
            V: Into<bytesstr::BytesStr> + AsRef<str>,
        {
            self.$field.push_or_edit(name, value);
            self
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;
    use bytesstr::BytesStr;

    #[test]
    fn common_params_parse() {
        let input = BytesStr::from_static(";some_single_key;some_key=with_value");

        let (rem, params) = Params::<CPS>::parse(input.as_ref())(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(params.params[0].name, "some_single_key");
        assert_eq!(params.params[0].value, None);

        assert_eq!(params.params[1].name, "some_key");
        assert_eq!(
            params.params[1].value.as_ref().map(BytesStr::as_ref),
            Some("with_value")
        );
    }

    #[test]
    fn common_params_print() {
        let params = Params::<CPS>::new()
            .with(Param::name("some_single_key"))
            .with(Param::value("some_key", "with_value"));

        assert_eq!(params.to_string(), ";some_single_key;some_key=with_value");
    }

    #[test]
    fn common_params_print_encode() {
        let params = Params::<CPS>::new().with(Param::value("emoji", "😀"));

        assert_eq!(params.to_string(), ";emoji=%F0%9F%98%80");
    }

    #[test]
    fn common_params_decode() {
        let src = BytesStr::from_static(";emoji=%F0%9F%98%80");
        let (rem, params) = Params::<HPS>::parse(src.as_ref())(&src).unwrap();

        assert!(rem.is_empty());

        assert_eq!(params.params[0].name, "emoji");

        let value = params.params[0].value.as_ref().unwrap();

        assert_eq!(value, "😀");
    }

    #[test]
    fn header_params_parse() {
        let src = BytesStr::from_static("?some_single_key&some_key=with_value");
        let (rem, params) = Params::<HPS>::parse(src.as_ref())(&src).unwrap();

        assert!(rem.is_empty());

        assert_eq!(params.params[0].name, "some_single_key");
        assert_eq!(params.params[0].value, None);

        assert_eq!(params.params[1].name, "some_key");
        assert_eq!(
            params.params[1].value.as_ref().map(AsRef::<[u8]>::as_ref),
            Some(&b"with_value"[..])
        );
    }

    #[test]
    fn header_params_print() {
        let params = Params::<HPS>::new()
            .with(Param::name("some_single_key"))
            .with(Param::value("some_key", "with_value"));

        assert_eq!(params.to_string(), "?some_single_key&some_key=with_value");
    }
}
