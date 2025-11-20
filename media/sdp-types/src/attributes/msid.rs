use std::fmt;

use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::{
    bytes::complete::take_while1,
    combinator::{map, opt},
    error::context,
    sequence::{pair, preceded},
};

use crate::not_whitespace;

/// MediaStream Identification attribute (`a=msid`)
///
/// Media Level attribute
///
/// [RFC8830](https://www.rfc-editor.org/rfc/rfc8830.html)
#[derive(Debug, Clone)]
pub struct MsId {
    pub id: BytesStr,
    pub appdata: Option<BytesStr>,
}

impl MsId {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing msid",
            map(
                pair(
                    // id
                    take_while1(not_whitespace),
                    // appdata
                    opt(preceded(
                        take_while1(char::is_whitespace),
                        take_while1(not_whitespace),
                    )),
                ),
                |(id, appdata)| MsId {
                    id: BytesStr::from_parse(src, id),
                    appdata: appdata.map(|appdata| BytesStr::from_parse(src, appdata)),
                },
            ),
        )(i)
    }
}

impl fmt::Display for MsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id)?;

        if let Some(appdata) = &self.appdata {
            write!(f, " {appdata}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn msid() {
        let input = BytesStr::from_static("myid myappdata");

        let (rem, msid) = MsId::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(msid.id, "myid");
        assert_eq!(msid.appdata.unwrap(), "myappdata");
    }

    #[test]
    fn msid_print() {
        let msid = MsId {
            id: "myid".into(),
            appdata: Some("myappdata".into()),
        };

        assert_eq!(msid.to_string(), "myid myappdata");
    }
}
