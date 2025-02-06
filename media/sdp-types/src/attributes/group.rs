use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::{
    bytes::complete::{take_while, take_while1},
    combinator::map,
    multi::separated_list1,
    sequence::tuple,
};
use std::fmt;

#[derive(Debug, Clone)]
pub struct Group {
    pub typ: BytesStr,
    pub mids: Vec<BytesStr>,
}

impl Group {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            tuple((
                // type
                take_while(|c: char| !c.is_whitespace()),
                take_while(char::is_whitespace),
                // mids
                separated_list1(
                    take_while1(char::is_whitespace),
                    map(take_while(|c: char| !c.is_whitespace()), |str| {
                        BytesStr::from_parse(src, str)
                    }),
                ),
            )),
            |(typ, _, mids)| Self {
                typ: BytesStr::from_parse(src, typ),
                mids,
            },
        )(i)
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.typ)?;

        for mid in &self.mids {
            write!(f, " {mid}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn group() {
        let input = BytesStr::from_static("BUNDLE 0 1 2");

        let (rem, group) = Group::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(group.typ, "BUNDLE");

        assert_eq!(
            group.mids,
            vec![
                BytesStr::from(0.to_string()),
                BytesStr::from(1.to_string()),
                BytesStr::from(2.to_string())
            ]
        );
    }

    #[test]
    fn group_print() {
        let group = Group {
            typ: "BUNDLE".into(),
            mids: vec!["0".into(), "1".into(), "2".into()],
        };

        assert_eq!(group.to_string(), "BUNDLE 0 1 2");
    }
}
