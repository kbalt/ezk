use std::{fmt, ops::RangeInclusive};

use internal::IResult;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{u8, u32},
    combinator::{map, opt},
    error::context,
    multi::{many0, separated_list1},
    number::complete::float,
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
};

/// Image attributes attribute (`a=imageattr`)
///
/// Media Level attribute
///
/// [RFC6236](https://datatracker.ietf.org/doc/html/rfc6236)
#[derive(Debug, Clone, PartialEq)]
pub struct ImageAttr {
    /// Payload type the image attributes apply to, `None` if it applies to all
    pub pt: Option<u8>,
    pub send: Option<ImageAttrSets>,
    pub recv: Option<ImageAttrSets>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImageAttrSets {
    Wildcard,
    Sets(Vec<ImageAttrSet>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImageAttrSet {
    pub x: ImageAttrXyRange,
    pub y: ImageAttrXyRange,

    /// (sample aspect ratio) is the sample aspect ratio associated with the set (optional, MAY be ignored)
    pub sar: Option<ImageAttrSampleAspectRatio>,
    /// par (picture aspect ratio) is the allowed ratio between the display's x and y physical size (optional)
    pub par: Option<RangeInclusive<f32>>,
    /// q (range [0.0..1.0], default value 0.5) is the preference for the given set, a higher value means a higher preference
    pub q: Option<f32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImageAttrSampleAspectRatio {
    List(Vec<f32>),
    Range(f32, f32),
    Value(f32),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImageAttrXyRange {
    Range { lower: u32, upper: u32, step: u32 },
    List(Vec<u32>),
    Value(u32),
}

impl ImageAttrXyRange {
    fn parse(i: &str) -> IResult<&str, Self> {
        alt((
            map(
                delimited(
                    tag("["),
                    tuple((
                        terminated(u32, tag(":")),
                        opt(terminated(u32, tag(":"))),
                        u32,
                    )),
                    tag("]"),
                ),
                |(lower, step, upper)| ImageAttrXyRange::Range {
                    lower,
                    upper,
                    step: step.unwrap_or(1),
                },
            ),
            map(
                delimited(tag("["), separated_list1(tag(","), u32), tag("]")),
                ImageAttrXyRange::List,
            ),
            map(u32, ImageAttrXyRange::Value),
        ))(i)
    }
}

// temporary type used during parsing
enum Direction {
    Send,
    Recv,
}

#[derive(Debug, Clone, PartialEq)]
enum Param {
    Sar(ImageAttrSampleAspectRatio),
    Par { ratio_min: f32, ratio_max: f32 },
    Q(f32),
}

impl Param {
    fn parse(i: &str) -> IResult<&str, Self> {
        alt((
            map(
                preceded(
                    tag("sar="),
                    alt((
                        map(
                            delimited(tag("["), separated_pair(float, tag("-"), float), tag("]")),
                            |(l, r)| ImageAttrSampleAspectRatio::Range(l, r),
                        ),
                        map(
                            delimited(tag("["), separated_list1(tag(","), float), tag("]")),
                            ImageAttrSampleAspectRatio::List,
                        ),
                        map(float, ImageAttrSampleAspectRatio::Value),
                    )),
                ),
                Param::Sar,
            ),
            map(
                preceded(
                    tag("par="),
                    alt((
                        delimited(tag("["), separated_pair(float, tag("-"), float), tag("]")),
                        map(float, |ratio| (ratio, ratio)),
                    )),
                ),
                |(ratio_min, ratio_max)| Param::Par {
                    ratio_min,
                    ratio_max,
                },
            ),
            map(preceded(tag("q="), float), Param::Q),
        ))(i)
    }
}

fn parse_set(i: &str) -> IResult<&str, ImageAttrSet> {
    map(
        delimited(
            tag("["),
            tuple((
                preceded(tag("x="), ImageAttrXyRange::parse),
                tag(","),
                preceded(tag("y="), ImageAttrXyRange::parse),
                many0(preceded(tag(","), Param::parse)),
            )),
            tag("]"),
        ),
        |(x, _, y, params)| {
            let mut sar = None;
            let mut par = None;
            let mut q = None;

            for param in params {
                match param {
                    Param::Sar(v) => sar = Some(v),
                    Param::Par {
                        ratio_min,
                        ratio_max,
                    } => par = Some(ratio_min..=ratio_max),
                    Param::Q(v) => q = Some(v),
                }
            }

            ImageAttrSet { x, y, sar, par, q }
        },
    )(i)
}

fn parse_attr_list(i: &str) -> IResult<&str, ImageAttrSets> {
    alt((
        map(tag("*"), |_| ImageAttrSets::Wildcard),
        map(
            separated_list1(take_while1(char::is_whitespace), parse_set),
            ImageAttrSets::Sets,
        ),
    ))(i)
}

impl ImageAttr {
    pub fn parse(i: &str) -> IResult<&str, Self> {
        context(
            "parsing imageattr",
            map(
                separated_pair(
                    // pt
                    alt((map(tag("*"), |_| None), map(u8, Some))),
                    take_while1(char::is_whitespace),
                    // direction + attr-list pairs
                    separated_list1(
                        take_while1(char::is_whitespace),
                        separated_pair(
                            alt((
                                map(tag("send"), |_| Direction::Send),
                                map(tag("recv"), |_| Direction::Recv),
                            )),
                            take_while1(char::is_whitespace),
                            parse_attr_list,
                        ),
                    ),
                ),
                |(pt, list)| {
                    let mut send = None;
                    let mut recv = None;

                    for (dir, attr_list) in list {
                        match dir {
                            Direction::Send => send = Some(attr_list),
                            Direction::Recv => recv = Some(attr_list),
                        }
                    }

                    ImageAttr { pt, send, recv }
                },
            ),
        )(i)
    }
}

impl fmt::Display for ImageAttrXyRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ImageAttrXyRange::Range { lower, upper, step } => {
                write!(f, "[{lower}:")?;
                if *step != 1 {
                    write!(f, "{step}:")?;
                }
                write!(f, "{upper}]")
            }
            ImageAttrXyRange::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i == 0 {
                        write!(f, "{item}")?;
                    } else {
                        write!(f, ",{item}")?;
                    }
                }
                write!(f, "]")?;

                Ok(())
            }
            ImageAttrXyRange::Value(v) => v.fmt(f),
        }
    }
}

impl fmt::Display for ImageAttrSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[x={},y={}", self.x, self.y)?;

        if let Some(sar) = &self.sar {
            match sar {
                ImageAttrSampleAspectRatio::List(items) => {
                    write!(f, ",sar=[")?;
                    for (i, item) in items.iter().enumerate() {
                        if i == 0 {
                            write!(f, "{item:.4}")?;
                        } else {
                            write!(f, ",{item:.4}")?;
                        }
                    }
                    write!(f, "]")?;
                }
                ImageAttrSampleAspectRatio::Range(min, max) => {
                    write!(f, ",sar=[{min:.4}-{max:.4}]")?;
                }
                ImageAttrSampleAspectRatio::Value(v) => {
                    write!(f, ",sar={v:.4}")?;
                }
            }
        }

        if let Some(par) = &self.par {
            write!(f, ",par=[{:.4}-{:.4}]", par.start(), par.end())?
        }

        if let Some(q) = self.q {
            write!(f, ",q={q:.2}")?;
        }

        write!(f, "]")
    }
}

impl fmt::Display for ImageAttrSets {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ImageAttrSets::Wildcard => write!(f, "*"),
            ImageAttrSets::Sets(sets) => {
                for (i, set) in sets.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{set}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for ImageAttr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.pt {
            Some(pt) => write!(f, "{pt}")?,
            None => write!(f, "*")?,
        }

        if let Some(send) = &self.send {
            write!(f, " send {send}")?;
        }

        if let Some(recv) = &self.recv {
            write!(f, " recv {recv}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xyrange() {
        let (rem, v) = ImageAttrXyRange::parse("800").unwrap();
        assert!(rem.is_empty());
        assert_eq!(v, ImageAttrXyRange::Value(800));

        let (rem, v) = ImageAttrXyRange::parse("[800:1200]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            v,
            ImageAttrXyRange::Range {
                lower: 800,
                upper: 1200,
                step: 1
            }
        );

        let (rem, v) = ImageAttrXyRange::parse("[800:4:1200]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            v,
            ImageAttrXyRange::Range {
                lower: 800,
                upper: 1200,
                step: 4
            }
        );

        let (rem, v) = ImageAttrXyRange::parse("[320,640,1280]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(v, ImageAttrXyRange::List(vec![320, 640, 1280]));

        // Single-element brackets: no colon, falls through to list
        let (rem, v) = ImageAttrXyRange::parse("[640]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(v, ImageAttrXyRange::List(vec![640]));
    }

    #[test]
    fn fmt_xyrange() {
        assert_eq!(ImageAttrXyRange::Value(1920).to_string(), "1920");
        assert_eq!(
            ImageAttrXyRange::Range {
                lower: 320,
                upper: 1920,
                step: 1
            }
            .to_string(),
            "[320:1920]"
        );
        assert_eq!(
            ImageAttrXyRange::Range {
                lower: 320,
                upper: 1920,
                step: 2
            }
            .to_string(),
            "[320:2:1920]"
        );
        assert_eq!(ImageAttrXyRange::List(vec![640]).to_string(), "[640]");
        assert_eq!(
            ImageAttrXyRange::List(vec![320, 640, 1280]).to_string(),
            "[320,640,1280]"
        );
    }

    #[test]
    fn parse_params() {
        let (rem, v) = Param::parse("sar=[0.5-0.6]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(v, Param::Sar(ImageAttrSampleAspectRatio::Range(0.5, 0.6)));

        let (rem, v) = Param::parse("sar=[0.5,0.6]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            v,
            Param::Sar(ImageAttrSampleAspectRatio::List(vec![0.5, 0.6]))
        );

        let (rem, v) = Param::parse("sar=0.5").unwrap();
        assert!(rem.is_empty());
        assert_eq!(v, Param::Sar(ImageAttrSampleAspectRatio::Value(0.5)));

        let (rem, v) = Param::parse("par=[0.5-0.6]").unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            v,
            Param::Par {
                ratio_min: 0.5,
                ratio_max: 0.6
            }
        );

        // Non standard PAR should also parse
        let (rem, v) = Param::parse("par=0.5").unwrap();
        assert!(rem.is_empty());
        assert_eq!(
            v,
            Param::Par {
                ratio_min: 0.5,
                ratio_max: 0.5
            }
        );

        let (rem, v) = Param::parse("q=0.5").unwrap();
        assert!(rem.is_empty());
        assert_eq!(v, Param::Q(0.5));
    }

    #[test]
    fn fmt_set_all_params() {
        let set = ImageAttrSet {
            x: ImageAttrXyRange::Range {
                lower: 320,
                upper: 1920,
                step: 1,
            },
            y: ImageAttrXyRange::List(vec![240, 720]),
            sar: Some(ImageAttrSampleAspectRatio::Value(1.1)),
            par: Some(0.75..=1.33),
            q: Some(0.8),
        };
        assert_eq!(
            set.to_string(),
            "[x=[320:1920],y=[240,720],sar=1.1000,par=[0.7500-1.3300],q=0.80]"
        );
    }

    fn unwrap_sets(sets: &Option<ImageAttrSets>) -> &Vec<ImageAttrSet> {
        match sets {
            Some(ImageAttrSets::Sets(s)) => s,
            other => panic!("expected Some(Sets), got {other:?}"),
        }
    }

    #[test]
    fn parse_imageattr() {
        let input = "97 send [x=800,y=640,sar=1.1] recv [x=336,y=256] [x=200,y=100]";

        let (rem, attr) = ImageAttr::parse(input).unwrap();
        assert!(rem.is_empty());

        assert_eq!(attr.pt, Some(97));

        let send = unwrap_sets(&attr.send);
        assert_eq!(send.len(), 1);
        assert_eq!(send[0].x, ImageAttrXyRange::Value(800));
        assert_eq!(send[0].y, ImageAttrXyRange::Value(640));
        assert_eq!(send[0].sar, Some(ImageAttrSampleAspectRatio::Value(1.1)));
        assert!(send[0].par.is_none());

        let recv = unwrap_sets(&attr.recv);
        assert_eq!(recv.len(), 2);
        assert_eq!(recv[0].x, ImageAttrXyRange::Value(336));
        assert_eq!(recv[0].y, ImageAttrXyRange::Value(256));

        assert_eq!(recv[1].x, ImageAttrXyRange::Value(200));
        assert_eq!(recv[1].y, ImageAttrXyRange::Value(100));
    }

    #[test]
    fn parse_imageattr_multiple_send_sets() {
        let input = "96 send [x=640,y=480] [x=1280,y=720,q=0.9]";
        let (rem, attr) = ImageAttr::parse(input).unwrap();
        assert!(rem.is_empty());
        let send = unwrap_sets(&attr.send);
        assert_eq!(send.len(), 2);
        assert_eq!(send[0].x, ImageAttrXyRange::Value(640));
        assert_eq!(send[0].q, None);
        assert_eq!(send[1].x, ImageAttrXyRange::Value(1280));
        assert_eq!(send[1].q, Some(0.9));
    }

    #[test]
    fn fmt_imageattr() {
        let attr = ImageAttr {
            pt: Some(97),
            send: Some(ImageAttrSets::Sets(vec![ImageAttrSet {
                x: ImageAttrXyRange::Value(800),
                y: ImageAttrXyRange::Value(640),
                sar: Some(ImageAttrSampleAspectRatio::Value(1.1)),
                par: None,
                q: None,
            }])),
            recv: Some(ImageAttrSets::Sets(vec![
                ImageAttrSet {
                    x: ImageAttrXyRange::Value(336),
                    y: ImageAttrXyRange::Value(256),
                    sar: None,
                    par: None,
                    q: None,
                },
                ImageAttrSet {
                    x: ImageAttrXyRange::Value(200),
                    y: ImageAttrXyRange::Value(100),
                    sar: None,
                    par: None,
                    q: None,
                },
            ])),
        };
        assert_eq!(
            attr.to_string(),
            "97 send [x=800,y=640,sar=1.1000] recv [x=336,y=256] [x=200,y=100]"
        );
    }

    #[test]
    fn roundtrip_simple() {
        let input = "97 send [x=800,y=640,sar=1.1] recv [x=336,y=256] [x=200,y=100]";
        let (_, parsed) = ImageAttr::parse(input).unwrap();
        let formatted = parsed.to_string();
        let (rem, reparsed) = ImageAttr::parse(&formatted).unwrap();
        assert!(rem.is_empty());
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn roundtrip_ranges_and_params() {
        let input = "96 send [x=[320:1920],y=[240,720],q=0.8]";
        let (_, parsed) = ImageAttr::parse(input).unwrap();
        let formatted = parsed.to_string();
        let (rem, reparsed) = ImageAttr::parse(&formatted).unwrap();
        assert!(rem.is_empty());
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn roundtrip_wildcard_pt() {
        let input = "* recv [x=640,y=480]";
        let (_, parsed) = ImageAttr::parse(input).unwrap();
        let formatted = parsed.to_string();
        let (rem, reparsed) = ImageAttr::parse(&formatted).unwrap();
        assert!(rem.is_empty());
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn roundtrip_all_optional_params() {
        let input = "96 send [x=800,y=600,sar=1.1,par=[0.75-1.33],q=0.5]";
        let (_, parsed) = ImageAttr::parse(input).unwrap();
        let formatted = parsed.to_string();
        let (rem, reparsed) = ImageAttr::parse(&formatted).unwrap();
        assert!(rem.is_empty());
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn roundtrip_recv_wildcard() {
        let input = "97 send [x=480,y=320] recv *";
        let (_, parsed) = ImageAttr::parse(input).unwrap();
        let formatted = parsed.to_string();
        assert_eq!(formatted, input);
        let (rem, reparsed) = ImageAttr::parse(&formatted).unwrap();
        assert!(rem.is_empty());
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn roundtrip_both_wildcard() {
        let input = "97 send * recv *";
        let (_, parsed) = ImageAttr::parse(input).unwrap();
        let formatted = parsed.to_string();
        assert_eq!(formatted, input);
        let (rem, reparsed) = ImageAttr::parse(&formatted).unwrap();
        assert!(rem.is_empty());
        assert_eq!(parsed, reparsed);
    }
}
