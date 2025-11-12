use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::{
    branch::alt,
    bytes::complete::{tag_no_case, take_while1},
    character::complete::{char, u8},
    combinator::map,
    error::context,
    sequence::{preceded, separated_pair},
};
use std::fmt;

/// RTCP Feedback attribute (`a=rtcp-fb`).
///
/// Media Level attribute
///
/// [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585#section-4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpFeedback {
    pub pt: RtcpFeedbackPt,
    pub kind: RtcpFeedbackKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpFeedbackPt {
    /// Feedback type applies to the given payload type
    Pt(u8),
    /// Wildcard '*', applies to all payload types
    Any,
}

impl RtcpFeedbackPt {
    pub fn matches(&self, pt: u8) -> bool {
        match self {
            RtcpFeedbackPt::Pt(v) => *v == pt,
            RtcpFeedbackPt::Any => true,
        }
    }
}

/// Kind of RTCP feedback parameter for an `a=rtcp-fb` attribute.
///
/// # References
///
/// - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585)
/// - [RFC 5104](https://datatracker.ietf.org/doc/html/rfc5104)
/// - [RFC 6679](https://datatracker.ietf.org/doc/html/rfc6679)
/// - [RFC 8888](https://datatracker.ietf.org/doc/html/rfc8888)
/// - [draft-holmer-rmcat-transport-wide-cc-extensions-01](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
/// - [draft-alvestrand-rmcat-remb-03](https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpFeedbackKind {
    // See RFC 4585, excluded "ack app" & "nack app"
    /// `ack` - Positive acknowledgement
    Ack,
    /// `ack rpsi` - ACK Reference Picture Selection Indication
    AckRpsi,
    // See RFC 8888
    /// `ack ccfb` - Congestion Control Feedback
    AckCcfb,

    /// `nack` - Generic negative acknowledgement
    Nack,
    /// `nack pli` - Picture Loss Indication
    NackPli,
    /// `nack sli` - Slice Loss Indication
    NackSli,
    /// `nack rpsi` - NACK Reference Picture Selection Indication
    NackRpsi,

    // See RFC 5104
    /// `ccm fir` - Full Intra Request Command
    CcmFir,
    /// `ccm tmmbr` - Temporary Maximum Media Stream Bit Rate
    CcmTmmbr,
    /// `ccm tstr` - Temporal Spatial Trade Off
    CcmTstr,
    /// `ccm vbcm` - H.271 video back channel messages
    CcmVbcm,

    // See RFC 6679
    /// `ecn` - Explicit Congestion Notification
    Ecn,

    // See https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01
    /// `transport-cc `- Transport-wide Congestion Control
    TransportCC,

    // See https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03
    /// `goog-remb` - Receiver Estimated Maximum Bitrate
    GoogRemb,

    /// `trr-int <int>` - Minimal receiver report interval
    TrrInt(u64),

    /// Other unrecognized rtcp-fb ids
    Other(BytesStr),
}

impl RtcpFeedback {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        use RtcpFeedbackKind as Kind;
        use tag_no_case as t;

        context(
            "parsing rtcp-fb attribute",
            map(
                separated_pair(
                    // pt = * / fmt
                    alt((
                        map(char('*'), |_: char| RtcpFeedbackPt::Any),
                        map(u8, RtcpFeedbackPt::Pt),
                    )),
                    // SP
                    take_while1(char::is_whitespace),
                    // rtcp-fb-val
                    alt((
                        // ACK
                        map(t("ack rpsi"), |_| Kind::AckRpsi),
                        map(t("ack ccfb"), |_| Kind::AckCcfb),
                        map(t("ack"), |_| Kind::Ack),
                        // NACK
                        map(alt((t("nack pli"), t("pli"))), |_| Kind::NackPli),
                        map(alt((t("nack sli"), t("sli"))), |_| Kind::NackSli),
                        map(alt((t("nack rpsi"), t("rpsi"))), |_| Kind::NackRpsi),
                        map(t("nack"), |_| Kind::Nack),
                        // CCM
                        map(alt((t("ccm fir"), t("fir"))), |_| Kind::CcmFir),
                        map(alt((t("ccm tmmbr"), t("tmmbr"))), |_| Kind::CcmTmmbr),
                        map(t("ccm tstr"), |_| Kind::CcmTstr),
                        map(t("ccm vbcm"), |_| Kind::CcmVbcm),
                        // ECN
                        map(t("ecn"), |_| Kind::Ecn),
                        // TRANSPORT CC
                        map(t("transport-cc"), |_| Kind::TransportCC),
                        // GOOG-REMB
                        map(t("goog-remb"), |_| Kind::GoogRemb),
                        // TRR-INT
                        map(
                            preceded(
                                t("trr-int"),
                                preceded(
                                    take_while1(char::is_whitespace),
                                    nom::character::complete::u64,
                                ),
                            ),
                            Kind::TrrInt,
                        ),
                        // Other
                        map(take_while1(|c: char| !c.is_whitespace()), |s: &str| {
                            Kind::Other(BytesStr::from_parse(src, s))
                        }),
                    )),
                ),
                |(pt, kind)| RtcpFeedback { pt, kind },
            ),
        )(i)
    }
}

impl fmt::Display for RtcpFeedback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pt {
            RtcpFeedbackPt::Pt(pt) => write!(f, "{pt} ")?,
            RtcpFeedbackPt::Any => write!(f, "* ")?,
        }

        match &self.kind {
            RtcpFeedbackKind::Ack => write!(f, "ack"),
            RtcpFeedbackKind::AckRpsi => write!(f, "ack rpsi"),
            RtcpFeedbackKind::AckCcfb => write!(f, "ack ccfb"),
            RtcpFeedbackKind::Nack => write!(f, "nack"),
            RtcpFeedbackKind::NackPli => write!(f, "nack pli"),
            RtcpFeedbackKind::NackSli => write!(f, "nack sli"),
            RtcpFeedbackKind::NackRpsi => write!(f, "nack rpsi"),
            RtcpFeedbackKind::CcmFir => write!(f, "ccm fir"),
            RtcpFeedbackKind::CcmTmmbr => write!(f, "ccm tmmbr"),
            RtcpFeedbackKind::CcmTstr => write!(f, "ccm tstr"),
            RtcpFeedbackKind::CcmVbcm => write!(f, "ccm vbcm"),
            RtcpFeedbackKind::Ecn => write!(f, "ecn"),
            RtcpFeedbackKind::TransportCC => write!(f, "transport-cc"),
            RtcpFeedbackKind::GoogRemb => write!(f, "goog-remb"),
            RtcpFeedbackKind::TrrInt(int) => write!(f, "trr-int {int}"),
            RtcpFeedbackKind::Other(other) => f.write_str(other),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &'static str) -> RtcpFeedback {
        let src = BytesStr::from_static(input);
        let (rem, fb) = RtcpFeedback::parse(src.as_ref(), &src).unwrap();
        assert!(rem.is_empty());
        fb
    }

    #[test]
    fn parse_rtcp_fb() {
        // ACK
        assert_eq!(
            parse("* ack"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::Ack
            }
        );

        assert_eq!(
            parse("* ack rpsi"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::AckRpsi
            }
        );

        assert_eq!(
            parse("* ack ccfb"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::AckCcfb
            }
        );

        // NACK
        assert_eq!(
            parse("* nack"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::Nack
            }
        );

        assert_eq!(
            parse("96 nack pli"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Pt(96),
                kind: RtcpFeedbackKind::NackPli
            }
        );

        assert_eq!(
            parse("* pli"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::NackPli
            }
        );

        assert_eq!(
            parse("* sli"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::NackSli
            }
        );

        assert_eq!(
            parse("* rpsi"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::NackRpsi
            }
        );

        // CCM
        assert_eq!(
            parse("* ccm fir"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmFir
            }
        );

        assert_eq!(
            parse("* fir"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmFir
            }
        );

        assert_eq!(
            parse("* ccm tmmbr"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmTmmbr
            }
        );

        assert_eq!(
            parse("* tmmbr"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmTmmbr
            }
        );

        assert_eq!(
            parse("* ccm tstr"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmTstr
            }
        );

        assert_eq!(
            parse("* ccm vbcm"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmVbcm
            }
        );

        // TRR-INT
        assert_eq!(
            parse("* trr-int 0"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::TrrInt(0)
            }
        );

        assert_eq!(
            parse("* trr-int 100"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::TrrInt(100)
            }
        );

        // ECN
        assert_eq!(
            parse("* ecn"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::Ecn
            }
        );

        // "Drafts"
        assert_eq!(
            parse("* transport-cc"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::TransportCC
            }
        );

        assert_eq!(
            parse("* goog-remb"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::GoogRemb
            }
        );

        // Case insensitive
        assert_eq!(
            parse("* NACK"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::Nack
            }
        );

        assert_eq!(
            parse("* Transport-CC"),
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::TransportCC
            }
        );

        // Unknown token
        let result = parse("* other");
        assert_eq!(
            result.kind,
            RtcpFeedbackKind::Other(BytesStr::from_static("other"))
        );
    }

    #[test]
    fn test_to_string() {
        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::Nack
            }
            .to_string(),
            "* nack"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Pt(96),
                kind: RtcpFeedbackKind::NackPli
            }
            .to_string(),
            "96 nack pli"
        );

        // ACK
        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::Ack
            }
            .to_string(),
            "* ack"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::AckRpsi
            }
            .to_string(),
            "* ack rpsi"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::AckCcfb
            }
            .to_string(),
            "* ack ccfb"
        );

        // NACK
        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::NackPli
            }
            .to_string(),
            "* nack pli"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::NackSli
            }
            .to_string(),
            "* nack sli"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::NackRpsi
            }
            .to_string(),
            "* nack rpsi"
        );

        // CCM
        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmFir
            }
            .to_string(),
            "* ccm fir"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmTmmbr
            }
            .to_string(),
            "* ccm tmmbr"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmTstr
            }
            .to_string(),
            "* ccm tstr"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::CcmVbcm
            }
            .to_string(),
            "* ccm vbcm"
        );

        // TRR-INT
        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::TrrInt(100)
            }
            .to_string(),
            "* trr-int 100"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::TrrInt(0)
            }
            .to_string(),
            "* trr-int 0"
        );

        // Standalone
        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::Ecn
            }
            .to_string(),
            "* ecn"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::TransportCC
            }
            .to_string(),
            "* transport-cc"
        );

        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::GoogRemb
            }
            .to_string(),
            "* goog-remb"
        );

        // Other
        assert_eq!(
            RtcpFeedback {
                pt: RtcpFeedbackPt::Any,
                kind: RtcpFeedbackKind::Other(BytesStr::from_static("other"))
            }
            .to_string(),
            "* other"
        );
    }
}
