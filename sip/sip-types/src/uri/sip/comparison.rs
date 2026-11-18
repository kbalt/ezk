use super::{SipUri, SipUriUserPart};
use crate::Name;
use crate::header::HeaderParse;
use crate::header::typed::FromTo;
use crate::host::Host;
use crate::uri::NameAddr;
use crate::uri::params::{CPS, HPS, Param, Params, ParamsSpec};
use bytesstr::BytesStr;

pub(super) fn compare(a: &SipUri, b: &SipUri) -> bool {
    let users_match = match (&a.user_part, &b.user_part) {
        (SipUriUserPart::UserPw(a), SipUriUserPart::UserPw(b)) => {
            a.user == b.user && password(&a.password) == password(&b.password)
        }
        (a, b) => a == b,
    };
    let hosts_match = match (&a.host_port.host, &b.host_port.host) {
        (Host::Name(a), Host::Name(b)) => a.eq_ignore_ascii_case(b),
        (a, b) => a == b,
    };
    a.sips == b.sips
        && users_match
        && hosts_match
        && a.host_port.port == b.host_port.port
        && uri_params(&a.uri_params, &b.uri_params)
        && headers(&a.header_params, &b.header_params)
}

// Passwords, unlike users and parameters, are stored escaped. Decode only
// unreserved characters, leaving reserved characters distinct from escapes.
fn password(value: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut bytes = value.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let mut next = bytes.clone();
            if let (Some(hi), Some(lo)) = (next.next(), next.next())
                && let (Some(hi), Some(lo)) = ((hi as char).to_digit(16), (lo as char).to_digit(16))
            {
                let decoded = (hi * 16 + lo) as u8;
                if decoded.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&decoded) {
                    result.push(decoded);
                } else {
                    result.extend_from_slice(format!("%{decoded:02X}").as_bytes());
                }
                bytes = next;
                continue;
            }
        }
        result.push(byte);
    }
    result
}

fn uri_params(a: &Params<CPS>, b: &Params<CPS>) -> bool {
    fn direction(a: &Params<CPS>, b: &Params<CPS>) -> bool {
        a.iter().all(|param| {
            let matching: Vec<_> = b
                .iter()
                .filter(|p| p.name.eq_ignore_ascii_case(&param.name))
                .collect();
            if matching.is_empty() {
                // Transport presence follows the explicit default-component
                // rule and the transport=udp example in section 19.1.4.
                !["transport", "user", "ttl", "method", "maddr"]
                    .iter()
                    .any(|name| param.name.eq_ignore_ascii_case(name))
            } else {
                matching
                    .iter()
                    .all(|other| match (&param.value, &other.value) {
                        (Some(a), Some(b)) if !param.name.eq_ignore_ascii_case("method") => {
                            a.eq_ignore_ascii_case(b)
                        }
                        (a, b) => a == b,
                    })
            }
        })
    }
    direction(a, b) && direction(b, a)
}

fn headers(a: &Params<HPS>, b: &Params<HPS>) -> bool {
    // Section 7.3.1 permits comma-list fields to be split across occurrences.
    // Different field names may move freely, but same-name list values retain
    // their order (notably the sequence of applied Content-Encodings).
    fn grouped(headers: &Params<HPS>) -> Vec<Param> {
        let mut result: Vec<Param> = Vec::new();
        for header in headers.iter() {
            let name = Name::from(header.name.clone());
            if [
                "Require",
                "Supported",
                "Unsupported",
                "Proxy-Require",
                "Content-Encoding",
                "Content-Language",
            ]
            .iter()
            .any(|n| name == **n)
                && let Some(value) = &header.value
                && let Some(existing) = result
                    .iter_mut()
                    .find(|p| Name::from(p.name.clone()) == name && p.value.is_some())
            {
                existing.value =
                    Some(format!("{},{value}", existing.value.as_ref().unwrap()).into());
            } else {
                result.push(header.clone());
            }
        }
        result
    }
    let a = grouped(a);
    let b = grouped(b);
    let mut unmatched: Vec<_> = b.iter().collect();
    for header in a.iter() {
        let Some(index) = unmatched.iter().position(|other| {
            Name::from(header.name.clone()) == Name::from(other.name.clone())
                && header_value(header, other)
        }) else {
            return false;
        };
        unmatched.remove(index);
    }
    unmatched.is_empty()
}

fn parsed<H: HeaderParse>(value: &BytesStr) -> Option<H> {
    let (rest, header) = H::parse(value.as_ref(), value).ok()?;
    rest.trim().is_empty().then_some(header)
}

// The shared parameter parser discards quotation marks. Inspect only the raw
// From/To parameter remainder to retain which extension values were quoted;
// display-name quotes and URI parameters must not influence this decision.
fn quoted_from_to_params(value: &BytesStr) -> Option<Vec<BytesStr>> {
    let (mut rest, _) = NameAddr::parse_no_params(value.as_ref())(value).ok()?;
    let mut quoted = Vec::new();
    while !rest.trim().is_empty() {
        let input = rest.trim_start().strip_prefix(';')?.trim_start();
        let (remaining, param) = Param::do_parse(value.as_ref(), CPS::CHAR_SPEC)(input).ok()?;
        let raw = &input[..input.len() - remaining.len()];
        if raw
            .split_once('=')
            .is_some_and(|(_, v)| v.trim_start().starts_with('"'))
        {
            quoted.push(param.name);
        }
        rest = remaining;
    }
    Some(quoted)
}

fn header_value(a: &Param, b: &Param) -> bool {
    let (Some(a_value), Some(b_value)) = (&a.value, &b.value) else {
        return a.value == b.value;
    };
    let name = Name::from(a.name.clone());
    if name == Name::FROM || name == Name::TO {
        if let (Some(a), Some(b)) = (parsed::<FromTo>(a_value), parsed::<FromTo>(b_value)) {
            let (Some(a_quoted), Some(b_quoted)) = (
                quoted_from_to_params(a_value),
                quoted_from_to_params(b_value),
            ) else {
                return a_value == b_value;
            };
            // Section 20.20: display names and one-sided extensions do not
            // participate; tags are case-sensitive (section 19.3).
            let tag = |header: &FromTo| {
                header
                    .params
                    .iter()
                    .find(|p| p.name.eq_ignore_ascii_case("tag"))
                    .and_then(|p| p.value.clone())
                    .or_else(|| header.tag.clone())
            };
            let extensions = |a: &FromTo, b: &FromTo| {
                a.params
                    .iter()
                    .filter(|p| !p.name.eq_ignore_ascii_case("tag"))
                    .all(|param| {
                        b.params
                            .iter()
                            .filter(|p| p.name.eq_ignore_ascii_case(&param.name))
                            .all(|other| match (&param.value, &other.value) {
                                (Some(a), Some(b))
                                    if a_quoted
                                        .iter()
                                        .chain(&b_quoted)
                                        .any(|name| name.eq_ignore_ascii_case(&param.name)) =>
                                {
                                    a == b
                                }
                                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                                (a, b) => a == b,
                            })
                    })
            };
            return tag(&a) == tag(&b)
                && extensions(&a, &b)
                && extensions(&b, &a)
                && a.uri.uri.compare(&b.uri.uri);
        }
    } else if name == Name::CSEQ {
        // Method's general parser accepts case-insensitive spellings; CSeq
        // comparison explicitly requires a case-sensitive method (20.16).
        fn cseq(value: &str) -> Option<(u32, &str)> {
            let mut words = value.split_ascii_whitespace();
            let number = words.next()?.parse().ok()?;
            let method = words.next()?;
            words.next().is_none().then_some((number, method))
        }
        if let (Some(a), Some(b)) = (cseq(a_value), cseq(b_value)) {
            return a == b;
        }
    } else if name == Name::CONTENT_TYPE {
        if let (Some(a), Some(b)) = (MediaType::parse(a_value), MediaType::parse(b_value)) {
            return a.compare(&b);
        }
    } else if ["Require", "Supported", "Unsupported", "Proxy-Require"]
        .iter()
        .any(|n| name == **n)
    {
        // These enumerate option tags, not an ordered sequence of operations
        // (sections 20.29, 20.32, 20.37, and 20.40).
        let tags = |value: &str| {
            let mut tags: Vec<_> = value
                .split(',')
                .map(|v| v.trim().to_ascii_lowercase())
                .collect();
            tags.sort_unstable();
            tags
        };
        return tags(a_value) == tags(b_value);
    } else if ["Priority", "Content-Encoding", "Content-Language"]
        .iter()
        .any(|n| name == **n)
    {
        let mut a = a_value.split(',').map(str::trim);
        let mut b = b_value.split(',').map(str::trim);
        loop {
            match (a.next(), b.next()) {
                (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
                (None, None) => return true,
                _ => return false,
            }
        }
    } else if ["Expires", "Min-Expires", "Max-Forwards", "Content-Length"]
        .iter()
        .any(|n| name == **n)
        && let (Ok(a), Ok(b)) = (a_value.trim().parse::<u64>(), b_value.trim().parse::<u64>())
    {
        return a == b;
    }
    // Call-ID, Subject, methods, quoted strings, and unknown extension headers
    // must not be indiscriminately case-folded.
    a_value == b_value
}

// Comparison-local MIME parsing: the public ContentType parser intentionally
// wraps raw text. In particular, shared Params parsing would lose quoted-value
// syntax and would percent-decode values a second time.
struct MediaType<'a> {
    kind: &'a str,
    subtype: &'a str,
    params: Vec<(&'a str, String)>,
}

impl<'a> MediaType<'a> {
    fn parse(mut input: &'a str) -> Option<Self> {
        fn token<'a>(input: &mut &'a str) -> Option<&'a str> {
            let end = input
                .find(|c: char| {
                    !c.is_ascii()
                        || c.is_ascii_control()
                        || b"()<>@,;:\\\"/[]?= \t".contains(&(c as u8))
                })
                .unwrap_or(input.len());
            if end == 0 {
                return None;
            }
            let value = &input[..end];
            *input = &input[end..];
            Some(value)
        }

        input = input.trim_matches([' ', '\t']);
        let kind = token(&mut input)?;
        input = input
            .trim_start_matches([' ', '\t'])
            .strip_prefix('/')?
            .trim_start_matches([' ', '\t']);
        let subtype = token(&mut input)?;
        let mut params = Vec::new();
        loop {
            input = input.trim_start_matches([' ', '\t']);
            if input.is_empty() {
                return Some(Self {
                    kind,
                    subtype,
                    params,
                });
            }
            input = input.strip_prefix(';')?.trim_start_matches([' ', '\t']);
            let name = token(&mut input)?;
            input = input
                .trim_start_matches([' ', '\t'])
                .strip_prefix('=')?
                .trim_start_matches([' ', '\t']);
            let value = if let Some(quoted) = input.strip_prefix('"') {
                let mut chars = quoted.chars();
                let mut value = String::new();
                loop {
                    let c = chars.next()?;
                    if c == '"' {
                        input = chars.as_str();
                        break;
                    }
                    let c = if c == '\\' { chars.next()? } else { c };
                    if c.is_control() && c != '\t' {
                        return None;
                    }
                    value.push(c);
                }
                value
            } else {
                token(&mut input)?.to_owned()
            };
            params.push((name, value));
        }
    }

    fn compare(&self, other: &Self) -> bool {
        if !self.kind.eq_ignore_ascii_case(other.kind)
            || !self.subtype.eq_ignore_ascii_case(other.subtype)
        {
            return false;
        }
        let mut unmatched: Vec<_> = other.params.iter().collect();
        for (name, value) in &self.params {
            let Some(index) = unmatched.iter().position(|(other_name, other_value)| {
                name.eq_ignore_ascii_case(other_name)
                    && if name.eq_ignore_ascii_case("charset") {
                        value.eq_ignore_ascii_case(other_value)
                    } else {
                        // Boundary and unknown parameter values are sensitive;
                        // quoting does not change a value's case semantics.
                        value == other_value
                    }
            }) else {
                return false;
            };
            unmatched.remove(index);
        }
        unmatched.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn pair(a: &str, b: &str, equal: bool) {
        let a: SipUri = a.parse().unwrap();
        let b: SipUri = b.parse().unwrap();
        assert!(a.compare(&a), "not reflexive: {a:?}");
        assert!(b.compare(&b), "not reflexive: {b:?}");
        assert_eq!(a.compare(&b), equal, "{a:?} vs {b:?}");
        assert_eq!(b.compare(&a), equal, "{b:?} vs {a:?}");
    }

    #[test]
    fn rfc3261_examples() {
        // Every equivalent pair in each set from section 19.1.4.
        let sets: &[&[&str]] = &[
            &[
                "sip:%61lice@atlanta.com;transport=TCP",
                "sip:alice@AtLanTa.CoM;Transport=tcp",
            ],
            &[
                "sip:carol@chicago.com",
                "sip:carol@chicago.com;newparam=5",
                "sip:carol@chicago.com;security=on",
            ],
            &[
                "sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com",
                "sip:biloxi.com;method=REGISTER;transport=tcp?to=sip:bob%40biloxi.com",
            ],
            &[
                "sip:alice@atlanta.com?subject=project%20x&priority=urgent",
                "sip:alice@atlanta.com?priority=urgent&subject=project%20x",
            ],
        ];
        for set in sets {
            for (i, a) in set.iter().enumerate() {
                for b in &set[i + 1..] {
                    pair(a, b, true);
                }
            }
        }
        for (a, b) in [
            (
                "SIP:ALICE@AtLanTa.CoM;Transport=udp",
                "sip:alice@AtLanTa.CoM;Transport=UDP",
            ),
            ("sip:bob@biloxi.com", "sip:bob@biloxi.com:5060"),
            ("sip:bob@biloxi.com", "sip:bob@biloxi.com;transport=udp"),
            (
                "sip:bob@biloxi.com",
                "sip:bob@biloxi.com:6000;transport=tcp",
            ),
            (
                "sip:carol@chicago.com",
                "sip:carol@chicago.com?Subject=next%20meeting",
            ),
            ("sip:bob@phone21.boxesbybob.com", "sip:bob@192.0.2.4"),
        ] {
            pair(a, b, false);
        }
    }

    #[test]
    fn extension_parameter_nontransitivity() {
        pair(
            "sip:carol@chicago.com",
            "sip:carol@chicago.com;security=on",
            true,
        );
        pair(
            "sip:carol@chicago.com",
            "sip:carol@chicago.com;security=off",
            true,
        );
        pair(
            "sip:carol@chicago.com;security=on",
            "sip:carol@chicago.com;security=off",
            false,
        );
    }

    #[test]
    fn components_and_parameters() {
        for (a, b, equal) in [
            ("sip:a@example.com", "sips:a@example.com", false),
            ("sip:a@example.com", "sip:example.com", false),
            ("sip:a@example.com", "sip:a:@example.com", false),
            (
                "sip:a:secret@example.com",
                "sip:a:Secret@example.com",
                false,
            ),
            (
                "sip:a:s%65cret@example.com",
                "sip:a:secret@example.com",
                true,
            ),
            ("sip:a:%3a@example.com", "sip:a:%3A@example.com", true),
            ("sip:a:%24@example.com", "sip:a:$@example.com", false),
            ("sip:a@EXAMPLE.com:5060", "sip:a@example.COM:5060", true),
            ("sip:a@[2001:db8::1]", "sip:a@[2001:0DB8:0:0:0:0:0:1]", true),
            (
                "sip:a@example.com;foo=one;bar=two",
                "sip:a@example.com;BAR=TWO;FOO=ONE",
                true,
            ),
            (
                "sip:a@example.com;foo=one",
                "sip:a@example.com;FOO=two",
                false,
            ),
            ("sip:a@example.com;foo", "sip:a@example.com;foo=", false),
            ("sip:a@example.com;lr", "sip:a@example.com", true),
            (
                "sip:a@example.com;transport=udp",
                "sip:a@example.com;transport=tcp",
                false,
            ),
            (
                "sip:a@example.com;method=REGISTER",
                "sip:a@example.com;method=register",
                false,
            ),
            (
                "sip:a@example.com;%66oo=%62ar",
                "sip:a@example.com;foo=bar",
                true,
            ),
            // A decoded percent sign is data, not a second escape to decode.
            ("sip:%2561@example.com", "sip:a@example.com", false),
            (
                "sip:a@example.com;foo=%2561",
                "sip:a@example.com;foo=a",
                false,
            ),
        ] {
            pair(a, b, equal);
        }
        for parameter in [
            "transport=udp",
            "user=ip",
            "ttl=1",
            "method=INVITE",
            "maddr=example.com",
        ] {
            pair(
                "sip:a@example.com",
                &format!("sip:a@example.com;{parameter}"),
                false,
            );
        }
    }

    #[test]
    fn embedded_header_semantics() {
        for (a, b, equal) in [
            ("subject=project%20x", "Subject=project%20y", false),
            ("subject=project%20x", "Subject=Project%20x", false),
            ("subject=project%20x", "s=project%20x", true),
            ("Priority=urgent", "priority=URGENT", true),
            (
                "Call-ID=ABC%40example.com",
                "call-id=abc%40example.com",
                false,
            ),
            ("Call-ID=ABC%40example.com", "i=ABC%40example.com", true),
            ("CSeq=001%20INVITE", "cseq=1%20INVITE", true),
            ("CSeq=1%20INVITE", "cseq=1%20invite", false),
            ("Expires=0060", "expires=60", true),
            ("Min-Expires=0060", "min-expires=60", true),
            ("Max-Forwards=070", "max-forwards=70", true),
            ("Content-Length=0010", "l=10", true),
            ("Content-Encoding=gzip", "e=GZIP", true),
            ("Content-Language=en", "content-language=EN", true),
            ("Require=foo%2C%20bar", "require=FOO%2CBAR", true),
            ("Supported=foo", "k=FOO", true),
            ("Unsupported=foo", "unsupported=FOO", true),
            ("Proxy-Require=foo", "proxy-require=FOO", true),
            ("Allow=INVITE", "allow=invite", false),
            ("to=sip:bob%40EXAMPLE.com", "To=sip:bob%40example.COM", true),
            (
                "to=sip:Bob%40example.com",
                "To=sip:bob%40example.com",
                false,
            ),
            (
                "to=Alice%20%3Csip:bob%40example.com%3E%3Btag%3DABC",
                "to=Bob%20%3Csip:bob%40EXAMPLE.com%3E%3Btag%3DABC",
                true,
            ),
            (
                "to=%3Csip:bob%40example.com%3E%3Btag%3DABC",
                "to=%3Csip:bob%40example.com%3E%3Btag%3Dabc",
                false,
            ),
            (
                "to=%3Csip:bob%40example.com%3E%3Btag%3DABC",
                "to=%3Csip:bob%40example.com%3E%3BTAG%3DABC",
                true,
            ),
            (
                "from=sip:bob%40example.com%3Bext%3Done",
                "from=sip:bob%40example.com%3Bext%3Dtwo",
                false,
            ),
            (
                "from=sip:bob%40example.com%3Bext%3Done",
                "from=sip:bob%40example.com",
                true,
            ),
            (
                "from=sip:bob%40example.com%3Btag%3DONE",
                "from=sip:bob%40example.com",
                false,
            ),
            ("x-custom=ABC", "X-Custom=abc", false),
            ("subject=%2561", "subject=a", false),
            (
                "subject=x&priority=urgent",
                "PRIORITY=URGENT&Subject=x",
                true,
            ),
            ("subject=x&subject=y", "subject=y&subject=x", true),
            ("subject=x&subject=x", "subject=x", false),
            ("subject=x&priority=urgent", "subject=x", false),
        ] {
            pair(
                &format!("sip:a@example.com?{a}"),
                &format!("sip:a@example.com?{b}"),
                equal,
            );
        }
    }

    #[test]
    fn quoted_from_to_extensions() {
        use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

        for name in ["From", "To"] {
            for (a, b, equal) in [
                ("<sip:b@host>;x=\"ABC\"", "<sip:b@host>;x=\"abc\"", false),
                ("<sip:b@host>;x=\"ABC\"", "<sip:b@host>;X=ABC", true),
                ("<sip:b@host>;x=\"ABC\"", "<sip:b@host>;x=abc", false),
                ("<sip:b@host>;x=ABC", "<sip:b@host>;X=abc", true),
                (
                    "\"Alice\" <sip:b@host>;x=ABC",
                    "\"Bob\" <sip:b@HOST>;x=abc",
                    true,
                ),
                (
                    "<sip:b@host>;x=\"A;B\";y=TOKEN",
                    "<sip:b@host>;Y=token;X=\"A;b\"",
                    false,
                ),
                ("<sip:b@host>;x=\"ABC\"", "<sip:b@host>;y=abc", true),
            ] {
                let uri = |value: &str| {
                    format!(
                        "sip:a@example.com?{name}={}",
                        utf8_percent_encode(value, NON_ALPHANUMERIC)
                    )
                };
                pair(&uri(a), &uri(b), equal);
            }
        }
    }

    #[test]
    fn repeated_list_headers() {
        for name in [
            "Supported",
            "Require",
            "Unsupported",
            "Proxy-Require",
            "Content-Language",
        ] {
            pair(
                &format!("sip:a@example.com?{name}=foo&Subject=x&{name}=bar"),
                &format!("sip:a@example.com?Subject=x&{name}=FOO%2CBAR"),
                true,
            );
        }
        for (a, b, equal) in [
            ("Supported=foo&k=bar", "Supported=BAR%2CFOO", true),
            (
                "Content-Encoding=gzip&e=compress",
                "e=gzip%2Ccompress",
                true,
            ),
            (
                "Content-Encoding=gzip&Content-Encoding=compress",
                "Content-Encoding=compress&Content-Encoding=gzip",
                false,
            ),
            (
                "Content-Encoding=gzip&Content-Encoding=compress",
                "Content-Encoding=compress%2Cgzip",
                false,
            ),
            (
                "e=gzip&Subject=x&e=compress",
                "Subject=x&Content-Encoding=GZIP%2CCOMPRESS",
                true,
            ),
        ] {
            pair(
                &format!("sip:a@example.com?{a}"),
                &format!("sip:a@example.com?{b}"),
                equal,
            );
        }
    }

    #[test]
    fn embedded_content_type_semantics() {
        use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

        for (a, b, equal) in [
            ("application/sdp", "APPLICATION/SDP", true),
            (
                " text / plain ; charset = \"utf-8\" ",
                "TEXT/PLAIN;CHARSET=UTF-8",
                true,
            ),
            (
                "text/plain; charset=UTF-8; format=flowed",
                "TEXT/PLAIN;FORMAT=flowed;CHARSET=utf-8",
                true,
            ),
            (
                "text/plain; charset=\"UTF-8\"",
                "text/plain;charset=utf-8",
                true,
            ),
            (
                "multipart/mixed; boundary=AbC; charset=UTF-8",
                "MULTIPART/MIXED;CHARSET=utf-8;BOUNDARY=\"AbC\"",
                true,
            ),
            (
                "multipart/mixed; boundary=AbC",
                "multipart/mixed;boundary=abc",
                false,
            ),
            (
                "multipart/mixed; boundary=\"AbC\"",
                "multipart/mixed;boundary=\"abc\"",
                false,
            ),
            (
                "multipart/mixed; boundary=\"a;b\";charset=UTF-8",
                "multipart/mixed;CHARSET=\"utf-8\";BOUNDARY=\"a;b\"",
                true,
            ),
            (
                "multipart/mixed; boundary=\"a\\\"b\"",
                "multipart/mixed;BOUNDARY=\"a\\\"b\"",
                true,
            ),
            (
                "multipart/mixed; boundary=\"a\\b\"",
                "multipart/mixed;boundary=ab",
                true,
            ),
            (
                "text/plain; x-value=\"AbC\"",
                "text/plain;X-VALUE=\"abc\"",
                false,
            ),
            (
                "text/plain; x-value=AbC",
                "text/plain;X-VALUE=\"AbC\"",
                true,
            ),
            ("text/plain;charset=utf-8", "text/html;charset=utf-8", false),
            (
                "text/plain;charset=utf-8",
                "text/plain;charset=us-ascii",
                false,
            ),
            ("text/plain;charset=utf-8", "text/plain", false),
            // Percent signs in MIME values are data, not another URI escape.
            (
                "multipart/mixed;boundary=%61",
                "multipart/mixed;boundary=a",
                false,
            ),
            // Malformed MIME falls back to exact text, not broad case-folding.
            (
                "text/plain;boundary=\"unterminated",
                "TEXT/PLAIN;boundary=\"unterminated",
                false,
            ),
        ] {
            let uri = |value: &str| {
                format!(
                    "sip:a@example.com?Content-Type={}",
                    utf8_percent_encode(value, NON_ALPHANUMERIC)
                )
            };
            pair(&uri(a), &uri(b), equal);
        }
        pair(
            "sip:a@example.com?c=APPLICATION/SDP",
            "sip:a@example.com?Content-Type=application/sdp",
            true,
        );
    }

    #[test]
    fn embedded_option_tag_order_and_ordered_encodings() {
        for name in ["Supported", "Require", "Unsupported", "Proxy-Require"] {
            pair(
                &format!("sip:a@example.com?{name}=foo%2C%20bar"),
                &format!("sip:a@example.com?{name}=BAR%2CFOO"),
                true,
            );
            pair(
                &format!("sip:a@example.com?{name}=foo%2Cbar"),
                &format!("sip:a@example.com?{name}=foo%2Cbaz"),
                false,
            );
        }
        pair(
            "sip:a@example.com?k=foo%2Cbar",
            "sip:a@example.com?Supported=BAR%2CFOO",
            true,
        );
        pair(
            "sip:a@example.com?Content-Encoding=gzip%2Ccompress",
            "sip:a@example.com?e=GZIP%2C%20COMPRESS",
            true,
        );
        pair(
            "sip:a@example.com?Content-Encoding=gzip%2Ccompress",
            "sip:a@example.com?Content-Encoding=compress%2Cgzip",
            false,
        );
    }
}
