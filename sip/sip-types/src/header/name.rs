use bytesstr::BytesStr;

/// Represents a SIP-Header's name. It is used as key inside [Headers].
///
/// [Headers]: crate::Headers
#[derive(Debug, Clone)]
pub struct Name(Repr);

impl Name {
    /// Creates a new custom Name that is not implemented as constant.
    ///
    /// This function takes 2 parameters;
    ///
    /// - `name`: a string which would be the printed version of the Name.
    /// - `parse_strs`: A list of strings that are case-insensitively matched against names inside a message.
    ///
    /// A custom Name should only be used for lookups, to insert an unimplemented Name into a map
    /// use [Name::unknown].
    pub const fn custom(name: &'static str, parse_strs: &'static [&'static str]) -> Self {
        Self(Repr::Custom(BytesStr::from_static(name), parse_strs))
    }

    /// Returns a Name which contains the name
    ///
    /// This function will be called by parsers when they
    /// encounter a name not implemented by this library.
    pub const fn unknown(name: BytesStr) -> Self {
        Self(Repr::Unknown(name))
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        let other_print_str = other.as_print_str();

        if self == other_print_str {
            return true;
        }

        other
            .as_parse_strs()
            .map(|strs| strs.iter().any(|&str| self.eq(str)))
            .unwrap_or_default()
    }
}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        if self.as_print_str().eq_ignore_ascii_case(other) {
            return true;
        }

        self.as_parse_strs()
            .map(|strs| strs.iter().any(|str| str.eq_ignore_ascii_case(other)))
            .unwrap_or_default()
    }
}

impl<T> From<T> for Name
where
    T: Into<BytesStr> + AsRef<[u8]>,
{
    fn from(name: T) -> Self {
        Name::from_bytes(name)
    }
}

macro_rules! header_names {
    ($($(#[$comments:meta])* $print:literal, $ident:ident, [$($parse:literal),+], $konst:ident;)+) => {
        #[derive(Debug, Clone)]
        enum Repr {
            $($ident,)+
            Unknown(BytesStr),
            Custom(BytesStr, &'static [&'static str]),
        }

        static NAMES: &[(&'static str, Name)] = &[
            $($( ($parse, Name::$konst), )*)*
        ];

        impl Name {
            $(
            $(#[$comments])*
            pub const $konst: Name = Name(Repr::$ident);
            )+

            fn from_bytes(name: impl Into<BytesStr> + AsRef<[u8]>) -> Name {
                let slice: &[u8] = name.as_ref();

                for (parse, name) in NAMES {
                    if parse.as_bytes().eq_ignore_ascii_case(&slice) {
                        return name.clone();
                    }
                }

                Name::unknown(name.into())
            }

            pub fn as_print_str(&self) -> &str {
                match &self.0 {
                    $(Repr::$ident => $print . as_ref(),)*
                    Repr::Unknown(name) => name.as_ref(),
                    Repr::Custom(name, _) => name.as_ref(),
                }
            }

            pub const fn as_parse_strs(&self) -> Option<&[&str]> {
                match &self.0 {
                    $(
                    Repr::$ident => Some(&[$($parse),*]),
                    )+
                    Repr::Unknown(_) => None,
                    Repr::Custom(_, parse_strs) => Some(parse_strs),
                }
            }
        }
    };
}

header_names! {
    /// [[RFC3621, Section 20.1](https://tools.ietf.org/html/rfc3261#section-20.1)]
    "Accept",               Accept,             ["accept"],                 ACCEPT;

    /// [[RFC3621, Section 20.2](https://tools.ietf.org/html/rfc3261#section-20.2)]
    "Accept-Encoding",      AcceptEncoding,     ["accept-encoding"],        ACCEPT_ENCODING;

    /// [[RFC3621, Section 20.3](https://tools.ietf.org/html/rfc3261#section-20.3)]
    "Accept-Language",      AcceptLanguage,     ["accept-language"],        ACCEPT_LANGUAGE;

    /// [[RFC3621, Section 20.4](https://tools.ietf.org/html/rfc3261#section-20.4)]
    "Alert-Info",           AlertInfo,          ["alert-info"],             ALERT_INFO;

    /// [[RFC3621, Section 20.5](https://tools.ietf.org/html/rfc3261#section-20.5)]
    "Allow",                Allow,              ["allow"],                  ALLOW;

    /// [[RFC6665, Section 8.2.2](https://datatracker.ietf.org/doc/html/rfc6665#section-8.2.2)])]
    "Allow-Events",         AllowEvents,        ["allow-events", "u"],      ALLOW_EVENTS;

    /// [[RFC3621, Section 20.6](https://tools.ietf.org/html/rfc3261#section-20.6)]
    "Authentication-Info",  AuthenticationInfo, ["authentication-info"],    AUTHENTICATION_INFO;

    /// [[RFC3621, Section 20.7](https://tools.ietf.org/html/rfc3261#section-20.7)]
    "Authorization",        Authorization,      ["authorization"],          AUTHORIZATION;

    /// [[RFC3621, Section 20.8](https://tools.ietf.org/html/rfc3261#section-20.8)]
    "Call-ID",              CallID,             ["call-id", "i"],           CALL_ID;

    /// [[RFC3621, Section 20.9](https://tools.ietf.org/html/rfc3261#section-20.9)]
    "Call-Info",            CallInfo,           ["call-info"],              CALL_INFO;

    /// [[RFC3621, Section 20.10](https://tools.ietf.org/html/rfc3261#section-20.10)]
    "Contact",              Contact,            ["contact", "m"],           CONTACT;

    /// [[RFC3621, Section 20.11](https://tools.ietf.org/html/rfc3261#section-20.11)]
    "Content-Disposition",  ContentDisposition, ["content-disposition"],    CONTENT_DISPOSITION;

    /// [[RFC3621, Section 20.12](https://tools.ietf.org/html/rfc3261#section-20.12)]
    "Content-Encoding",     ContentEncoding,    ["content-encoding", "e"],  CONTENT_ENCODING;

    /// [[RFC3621, Section 20.13](https://tools.ietf.org/html/rfc3261#section-20.13)]
    "Content-Language",     ContentLanguage,    ["content-language"],       CONTENT_LANGUAGE;

    /// [[RFC3621, Section 20.14](https://tools.ietf.org/html/rfc3261#section-20.14)]
    "Content-Length",       ContentLength,      ["content-length", "l"],    CONTENT_LENGTH;

    /// [[RFC3621, Section 20.15](https://tools.ietf.org/html/rfc3261#section-20.15)]
    "Content-Type",         ContentType,        ["content-type", "c"],      CONTENT_TYPE;

    /// [[RFC3621, Section 20.16](https://tools.ietf.org/html/rfc3261#section-20.16)]
    "CSeq",                 CSeq,               ["cseq"],                   CSEQ;

    /// [[RFC3621, Section 20.17](https://tools.ietf.org/html/rfc3261#section-20.17)]
    "Date",                 Date,               ["date"],                   DATE;

    /// [[RFC3621, Section 20.18](https://tools.ietf.org/html/rfc3261#section-20.18)]
    "Error-Info",           ErrorInfo,          ["error-info"],             ERROR_INFO;

    /// [[RFC6665, Section 8.2.1](https://datatracker.ietf.org/doc/html/rfc6665#section-8.2.1)]
    "Event",                Event,              ["event", "o"],             EVENT;

    /// [[RFC3621, Section 20.19](https://tools.ietf.org/html/rfc3261#section-20.19)]
    "Expires",              Expires,            ["expires"],                EXPIRES;

    /// [[RFC3621, Section 20.20](https://tools.ietf.org/html/rfc3261#section-20.20)]
    "From",                 From,               ["from", "f"],              FROM;

    /// [[RFC3621, Section 20.21](https://tools.ietf.org/html/rfc3261#section-20.21)]
    "In-Reply-To",          InReplyTo,          ["in-reply-to"],            IN_REPLY_TO;

    /// [[RFC3621, Section 20.22](https://tools.ietf.org/html/rfc3261#section-20.22)]
    "Max-Forwards",         MaxForwards,        ["max-forwards"],           MAX_FORWARDS;

    /// [[RFC3621, Section 20.23](https://tools.ietf.org/html/rfc3261#section-20.23)]
    "Min-Expires",          MinExpires,         ["min-expires"],            MIN_EXPIRES;

    /// [[RFC4028, Section 20.23](https://datatracker.ietf.org/doc/html/rfc4028#section-5)]
    "Min-SE",               MinSe,              ["min-se"],                 MIN_SE;

    /// [[RFC3621, Section 20.24](https://tools.ietf.org/html/rfc3261#section-20.24)]
    "MIME-Version",         MIMEVersion,        ["mime-version"],           MIME_VERSION;

    /// [[RFC3621, Section 20.25](https://tools.ietf.org/html/rfc3261#section-20.25)]
    "Organization",         Organization,       ["organization"],           ORGANIZATION;

    /// [[RFC7315, Section 4.1](https://datatracker.ietf.org/doc/html/rfc7315#section-4.1)]
    "P-Associated-URI",     PAssociatedURI,     ["p-associated-uri"],       P_ASSOCIATED_URI;

    /// [[RFC7315, Section 4.2](https://datatracker.ietf.org/doc/html/rfc7315#section-4.2)]
    "P-Called-Party-ID",   PCalledPartyID,     ["p-called-party-id"],      P_CALLED_PARTY_ID;

    /// [[RFC7315, Section 4.3](https://datatracker.ietf.org/doc/html/rfc7315#section-4.3)]
    "P-Visited-Network-ID", PVisitedNetworkID, ["p-visited-network-id"],   P_VISITED_NETWORK_ID;

    /// [[RFC7315, Section 4.4](https://datatracker.ietf.org/doc/html/rfc7315#section-4.4)]
    "P-Access-Network-Info", PAccessNetworkInfo, ["p-access-network-info"], P_ACCESS_NETWORK_INFO;

    /// [[RFC7315, Section 4.5](https://datatracker.ietf.org/doc/html/rfc7315#section-4.5)]
    "P-Charging-Function-Addresses", PChargingFunctionAddresses, ["p-charging-function-addresses"], P_CHARGING_FUNCTION_ADDRESSES;

    /// [[RFC7315, Section 4.6](https://datatracker.ietf.org/doc/html/rfc7315#section-4.6)]
    "P-Charging-Vector", PChargingVector, ["p-charging-vector"], P_CHARGING_VECTOR;

    /// [[RFC3621, Section 20.26](https://tools.ietf.org/html/rfc3261#section-20.26)]
    "Priority",             Priority,           ["priority"],               PRIORITY;

    /// [[RFC3621, Section 20.27](https://tools.ietf.org/html/rfc3261#section-20.27)]
    "Proxy-Authenticate",   ProxyAuthenticate,  ["proxy-authenticate"],     PROXY_AUTHENTICATE;

    /// [[RFC3621, Section 20.28](https://tools.ietf.org/html/rfc3261#section-20.28)]
    "Proxy-Authorization",  ProxyAuthorization, ["proxy-authorization"],    PROXY_AUTHORIZATION;

    /// [[RFC3621, Section 20.29](https://tools.ietf.org/html/rfc3261#section-20.29)]
    "Proxy-Require",        ProxyRequire,       ["proxy-require"],          PROXY_REQUIRE;

     /// [[RFC3262, Section 20.34](https://datatracker.ietf.org/doc/html/rfc3262#section-7.2)]
    "RAck",                 RAck,               ["rack"],                   RACK;

    /// [[RFC3621, Section 20.30](https://tools.ietf.org/html/rfc3261#section-20.30)]
    "Record-Route",         RecordRoute,        ["record-route"],           RECORD_ROUTE;

    /// [[RFC3515, Section 2.1](https://www.rfc-editor.org/rfc/rfc3515#section-2.1)]
    "Refer-To",             ReferTo,            ["refer-to", "r"],          REFER_TO;

    /// [[RFC3891, Section 6.1](https://datatracker.ietf.org/doc/html/rfc3891#section-6.1)]
    "Replaces",             Replaces,           ["replaces"],               REPLACES;

    /// [[RFC3621, Section 20.31](https://tools.ietf.org/html/rfc3261#section-20.31)]
    "Reply-To",             ReplyTo,            ["reply-to"],               REPLY_TO;

    /// [[RFC3621, Section 20.32](https://tools.ietf.org/html/rfc3261#section-20.32)]
    "Require",              Require,            ["require"],                REQUIRE;

    /// [[RFC3621, Section 20.33](https://tools.ietf.org/html/rfc3261#section-20.33)]
    "Retry-After",          RetryAfter,         ["retry-after"],            RETRY_AFTER;

    /// [[RFC3621, Section 20.34](https://tools.ietf.org/html/rfc3261#section-20.34)]
    "Route",                Route,              ["route"],                  ROUTE;

    /// [[RFC3262, Section 20.34](https://datatracker.ietf.org/doc/html/rfc3262#section-7.1)]
    "RSeq",                 RSeq,               ["rseq"],                   RSEQ;

    /// [[RFC3329, Section 2.6](https://datatracker.ietf.org/doc/html/rfc3329#section-2.6)]
    "Security-Client",      SecurityClient,     ["security-client"],        SECURITY_CLIENT;

    /// [[RFC3329, Section 2.6](https://datatracker.ietf.org/doc/html/rfc3329#section-2.6)]
    "Security-Server",      SecurityServer,     ["security-server"],        SECURITY_SERVER;

    /// [[RFC3329, Section 2.6](https://datatracker.ietf.org/doc/html/rfc3329#section-2.6)]
    "Security-Verify",      SecurityVerify,     ["security-verify"],        SECURITY_VERIFY;

    /// [[RFC3621, Section 20.35](https://tools.ietf.org/html/rfc3261#section-20.35)]
    "Server",               Server,             ["server"],                 SERVER;

    /// [[RFC4028, Section 20.35](https://datatracker.ietf.org/doc/html/rfc4028#section-4)]
    "Session-Expires",      SessionExpires,     ["session-expires", "x"],        SESSION_EXPIRES;

    /// [[RFC3621, Section 20.36](https://tools.ietf.org/html/rfc3261#section-20.36)]
    "Subject",              Subject,            ["subject", "s"],           SUBJECT;

    /// [[RFC6665, Section 8.2.3](https://datatracker.ietf.org/doc/html/rfc6665#section-8.2.3)]
    "Subscription-State",   SubscriptionState,  ["subscription-state"],     SUBSCRIPTION_STATE;

    /// [[RFC3621, Section 20.37](https://tools.ietf.org/html/rfc3261#section-20.37)]
    "Supported",            Supported,          ["supported", "k"],         SUPPORTED;

    /// [[RFC3621, Section 20.38](https://tools.ietf.org/html/rfc3261#section-20.38)]
    "Timestamp",            Timestamp,          ["timestamp"],              TIMESTAMP;

    /// [[RFC3621, Section 20.39](https://tools.ietf.org/html/rfc3261#section-20.39)]
    "To",                   To,                 ["to", "t"],                TO;

    /// [[RFC3621, Section 20.40](https://tools.ietf.org/html/rfc3261#section-20.40)]
    "Unsupported",          Unsupported,        ["unsupported"],            UNSUPPORTED;

    /// [[RFC3621, Section 20.41](https://tools.ietf.org/html/rfc3261#section-20.41)]
    "User-Agent",           UserAgent,          ["user-agent"],             USER_AGENT;

    /// [[RFC3621, Section 20.42](https://tools.ietf.org/html/rfc3261#section-20.42)]
    "Via",                  Via,                ["via", "v"],               VIA;

    /// [[RFC3621, Section 20.43](https://tools.ietf.org/html/rfc3261#section-20.43)]
    "Warning",              Warning,            ["warning"],                WARNING;

    /// [[RFC3621, Section 20.44](https://tools.ietf.org/html/rfc3261#section-20.44)]
    "WWW-Authenticate",     WWWAuthenticate,    ["www-authenticate"],       WWW_AUTHENTICATE;
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! test_eq {
        ($name1:expr; $name2:expr;) => {{
            let name1 = $name1;
            let name2 = $name2;

            assert_eq!(name1, name2);
            assert_eq!(name2, name1);
        }};
    }

    #[test]
    fn test_eq() {
        test_eq! {
            Name::VIA;
            Name::unknown(BytesStr::from_static("Via"));
        }

        test_eq! {
            Name::VIA;
            Name::custom("v", &["via", "v"]);
        }

        test_eq! {
            Name::unknown(BytesStr::from_static("v"));
            Name::custom("Via", &["via", "v"]);
        }
    }
}
