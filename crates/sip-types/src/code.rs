use std::fmt;
use std::str::FromStr;

type Repr = u16;

/// Code is a representation of an SIP-Code encoded in an u16
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Code(Repr);

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tuple = f.debug_tuple("Code");
        tuple.field(&self.0);
        if let Some(text) = self.text() {
            tuple.field(&text);
        }
        tuple.finish()
    }
}

/// CodeKind represents the kind of SIP-Code for broader Code handling
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CodeKind {
    /// Represents code 100..=199
    Provisional,

    /// Represents code 200..=299
    Success,

    /// Represents code 300..=399
    Redirection,

    /// Represents code 400..=499
    RequestFailure,

    /// Represents code 500..=599
    ServerFailure,

    /// Represents code 600..=699
    GlobalFailure,

    /// Represents all other codes
    Custom,
}

impl Code {
    /// Returns the [CodeKind] of the code
    ///
    /// # Example
    ///
    /// ```
    /// use ezk_sip_types::Code;
    /// use ezk_sip_types::CodeKind;
    ///
    /// let code = Code::from(200);
    ///
    /// assert_eq!(code.kind(), CodeKind::Success);
    /// ```
    #[inline]
    pub fn kind(self) -> CodeKind {
        match self.0 {
            100..=199 => CodeKind::Provisional,
            200..=299 => CodeKind::Success,
            300..=399 => CodeKind::Redirection,
            400..=499 => CodeKind::RequestFailure,
            500..=599 => CodeKind::ServerFailure,
            600..=699 => CodeKind::GlobalFailure,
            _ => CodeKind::Custom,
        }
    }

    /// Returns the number that the code represents
    pub fn into_u16(self) -> Repr {
        self.0
    }
}

impl FromStr for Code {
    type Err = <Repr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Code(Repr::from_str(s)?))
    }
}

impl From<Repr> for Code {
    fn from(r: Repr) -> Code {
        Code(r)
    }
}

macro_rules! codes {
    ($($(#[$comments:meta])* [$code:expr => $name:ident, $text:literal];)*) => {
        impl Code {
            /// Returns the default response-text for a known Code
            pub fn text(self) -> Option<&'static str> {
                match self.0 {
                    $($code => Some($text),)*
                    _ => None
                }
            }

            $(
            $(#[$comments])*
            pub const $name: Code = Code($code);
            )*
        }
    };
}

codes! {
    // ==== PROVISIONAL 1XX ====

    /// [[RFC3621, Section 21.1.1](https://tools.ietf.org/html/rfc3261#section-21.1.1)]
    /// 100 Trying
    [100 => TRYING, "Trying"];

    /// [[RFC3621, Section 21.1.2](https://tools.ietf.org/html/rfc3261#section-21.1.2)]
    /// 180 Ringing
    [180 => RINGING, "Ringing"];

    /// [[RFC3621, Section 21.1.3](https://tools.ietf.org/html/rfc3261#section-21.1.3)]
    /// 181 Call Is Being Forwarded
    [181 => CALL_IS_BEING_FORWARDED, "Call Is Being Forwarded"];

    /// [[RFC3621, Section 21.1.4](https://tools.ietf.org/html/rfc3261#section-21.1.4)]
    /// 182 Queued
    [182 => QUEUED, "Queued"];

    /// [[RFC3621, Section 21.1.5](https://tools.ietf.org/html/rfc3261#section-21.1.5)]
    /// 183 Session Progress
    [183 => SESSION_PROGRESS, "Session Progress"];

    /// [[RFC6228](https://tools.ietf.org/html/rfc6228)]
    /// 199 Early Dialog Terminated
    [199 => EARLY_DIALOG_TERMINATED, "Early Dialog Terminated"];

    // ==== SUCCESS 2XX ====

    /// [[RFC3621, Section 21.2.1](https://tools.ietf.org/html/rfc3261#section-21.2.1)]
    /// 200 OK
    [200 => OK, "OK"];

    // ==== REDIRECTION 3XX ====

    /// [[RFC3621, Section 21.3.1](https://tools.ietf.org/html/rfc3261#section-21.3.1)]
    /// 300 Multiple Choices
    [300 => MULTIPLE_CHOICES, "Multiple Choices"];

    /// [[RFC3621, Section 21.3.2](https://tools.ietf.org/html/rfc3261#section-21.3.2)]
    /// 301 Moved Permanently
    [301 => MOVED_PERMANENTLY, "Moved Permanently"];

    /// [[RFC3621, Section 21.3.3](https://tools.ietf.org/html/rfc3261#section-21.3.3)]
    /// 302 Moved Temporarily
    [302 => MOVED_TEMPORARILY, "Moved Temporarily"];

    /// [[RFC3621, Section 21.3.4](https://tools.ietf.org/html/rfc3261#section-21.3.4)]
    /// 302 Use Proxy
    [305 => USE_PROXY, "Use Proxy"];

    /// [[RFC3621, Section 21.3.5](https://tools.ietf.org/html/rfc3261#section-21.3.5)]
    /// 380 Alternative Service
    [380 => ALTERNATIVE_SERVICE, "Alternative Service"];

    // ==== REQUEST FAILURE 4XX ====

    /// [[RFC3621, Section 21.4.1](https://tools.ietf.org/html/rfc3261#section-21.4.1)]
    /// 400 Bad Request
    [400 => BAD_REQUEST, "Bad Request"];

    /// [[RFC3621, Section 21.4.2](https://tools.ietf.org/html/rfc3261#section-21.4.2)]
    /// 401 Unauthorized
    [401 => UNAUTHORIZED, "Unauthorized"];

    /// [[RFC3621, Section 21.4.3](https://tools.ietf.org/html/rfc3261#section-21.4.3)]
    /// 402 Payment Required
    [402 => PAYMENT_REQUIRED, "Payment Required"];

    /// [[RFC3621, Section 21.4.4](https://tools.ietf.org/html/rfc3261#section-21.4.4)]
    /// 403 Forbidden
    [403 => FORBIDDEN, "Forbidden"];

    /// [[RFC3621, Section 21.4.5](https://tools.ietf.org/html/rfc3261#section-21.4.5)]
    /// 404 Not Found
    [404 => NOT_FOUND, "Not Found"];

    /// [[RFC3621, Section 21.4.6](https://tools.ietf.org/html/rfc3261#section-21.4.6)]
    /// 405 Method Not Allowed
    [405 => METHOD_NOT_ALLOWED, "Method Not Allowed"];

    /// [[RFC3621, Section 21.4.7](https://tools.ietf.org/html/rfc3261#section-21.4.7)]
    /// 406 Not Acceptable
    [406 => NOT_ACCEPTABLE, "Not Acceptable"];

    /// [[RFC3621, Section 21.4.8](https://tools.ietf.org/html/rfc3261#section-21.4.8)]
    /// 407 Proxy Authentication Required
    [407 => PROXY_AUTHENTICATION_REQUIRED, "Proxy Authentication Required"];

    /// [[RFC3621, Section 21.4.9](https://tools.ietf.org/html/rfc3261#section-21.4.9)]
    /// 408 Request Timeout
    [408 => REQUEST_TIMEOUT, "Request Timeout"];

    /// [[RFC3621, Section 21.4.10](https://tools.ietf.org/html/rfc3261#section-21.4.10)]
    /// 410 Gone
    [410 => GONE, "Gone"];

    /// [[RFC3621, Section 21.4.11](https://tools.ietf.org/html/rfc3261#section-21.4.11)]
    /// 413 Request Entity Too Large
    [413 => REQUEST_ENTITY_TOO_LARGE, "Request Entity Too Large"];

    /// [[RFC3621, Section 21.4.12](https://tools.ietf.org/html/rfc3261#section-21.4.12)]
    /// 414 Request-URI Too Long
    [414 => REQUEST_URI_TOO_LONG, "Request-URI Too Long"];

    /// [[RFC3621, Section 21.4.13](https://tools.ietf.org/html/rfc3261#section-21.4.13)]
    /// 415 Unsupported Media Type
    [415 => UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type"];

    /// [[RFC3621, Section 21.4.14](https://tools.ietf.org/html/rfc3261#section-21.4.14)]
    /// 416 Unsupported URI Scheme
    [416 => UNSUPPORTED_URI_SCHEME, "Unsupported URI Scheme"];

    /// [[RFC3621, Section 21.4.15](https://tools.ietf.org/html/rfc3261#section-21.4.15)]
    /// 420 Bad Extension
    [420 => BAD_EXTENSION, "Bad Extension"];

    /// [[RFC3621, Section 21.4.16](https://tools.ietf.org/html/rfc3261#section-21.4.16)]
    /// 421 Extension Required
    [421 => EXTENSION_REQUIRED, "Extension Required"];

    /// [[RFC4028, Section 6](https://datatracker.ietf.org/doc/html/rfc4028#section-6)]
    /// 422 Session Interval Too Small
    [422 => SESSION_INTERVAL_TOO_SMALL, "Session Interval Too Small"];

    /// [[RFC3621, Section 21.4.17](https://tools.ietf.org/html/rfc3261#section-21.4.17)]
    /// 423 Interval Too Brief
    [423 => INTERVAL_TOO_BRIEF, "Interval Too Brief"];

    /// [[RFC3621, Section 21.4.18](https://tools.ietf.org/html/rfc3261#section-21.4.18)]
    /// 480 Temporarily Unavailable
    [480 => TEMPORARILY_UNAVAILABLE, "Temporarily Unavailable"];

    /// [[RFC3621, Section 21.4.19](https://tools.ietf.org/html/rfc3261#section-21.4.19)]
    /// 481 Call/Transaction Does Not Exist
    [481 => CALL_OR_TRANSACTION_DOES_NOT_EXIST, "Call/Transaction Does Not Exist"];

    /// [[RFC3621, Section 21.4.20](https://tools.ietf.org/html/rfc3261#section-21.4.20)]
    /// 482 Loop Detected
    [482 => LOOP_DETECTED, "Loop Detected"];

    /// [[RFC3621, Section 21.4.21](https://tools.ietf.org/html/rfc3261#section-21.4.21)]
    /// 483 Too Many Hops
    [483 => TOO_MANY_HOPS, "Too Many Hops"];

    /// [[RFC3621, Section 21.4.22](https://tools.ietf.org/html/rfc3261#section-21.4.22)]
    /// 484 Address Incomplete
    [484 => ADDRESS_INCOMPLETE, "Address Incomplete"];

    /// [[RFC3621, Section 21.4.23](https://tools.ietf.org/html/rfc3261#section-21.4.23)]
    /// 485 Ambiguous
    [485 => AMBIGUOUS, "Ambiguous"];

    /// [[RFC3621, Section 21.4.24](https://tools.ietf.org/html/rfc3261#section-21.4.24)]
    /// 486 Busy Here
    [486 => BUSY_HERE, "Busy Here"];

    /// [[RFC3621, Section 21.4.25](https://tools.ietf.org/html/rfc3261#section-21.4.25)]
    /// 487 Request Terminated
    [487 => REQUEST_TERMINATED, "Request Terminated"];

    /// [[RFC3621, Section 21.4.26](https://tools.ietf.org/html/rfc3261#section-21.4.26)]
    /// 488 Not Acceptable Here
    [488 => NOT_ACCEPTABLE_HERE, "Not Acceptable Here"];

    /// [[RFC3621, Section 21.4.27](https://tools.ietf.org/html/rfc3261#section-21.4.27)]
    /// 491 Request Pending
    [491 => REQUEST_PENDING, "Request Pending"];

    /// [[RFC3621, Section 21.4.28](https://tools.ietf.org/html/rfc3261#section-21.4.28)]
    /// 493 Undecipherable
    [493 => UNDECIPHERABLE, "Undecipherable"];

    // ==== SERVER FAILURE 5XX ====

    /// [[RFC3621, Section 21.5.1](https://tools.ietf.org/html/rfc3261#section-21.5.1)]
    /// 500 Server Internal Error
    [500 => SERVER_INTERNAL_ERROR, "Server Internal Error"];

    /// [[RFC3621, Section 21.5.2](https://tools.ietf.org/html/rfc3261#section-21.5.2)]
    /// 501 Not Implemented
    [501 => NOT_IMPLMENTED, "Not Implemented"];

    /// [[RFC3621, Section 21.5.3](https://tools.ietf.org/html/rfc3261#section-21.5.3)]
    /// 502 Bad Gateway
    [502 => BAD_GATEWAY, "Bad Gateway"];

    /// [[RFC3621, Section 21.5.4](https://tools.ietf.org/html/rfc3261#section-21.5.4)]
    /// 503 Service Unavailable
    [503 => SERVICE_UNAVAILABLE, "Service Unavailable"];

    /// [[RFC3621, Section 21.5.5](https://tools.ietf.org/html/rfc3261#section-21.5.5)]
    /// 504 Server Time-out
    [504 => SERVER_TIMEOUT, "Server Time-out"];

    /// [[RFC3621, Section 21.5.6](https://tools.ietf.org/html/rfc3261#section-21.5.6)]
    /// 505 Version Not Supported
    [505 => VERSION_NOT_SUPPORTED, "Version Not Supported"];

    /// [[RFC3621, Section 21.5.7](https://tools.ietf.org/html/rfc3261#section-21.5.7)]
    /// 513 Message Too Large
    [513 => MESSAGE_TOO_LARGE, "Message Too Large"];

    // ==== GLOBAL FAILURE 6XX ====

    /// [[RFC3621, Section 21.6.1](https://tools.ietf.org/html/rfc3261#section-21.6.1)]
    /// 600 Busy Everywhere
    [600 => BUSY_EVERYWHERE, "Busy Everywhere"];

    /// [[RFC3621, Section 21.6.2](https://tools.ietf.org/html/rfc3261#section-21.6.2)]
    /// 603 Decline
    [603 => DECLINE, "Decline"];

    /// [[RFC3621, Section 21.6.3](https://tools.ietf.org/html/rfc3261#section-21.6.3)]
    /// 604 Does Not Exist Anywhere
    [604 => DOES_NOT_EXIST_ANYWHERE, "Does Not Exist Anywhere"];

    /// [[RFC3621, Section 21.6.4](https://tools.ietf.org/html/rfc3261#section-21.6.4)]
    /// 606 Not Acceptable
    [606 => NOT_ACCEPTABLE6, "Not Acceptable"];
}
