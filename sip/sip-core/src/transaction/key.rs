use super::consts::RFC3261_BRANCH_PREFIX;
use super::generate_branch;
use crate::BaseHeaders;
use bytesstr::BytesStr;
use sip_types::header::HeaderError;
use sip_types::header::typed::{CSeq, Via};
use sip_types::host::HostPort;
use sip_types::msg::MessageLine;
use sip_types::{Method, Name};
use std::fmt;

static EMPTY: BytesStr = BytesStr::empty();

/// Transaction key, used to match a message to an ongoing transaction
///
/// Can be generated new or created from an incoming message.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TsxKey(Repr);

impl fmt::Display for TsxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_server() {
            write!(f, "server:")?;
        } else {
            write!(f, "client:")?;
        }

        let method = match &self.0 {
            Repr::RFC3261(repr) => repr.method.as_ref().unwrap_or(&Method::INVITE),
            Repr::RFC2543(repr) => repr.method.as_ref().unwrap_or(&Method::INVITE),
        };

        write!(f, "{}:{}", self.branch(), method)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum Repr {
    RFC3261(Rfc3261),
    RFC2543(Box<Rfc2543>),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Rfc2543 {
    role: Role,
    method: Option<Method>,
    cseq: u32,
    from_tag: BytesStr,
    call_id: BytesStr,
    via_host_port: HostPort,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Rfc3261 {
    role: Role,
    branch: BytesStr,
    method: Option<Method>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum Role {
    Server,
    Client,
}

// invite and ack are represented as None
// to match transaction-level ACK-requests to invite transactions
fn filter_method(method: &Method) -> Option<Method> {
    Some(method)
        .filter(|&m| !(matches!(m, &Method::INVITE | &Method::ACK)))
        .cloned()
}

impl TsxKey {
    #[inline]
    pub fn is_server(&self) -> bool {
        match &self.0 {
            Repr::RFC3261(rfc) => rfc.role == Role::Server,
            Repr::RFC2543(rfc) => rfc.role == Role::Server,
        }
    }

    #[inline]
    pub fn is_invite(&self) -> bool {
        match &self.0 {
            Repr::RFC3261(rfc) => rfc.method.is_none(),
            Repr::RFC2543(rfc) => rfc.method.is_none(),
        }
    }

    #[inline]
    pub fn client(method: &Method) -> Self {
        TsxKey(Repr::RFC3261(Rfc3261 {
            role: Role::Client,
            branch: generate_branch(),
            method: filter_method(method),
        }))
    }

    #[inline]
    pub fn branch(&self) -> &BytesStr {
        match &self.0 {
            Repr::RFC3261(v) => &v.branch,
            Repr::RFC2543(_) => &EMPTY,
        }
    }

    fn from_headers(headers: &BaseHeaders, role: Role) -> Result<Self, HeaderError> {
        let Via {
            sent_by, params, ..
        } = &headers.via[0];

        let branch = params.get_val_ignore_ascii_case("branch").unwrap_or(&EMPTY);

        let CSeq { method, cseq } = &headers.cseq;
        let method = filter_method(method);

        let repr = if branch.starts_with(RFC3261_BRANCH_PREFIX) {
            Repr::RFC3261(Rfc3261 {
                role,
                branch: branch.clone(),
                method,
            })
        } else {
            Repr::RFC2543(Box::new(Rfc2543 {
                role,
                method,
                cseq: *cseq,
                from_tag: headers
                    .from
                    .tag
                    .as_ref()
                    .ok_or_else(|| HeaderError::malformed_adhoc(Name::FROM, "Missing Tag"))?
                    .clone(),
                call_id: headers.call_id.0.clone(),
                via_host_port: sent_by.clone(),
            }))
        };

        Ok(TsxKey(repr))
    }

    /// Create a [`TsxKey`] from the line and headers of any message
    #[inline]
    pub fn from_message_parts(
        line: &MessageLine,
        headers: &BaseHeaders,
    ) -> Result<Self, HeaderError> {
        match &line {
            MessageLine::Request(_) => Self::from_headers(headers, Role::Server),
            MessageLine::Response(_) => Self::from_headers(headers, Role::Client),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_types::Headers;

    #[test]
    fn branch_name_ignores_case_but_branch_value_does_not() {
        let key = |name: &str, value: &str| {
            let mut headers = Headers::new();
            headers.insert(Name::VIA, format!("SIP/2.0/UDP 127.0.0.1;{name}={value}"));
            headers.insert(Name::FROM, "<sip:alice@example.com>;TaG=AbC");
            headers.insert(Name::TO, "<sip:bob@example.com>");
            headers.insert(Name::CALL_ID, "CallID");
            headers.insert(Name::CSEQ, "1 INVITE");
            let headers = BaseHeaders::extract_from(&headers).unwrap();
            TsxKey::from_headers(&headers, Role::Server).unwrap()
        };
        let lower = key("branch", "z9hG4bK-AbC");
        let mixed = key("BrAnCh", "z9hG4bK-AbC");
        assert_eq!(lower, mixed);
        assert_eq!(mixed.branch(), "z9hG4bK-AbC");
        assert_ne!(lower, key("BRANCH", "z9hG4bK-abc"));
    }
}
