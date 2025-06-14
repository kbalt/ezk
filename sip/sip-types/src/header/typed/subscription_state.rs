use crate::header::headers::OneOrMore;
use crate::header::name::Name;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::print::{AppendCtx, Print, PrintCtx};
use crate::uri::params::{CPS, Params};
use anyhow::bail;
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use internal::ws;
use nom::bytes::complete::take_while1;
use nom::combinator::map_res;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

/// substate-value defined in [RFC 6665](https://datatracker.ietf.org/doc/html/rfc6665#section-8.4)
#[derive(Debug, Clone, PartialEq)]
pub enum SubStateValue {
    Active,
    Pending,
    Terminated,
}

impl fmt::Display for SubStateValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SubStateValue::Active => f.write_str("active"),
            SubStateValue::Pending => f.write_str("pending"),
            SubStateValue::Terminated => f.write_str("terminated"),
        }
    }
}

/// event-reason-value defined in [RFC 6665](https://datatracker.ietf.org/doc/html/rfc6665#section-8.4)
#[derive(Debug, Clone, PartialEq)]
pub enum EventReasonValue {
    Deactivated,
    Probation,
    Rejected,
    Timeout,
    GiveUp,
    NoResource,
    Invariant,
    Other(BytesStr),
}

impl fmt::Display for EventReasonValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use EventReasonValue::*;
        match self {
            Deactivated => f.write_str("deactivated"),
            Probation => f.write_str("probation"),
            Rejected => f.write_str("rejected"),
            Timeout => f.write_str("timeout"),
            GiveUp => f.write_str("giveup"),
            NoResource => f.write_str("noresource"),
            Invariant => f.write_str("invariant"),
            Other(o) => write!(f, "{}", o),
        }
    }
}

/// `Subscription-State` header
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    pub state: SubStateValue,
    pub expires: Option<u32>,
    pub reason: Option<EventReasonValue>,
    pub retry_after: Option<u32>,
    pub params: Params<CPS>,
}

impl SubscriptionState {
    #[inline]
    pub fn new(state: SubStateValue) -> SubscriptionState {
        SubscriptionState {
            state,
            expires: None,
            reason: None,
            retry_after: None,
            params: Params::new(),
        }
    }

    pub fn with_expires(mut self, expires: u32) -> Self {
        self.expires = Some(expires);
        self
    }

    pub fn with_reason(mut self, reason: EventReasonValue) -> Self {
        self.reason = Some(reason);
        self
    }

    pub fn with_retry_after(mut self, retry_after: u32) -> Self {
        self.retry_after = Some(retry_after);
        self
    }
}

impl ConstNamed for SubscriptionState {
    const NAME: Name = Name::SUBSCRIPTION_STATE;
}

impl Print for SubscriptionState {
    fn print(&self, f: &mut Formatter<'_>, _ctx: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{}", self.state)?;
        if let Some(e) = &self.expires {
            write!(f, ";expires={}", e)?;
        }
        if let Some(reason) = &self.reason {
            write!(f, ";reason={}", reason)?;
        }
        if let Some(after) = &self.retry_after {
            write!(f, ";retry-after={}", after)?;
        }
        write!(f, "{}", &self.params)?;
        Ok(())
    }
}

impl HeaderParse for SubscriptionState {
    fn parse<'i>(src: &'i Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map_res(
            ws((take_while1(|b| b != ';'), Params::<CPS>::parse(src))),
            |(sub_state, mut params)| -> anyhow::Result<Self> {
                Ok(Self {
                    state: match sub_state {
                        "active" => SubStateValue::Active,
                        "pending" => SubStateValue::Pending,
                        "terminated" => SubStateValue::Terminated,
                        _ => bail!("Received invalid state in Subscription-State header"),
                    },
                    reason: {
                        if let Some(r) = params.take("reason") {
                            use EventReasonValue::*;
                            Some(match r.as_ref() {
                                "deactivated" => Deactivated,
                                "probation" => Probation,
                                "rejected" => Rejected,
                                "timeout" => Timeout,
                                "giveup" => GiveUp,
                                "noresource" => NoResource,
                                "invariant" => Invariant,
                                _ => Other(r),
                            })
                        } else {
                            None
                        }
                    },
                    expires: params
                        .take("expires")
                        .as_ref()
                        .and_then(|e| u32::from_str(e).ok()),
                    retry_after: params
                        .take("retry-after")
                        .as_ref()
                        .and_then(|after| u32::from_str(after).ok()),
                    params,
                })
            },
        )(i)
    }
}

impl ExtendValues for SubscriptionState {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        // Do not create SubscriptionState CSV header
        values.push(self.print_ctx(ctx).to_string().into());
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    #[test]
    fn subscription_state_parse_with_reason() {
        let mut headers = Headers::new();
        headers.insert(Name::SUBSCRIPTION_STATE, "terminated; reason=timeout");

        let state: SubscriptionState = headers.get_named().unwrap();
        assert_eq!(state.state, SubStateValue::Terminated);
        assert_eq!(state.expires, None);
        assert_eq!(state.reason, Some(EventReasonValue::Timeout));
        assert!(state.params.is_empty());
    }

    #[test]
    fn subscription_state_parse_with_expires() {
        let mut headers = Headers::new();
        headers.insert(Name::SUBSCRIPTION_STATE, "active; expires=3600");

        let state: SubscriptionState = headers.get_named().unwrap();
        assert_eq!(state.state, SubStateValue::Active);
        assert_eq!(state.expires, Some(3600));
        assert_eq!(state.reason, None);
        assert!(state.params.is_empty());
    }

    #[test]
    fn subscription_state_print_simple() {
        let sub_state = SubscriptionState::new(SubStateValue::Pending);
        assert_eq!(sub_state.default_print_ctx().to_string(), "pending");
    }

    #[test]
    fn subscription_state_print_with_expires() {
        let sub_state = SubscriptionState::new(SubStateValue::Active).with_expires(3600);
        assert_eq!(
            sub_state.default_print_ctx().to_string(),
            "active;expires=3600"
        );
    }

    #[test]
    fn subscription_state_print_with_reason() {
        let sub_state = SubscriptionState::new(SubStateValue::Terminated)
            .with_reason(EventReasonValue::Timeout)
            .with_retry_after(600);
        assert_eq!(
            sub_state.default_print_ctx().to_string(),
            "terminated;reason=timeout;retry-after=600"
        );
    }
}
