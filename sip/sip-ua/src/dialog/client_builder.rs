use super::{Dialog, DialogLayer};
use crate::dialog::layer::DialogEntry;
use crate::util::{random_sequence_number, random_string};
use bytes::Bytes;
use sip_core::transaction::TsxResponse;
use sip_core::transport::TargetTransportInfo;
use sip_core::{Endpoint, Request};
use sip_types::header::HeaderError;
use sip_types::header::typed::{CSeq, CallID, Contact, FromTo, MaxForwards, Routing};
use sip_types::msg::RequestLine;
use sip_types::uri::{NameAddr, SipUri};
use sip_types::{Headers, Method, Name};
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct ClientDialogBuilder {
    pub endpoint: Endpoint,
    pub local_cseq: u32,
    pub local_fromto: FromTo,
    pub peer_fromto: FromTo,
    pub local_contact: Contact,
    pub call_id: CallID,
    pub target: SipUri,
    pub secure: bool,
    pub target_tp_info: TargetTransportInfo,
}

impl ClientDialogBuilder {
    pub fn new(
        endpoint: Endpoint,
        local_addr: NameAddr,
        local_contact: Contact,
        target: SipUri,
    ) -> Self {
        Self {
            endpoint,
            local_cseq: random_sequence_number(),
            local_fromto: FromTo::new(local_addr, Some(random_string())),
            peer_fromto: FromTo::new(NameAddr::uri(target.clone()), None),
            local_contact,
            call_id: CallID(random_string()),
            secure: target.sips,
            target,
            target_tp_info: TargetTransportInfo::default(),
        }
    }

    pub fn create_request(&mut self, method: Method, cseq: Option<u32>) -> Request {
        let mut headers = Headers::new();

        let cseq = match cseq {
            Some(cseq) => cseq,
            None => {
                self.local_cseq += 1;
                self.local_cseq
            }
        };

        headers.insert_named(&MaxForwards(70));
        headers.insert_type(Name::FROM, &self.local_fromto);
        headers.insert_type(Name::TO, &self.peer_fromto);
        headers.insert_named(&self.call_id);
        headers.insert_named(&CSeq {
            cseq,
            method: method.clone(),
        });
        headers.insert_named(&self.local_contact);

        Request {
            line: RequestLine {
                method,
                uri: self.target.clone(),
            },
            headers,
            body: Bytes::new(),
        }
    }

    pub fn create_dialog_from_response(
        &mut self,
        response: &TsxResponse,
    ) -> Result<Dialog, HeaderError> {
        assert!(response.base_headers.to.tag.is_some());

        let dialog = Dialog {
            endpoint: self.endpoint.clone(),
            local_cseq: self.local_cseq.into(),
            local_fromto: self.local_fromto.clone(),
            peer_fromto: response.base_headers.to.clone(),
            local_contact: self.local_contact.clone(),
            peer_contact: response.headers.get_named()?,
            call_id: self.call_id.clone(),
            route_set: client_route_set(&response.headers),
            secure: self.secure,
            target_tp_info: Mutex::new(self.target_tp_info.clone()),
        };

        let entry = DialogEntry::new(None);
        self.endpoint
            .layer::<DialogLayer>()
            .dialogs
            .lock()
            .insert(dialog.key(), entry);

        Ok(dialog)
    }
}

fn client_route_set(headers: &Headers) -> Vec<Routing> {
    let mut route_set: Vec<Routing> = headers.get(Name::RECORD_ROUTE).unwrap_or_default();
    route_set.reverse();
    route_set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverses_response_record_route_for_client_dialog() {
        let mut headers = Headers::new();
        headers.insert(
            Name::RECORD_ROUTE,
            "<sip:callee-proxy.example;lr>, <sip:caller-proxy.example;lr>",
        );

        let route_set = client_route_set(&headers);
        let caller_proxy: SipUri = "sip:caller-proxy.example;lr".parse().unwrap();
        let callee_proxy: SipUri = "sip:callee-proxy.example;lr".parse().unwrap();

        assert_eq!(route_set.len(), 2);
        assert!(route_set[0].uri.uri.compare(&caller_proxy));
        assert!(route_set[1].uri.uri.compare(&callee_proxy));
    }

    #[test]
    fn reverses_response_record_route_across_header_lines() {
        let mut headers = Headers::new();
        headers.insert(
            Name::RECORD_ROUTE,
            "<sip:proxy-a.example;lr>, <sip:proxy-b.example;lr>",
        );
        headers.insert(Name::RECORD_ROUTE, "<sip:proxy-c.example;lr>");

        let route_set = client_route_set(&headers);
        let proxy_a: SipUri = "sip:proxy-a.example;lr".parse().unwrap();
        let proxy_b: SipUri = "sip:proxy-b.example;lr".parse().unwrap();
        let proxy_c: SipUri = "sip:proxy-c.example;lr".parse().unwrap();

        assert_eq!(route_set.len(), 3);
        assert!(route_set[0].uri.uri.compare(&proxy_c));
        assert!(route_set[1].uri.uri.compare(&proxy_b));
        assert!(route_set[2].uri.uri.compare(&proxy_a));
    }

    #[test]
    fn absent_record_route_produces_empty_route_set() {
        assert!(client_route_set(&Headers::new()).is_empty());
    }

    #[test]
    fn preserves_single_response_record_route() {
        let mut headers = Headers::new();
        headers.insert(Name::RECORD_ROUTE, "<sip:proxy.example;lr>");

        let route_set = client_route_set(&headers);
        let proxy: SipUri = "sip:proxy.example;lr".parse().unwrap();

        assert_eq!(route_set.len(), 1);
        assert!(route_set[0].uri.uri.compare(&proxy));
    }
}
