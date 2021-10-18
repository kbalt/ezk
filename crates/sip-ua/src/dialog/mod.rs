use crate::dialog::layer::DialogEntry;
use crate::util::random_sequence_number;
use bytesstr::BytesStr;
use sip_core::transport::OutgoingResponse;
use sip_core::{Endpoint, IncomingRequest, LayerKey, Request, Result};
use sip_types::header::typed::{CSeq, CallID, Contact, FromTo, Routing};
use sip_types::host::HostPort;
use sip_types::{Code, Method, Name};

mod key;
mod layer;

pub use key::DialogKey;
pub use layer::{register_usage, DialogLayer, Usage, UsageGuard};

#[derive(Debug)]
pub struct Dialog {
    pub endpoint: Endpoint,

    dialog_layer: LayerKey<DialogLayer>,

    /// Local CSeq number, increments with every request constructed using this dialog
    pub local_cseq: u32,

    /// Remote CSeq number as seen in first request
    pub peer_cseq: u32,

    /// From header used to construct requests inside the dialog
    ///
    /// All dialog code assumes that the tag is some
    pub local_fromto: FromTo,

    /// To header used to construct requests inside the dialog
    ///
    /// Tag may be `None` to provide backwards compatibility
    pub peer_fromto: FromTo,

    /// Local Contact header, used to construct requests inside the dialog
    pub local_contact: Contact,

    /// Remote Contact header, used to construct requests inside the dialog
    /// as its the target URI.
    pub peer_contact: Contact,

    /// CallID of the Dialog which is part of the dialog key
    pub call_id: CallID,

    /// Dialog's Route set, must be set with every request
    pub route_set: Vec<Routing>,

    /// Was a secure transport used to construct this dialog
    /// Requires all future requests to also use secure transports
    // TODO use this
    pub secure: bool,

    /// Via address of the dialog, can be set to override the transports
    /// default via host-port.
    ///
    /// Can be discovered by reading the received param on responses or by using STUN
    pub via_host_port: Option<HostPort>,
}

impl Dialog {
    /// Create a dialog from an incoming request (may be early)
    #[allow(clippy::too_many_arguments)]
    pub fn new_server(
        endpoint: Endpoint,
        dialog_layer: LayerKey<DialogLayer>,
        peer_cseq: u32,
        peer_fromto: FromTo,
        local_fromto: FromTo,
        local_contact: Contact,
        peer_contact: Contact,
        call_id: CallID,
        route_set: Vec<Routing>,
        secure: bool,
    ) -> Self {
        assert!(local_fromto.tag.is_some());

        let dialog = Self {
            endpoint,
            dialog_layer,
            local_cseq: random_sequence_number(),
            peer_cseq,

            // On server dialogs the from/to headers are reversed
            // since they are taken from an incoming request
            local_fromto,
            peer_fromto,
            local_contact,
            peer_contact,
            call_id,
            route_set,
            secure,
            via_host_port: None,
        };

        let entry = DialogEntry::new(dialog.peer_cseq);

        dialog.endpoint[dialog_layer]
            .dialogs
            .lock()
            .insert(dialog.key(), entry);

        dialog
    }

    /// Create a key that the dialog can be identified with
    pub fn key(&self) -> DialogKey {
        DialogKey {
            call_id: self.call_id.0.clone(),
            peer_tag: self.peer_fromto.tag.clone(),
            local_tag: self.local_fromto.tag.clone().unwrap(),
        }
    }

    pub fn create_request(&mut self, method: Method) -> Request {
        let mut request = Request::new(method.clone(), self.peer_contact.uri.uri.clone());

        let cseq = CSeq::new(self.local_cseq, method);
        self.local_cseq += 1;

        request.headers.insert_type(Name::FROM, &self.local_fromto);
        request.headers.insert_type(Name::TO, &self.peer_fromto);
        request.headers.insert_named(&self.call_id);
        request.headers.insert_named(&cseq);
        request.headers.insert_type(Name::ROUTE, &self.route_set);

        request
    }

    pub async fn create_response(
        &self,
        request: &IncomingRequest,
        code: Code,
        reason: Option<BytesStr>,
    ) -> Result<OutgoingResponse> {
        let mut response = self.endpoint.create_response(request, code, reason).await?;

        if code == Code::TRYING {
            // remove tag from 100 response
            response
                .msg
                .headers
                .edit(Name::TO, |to: &mut FromTo| to.tag = None)?;
        }

        if request.line.method == Method::INVITE {
            let code = code.into_u16();

            if let 101..=399 | 485 = code {
                if !response.msg.headers.contains(&Name::CONTACT) {
                    response.msg.headers.insert_named(&self.local_contact);
                }
            }

            if let 180..=189 | 200..=299 | 405 = code {
                response.msg.headers.insert_named(self.endpoint.allowed());
            }

            if let 200..=299 = code {
                response.msg.headers.insert_named(self.endpoint.supported());
            }
        }

        Ok(response)
    }
}

impl Drop for Dialog {
    fn drop(&mut self) {
        self.endpoint[self.dialog_layer]
            .dialogs
            .lock()
            .remove(&self.key());
    }
}
