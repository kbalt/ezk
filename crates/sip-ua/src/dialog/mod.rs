use self::layer::DialogEntry;
use crate::util::{random_sequence_number, random_string};
use bytesstr::BytesStr;
use sip_core::transport::{OutgoingResponse, TargetTransportInfo};
use sip_core::{Endpoint, Error, IncomingRequest, LayerKey, Request, Result};
use sip_types::header::typed::{CSeq, CallID, Contact, FromTo, MaxForwards, Routing};
use sip_types::header::HeaderError;
use sip_types::{Code, Method, Name};
use std::sync::atomic::{AtomicU32, Ordering};

mod client_builder;
mod key;
mod layer;

pub use client_builder::ClientDialogBuilder;
pub use key::DialogKey;
pub use layer::{register_usage, DialogLayer, Usage, UsageGuard};
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct Dialog {
    pub endpoint: Endpoint,

    pub dialog_layer: LayerKey<DialogLayer>,

    /// Local CSeq number, increments with every request constructed using this dialog
    pub local_cseq: AtomicU32,

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

    /// Target of the dialog peer
    pub target_tp_info: Mutex<TargetTransportInfo>,
}

impl Dialog {
    /// Create a dialog from an incoming request (may be early)
    pub fn new_server(
        endpoint: Endpoint,
        dialog_layer: LayerKey<DialogLayer>,
        request: &IncomingRequest,
        local_contact: Contact,
    ) -> Result<Self> {
        if request.base_headers.from.tag.is_none() {
            return Err(Error::Header(HeaderError::malformed_adhoc(
                Name::FROM,
                "Missing Tag",
            )));
        }

        let route_set: Vec<Routing> = request.headers.get(Name::RECORD_ROUTE).unwrap_or_default();

        let mut dialog = Self {
            endpoint,
            dialog_layer,
            local_cseq: random_sequence_number().into(),
            local_fromto: request.base_headers.to.clone(),
            peer_fromto: request.base_headers.from.clone(),
            local_contact,
            peer_contact: request.headers.get_named()?,
            call_id: request.base_headers.call_id.clone(),
            route_set,
            // TODO check how this works exactly
            secure: request.line.uri.info().secure,
            target_tp_info: Default::default(),
        };

        dialog.local_fromto.tag = Some(random_string());

        let entry = DialogEntry::new(Some(request.base_headers.cseq.cseq));
        dialog.endpoint[dialog_layer]
            .dialogs
            .lock()
            .insert(dialog.key(), entry);

        Ok(dialog)
    }

    pub fn register_usage<U: Usage>(&self, usage: U) -> UsageGuard {
        register_usage(self.endpoint.clone(), self.dialog_layer, self.key(), usage)
            .expect("called by the dialog")
    }

    /// Create a key that the dialog can be identified with
    pub fn key(&self) -> DialogKey {
        DialogKey {
            call_id: self.call_id.0.clone(),
            peer_tag: self.peer_fromto.tag.clone(),
            local_tag: self.local_fromto.tag.clone().unwrap(),
        }
    }

    pub fn create_request(&self, method: Method) -> Request {
        let mut request = Request::new(method.clone(), self.peer_contact.uri.uri.clone());

        let cseq = CSeq::new(self.local_cseq.fetch_add(1, Ordering::Relaxed), method);

        request.headers.insert_type(Name::FROM, &self.local_fromto);
        request.headers.insert_type(Name::TO, &self.peer_fromto);
        request.headers.insert_named(&MaxForwards(70));
        request.headers.insert_named(&self.call_id);
        request.headers.insert_named(&cseq);

        if !self.route_set.is_empty() {
            request.headers.insert_type(Name::ROUTE, &self.route_set);
        }

        request
    }

    pub fn create_response(
        &self,
        request: &IncomingRequest,
        code: Code,
        reason: Option<BytesStr>,
    ) -> Result<OutgoingResponse> {
        let mut response = self.endpoint.create_response(request, code, reason);

        if request.line.method == Method::INVITE || request.line.method == Method::SUBSCRIBE {
            let _ = request
                .headers
                .clone_into(&mut response.msg.headers, Name::RECORD_ROUTE);

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
                if request.base_headers.to.tag.is_none() {
                    // Add To-tag to success response to create dialog
                    response.msg.headers.edit(Name::TO, |to: &mut FromTo| {
                        to.tag.clone_from(&self.local_fromto.tag);
                    })?;
                }

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
