use crate::transaction::{ClientInvTsx, ClientTsx, ServerInvTsx, ServerTsx, TsxKey};
use crate::transaction::{Transactions, TsxMessage};
use crate::transport::{
    Direction, Factory, OutgoingParts, OutgoingRequest, OutgoingResponse, ReceivedMessage,
    TpHandle, Transport, Transports, TransportsBuilder,
};
use crate::{BaseHeaders, IncomingRequest, Layer, MayTake, Request, Response, Result};
use bytes::{Bytes, BytesMut};
use bytesstr::BytesStr;
use sip_types::header::typed::{Accept, Allow, Supported, Via};
use sip_types::host::Host;
use sip_types::msg::{MessageLine, StatusLine};
use sip_types::parse::Parser;
use sip_types::print::{AppendCtx, BytesPrint, PrintCtx};
use sip_types::{Code, Headers, Method, Name};
use std::fmt::Write;
use std::marker::PhantomData;
use std::mem::take;
use std::net::{IpAddr, SocketAddr};
use std::ops::Index;
use std::sync::Arc;
use std::{fmt, io};
use tokio::sync::broadcast;
use tracing::Instrument;

/// The endpoint is the centerpiece of the sip stack. It contains all information about the
/// application and a stack of layered modules which build the logic of SIP applications and
/// its extensions.
///
/// It being a wrapper of a `Arc<Inner>` (where `Inner` is an internal struct) makes it relatively
/// cheap to clone and store where needed, but sometimes tricky to store as the endpoint may never
/// contain itself to avoid cyclic references.
#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<Inner>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("inner_refcount", &Arc::strong_count(&self.inner))
            .finish_non_exhaustive()
    }
}

struct Inner {
    // capabilities
    accept: Vec<Accept>,
    allow: Vec<Allow>,
    supported: Vec<Supported>,

    // Parser used for all parsing operations.
    parser: Parser,

    transports: Transports,
    transactions: Transactions,

    layer: Box<[Box<dyn Layer>]>,
}

impl Endpoint {
    /// Construct a new [`EndpointBuilder`]
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::new()
    }

    /// Returns the endpoints current [`Parser`]
    pub fn parser(&self) -> Parser {
        self.inner.parser
    }

    /// Sends an INVITE request and return a [`ClientInvTsx`] which MUST be used to drive the transaction
    pub async fn send_invite(&self, request: Request) -> Result<ClientInvTsx> {
        ClientInvTsx::send(self.clone(), request).await
    }

    /// Sends a request and return a [`ClientTsx`] which MUST be used to drive the transaction
    pub async fn send_request(&self, request: Request) -> Result<ClientTsx> {
        ClientTsx::send(self.clone(), request).await
    }

    /// Create a [`ServerTsx`] from an [`IncomingRequest`]. The returned transaction
    /// can be used to form and send responses to the request.
    pub fn create_server_tsx(&self, request: &IncomingRequest) -> ServerTsx {
        ServerTsx::new(self.clone(), request)
    }

    /// Create a [`ServerInvTsx`] from an INVITE [`IncomingRequest`]. The returned transaction
    /// can be used to form and send responses to the request.
    pub fn create_server_inv_tsx(&self, request: &IncomingRequest) -> ServerInvTsx {
        ServerInvTsx::new(self.clone(), request)
    }

    /// Returns all ACCEPT headers this endpoint supports
    pub fn accepted(&self) -> &Vec<Accept> {
        &self.inner.accept
    }

    /// Returns all ALLOW headers this endpoint supports
    pub fn allowed(&self) -> &Vec<Allow> {
        &self.inner.allow
    }

    /// Returns all SUPPORTED headers this endpoint supports
    pub fn supported(&self) -> &Vec<Supported> {
        &self.inner.supported
    }

    /// Create a VIA header with the given transport and transaction key
    pub fn create_via(&self, transport: &TpHandle, tsx_key: &TsxKey) -> Via {
        Via::new(
            transport.name(),
            transport.sent_by(),
            tsx_key.branch().clone(),
        )
    }

    /// Takes a request and converts it into an `Outgoing`.
    /// To do so it calculates the destination and retrieves a suitable transport
    pub async fn create_outgoing(&self, request: Request) -> Result<OutgoingRequest> {
        let (transport, destination) = self.transports().select(self, &*request.line.uri).await?;

        Ok(OutgoingRequest {
            msg: request,
            parts: OutgoingParts {
                transport,
                destination,
                buffer: Default::default(),
            },
        })
    }

    /// Print the request to its buffer (if needed) and send it via the transport
    pub async fn send_outgoing_request(&self, message: &mut OutgoingRequest) -> io::Result<()> {
        if message.parts.buffer.is_empty() {
            let mut buffer = BytesMut::new();

            let ctx = PrintCtx {
                method: Some(&message.msg.line.method),
                uri: None,
            };

            message
                .msg
                .headers
                .insert(Name::CONTENT_LENGTH, message.msg.body.len().to_string());

            write!(
                buffer,
                "{}\r\n{}\r\n",
                message.msg.line.print_ctx(ctx),
                message.msg.headers
            )
            .map_err(|e| {
                // wrap
                io::Error::new(io::ErrorKind::Other, e)
            })?;

            buffer.extend_from_slice(&message.msg.body);

            message.parts.buffer = buffer.freeze();
        }

        let target = message.parts.destination[0];

        log::trace!(
            "Sending request to {}\n{:?}",
            target,
            BytesPrint(&message.parts.buffer)
        );

        message
            .parts
            .transport
            .send(&message.parts.buffer, message.parts.destination[0])
            .await
    }

    /// Print the request to its buffer (if needed) and send it via the transport
    pub async fn send_outgoing_response(&self, message: &mut OutgoingResponse) -> io::Result<()> {
        if message.parts.buffer.is_empty() {
            let mut buffer = BytesMut::new();

            let ctx = PrintCtx {
                method: None,
                uri: None,
            };

            message
                .msg
                .headers
                .insert(Name::CONTENT_LENGTH, message.msg.body.len().to_string());

            write!(
                buffer,
                "{}\r\n{}\r\n",
                message.msg.line.print_ctx(ctx),
                message.msg.headers
            )
            .map_err(|e| {
                // wrap
                io::Error::new(io::ErrorKind::Other, e)
            })?;

            buffer.extend_from_slice(&message.msg.body);

            message.parts.buffer = buffer.freeze();
        }

        let target = message.parts.destination[0];

        log::trace!(
            "Sending response to {}\n{:?}",
            target,
            BytesPrint(&message.parts.buffer)
        );

        message
            .parts
            .transport
            .send(&message.parts.buffer, message.parts.destination[0])
            .await
    }

    /// Create a response to an incoming request with a given status code and optional reason
    ///
    /// This is async as it may need to make a DNS lookup to calculate the response address
    pub async fn create_response(
        &self,
        request: &IncomingRequest,
        code: Code,
        reason: Option<BytesStr>,
    ) -> Result<OutgoingResponse> {
        assert_ne!(request.line.method, Method::ACK);

        let mut headers = Headers::with_capacity(5);

        headers.insert_type(&request.base_headers.top_via);
        headers.insert_type(&request.base_headers.from);
        headers.insert_type(&request.base_headers.to);
        headers.insert_type(&request.base_headers.call_id);
        headers.insert_type(&request.base_headers.cseq);

        if code == Code::TRYING {
            let _ = request.headers.clone_into(&mut headers, Name::TIMESTAMP);
        }

        let destination = match request.tp_info.transport.direction() {
            Direction::None => {
                if let Some(maddr) = request
                    .base_headers
                    .top_via
                    .params
                    .get_val("maddr")
                    .and_then(|maddr| maddr.parse::<IpAddr>().ok())
                {
                    // TODO maddr default port guessing (currently defaulting to 5060)
                    vec![SocketAddr::new(
                        maddr,
                        request.base_headers.top_via.sent_by.port.unwrap_or(5060),
                    )]
                } else if let Some(rport) = request
                    .base_headers
                    .top_via
                    .params
                    .get_val("rport")
                    .and_then(|rport| rport.parse::<u16>().ok())
                {
                    vec![SocketAddr::new(request.tp_info.source.ip(), rport)]
                } else {
                    let destination = self
                        .transports()
                        // TODO correctly guess default port
                        .resolve_host_port(
                            &request.base_headers.top_via.sent_by.host,
                            request.base_headers.top_via.sent_by.port.unwrap_or(5060),
                        )
                        .await?;

                    destination
                }
            }
            Direction::Outgoing(remote) | Direction::Incoming(remote) => {
                // Use the transport from the request, same remote addr
                vec![remote]
            }
        };

        Ok(OutgoingResponse {
            msg: Response {
                line: StatusLine {
                    code,
                    reason: reason.or_else(|| code.text().map(BytesStr::from_static)),
                },
                headers,
                body: Bytes::new(),
            },
            parts: OutgoingParts {
                transport: request.tp_info.transport.clone(),
                destination,
                buffer: Default::default(),
            },
        })
    }

    /// Pass a received message to the endpoint for further processing
    ///
    /// Spawns a task internally which will let every registered layer have a look at the message
    /// and let it decide if it is going to handle it.
    pub fn receive(&self, message: ReceivedMessage) {
        tokio::spawn(self.clone().do_receive(message));
    }

    #[tracing::instrument(level = "debug", skip(self, message), fields(%message))]
    async fn do_receive(self, message: ReceivedMessage) {
        log::trace!(
            "Received message: \n{:?}",
            BytesPrint(&message.tp_info.buffer)
        );

        let mut base_headers = match BaseHeaders::extract_from(&message.headers) {
            Ok(base_headers) => base_headers,
            Err(e) => {
                log::warn!("Failed to get base headers for incoming message, {}", e);
                return;
            }
        };

        if message.line.is_request() {
            add_received_rport(&mut base_headers.top_via, message.tp_info.source);
        }

        let tsx_key = match TsxKey::from_message_parts(&message.line, &base_headers) {
            Ok(tsx_key) => tsx_key,
            Err(e) => {
                log::warn!("Failed to get tsx key for incoming message, {}", e);
                return;
            }
        };

        match self.transactions().get_tsx_handler(&tsx_key) {
            Some(handler) => {
                let tsx_message = TsxMessage {
                    line: message.line,
                    base_headers,
                    headers: message.headers,
                    body: message.body,
                };

                log::debug!("delegating message to transaction {}", tsx_key);

                if handler.send(tsx_message).is_err() {
                    log::error!("transaction vanished without unregistering");

                    self.transactions().remove_transaction(&tsx_key);
                }
            }
            None => {
                let line = match message.line {
                    MessageLine::Request(line) => line,
                    _ => {
                        log::warn!("the received message is an orphaned response");
                        return;
                    }
                };

                let incoming = IncomingRequest {
                    tp_info: message.tp_info,
                    line,
                    base_headers,
                    headers: message.headers,
                    body: message.body,
                    tsx_key,
                };

                let mut request = Some(incoming);

                for layer in self.inner.layer.iter() {
                    let span = tracing::info_span!("receive", layer = %layer.name());

                    layer
                        .receive(&self, MayTake::new(&mut request))
                        .instrument(span)
                        .await;

                    if request.is_none() {
                        return;
                    }
                }

                log::debug!("No layer handled the request");

                // Safe unwrap. Loop checks every iteration if request is none
                let request = request.unwrap();

                if let Err(e) = self.handle_unwanted_request(request).await {
                    log::error!("Failed to respond to unhandled incoming request, {:?}", e);
                }
            }
        }
    }

    async fn handle_unwanted_request(&self, request: IncomingRequest) -> Result<()> {
        if request.line.method == Method::ACK {
            // Cannot respond to unhandled ACK requests
            return Ok(());
        }

        let response = self
            .create_response(&request, Code::CALL_OR_TRANSACTION_DOES_NOT_EXIST, None)
            .await?;

        if request.line.method == Method::INVITE {
            let tsx = self.create_server_inv_tsx(&request);

            tsx.respond_failure(response).await
        } else {
            let tsx = self.create_server_tsx(&request);

            tsx.respond(response).await
        }
    }

    pub(crate) fn transactions(&self) -> &Transactions {
        &self.inner.transactions
    }

    pub(crate) fn transports(&self) -> &Transports {
        &self.inner.transports
    }
}

fn add_received_rport(via: &mut Via, source: SocketAddr) {
    let source_host: Host = source.ip().into();

    if source_host != via.sent_by.host {
        via.params.push_or_edit("received", source.ip().to_string());
    }

    if let Some(rport) = via.params.get_mut("rport") {
        rport.value = Some(source.port().to_string().into());
    }
}

/// Builder instance for [`Endpoint`]
pub struct EndpointBuilder {
    sender: broadcast::Sender<Endpoint>,

    // capabilities
    accept: Vec<Accept>,
    allow: Vec<Allow>,
    supported: Vec<Supported>,

    transports: TransportsBuilder,
    layer: Vec<Box<dyn Layer>>,
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointBuilder {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1);

        Self {
            sender,
            accept: vec![],
            allow: vec![],
            supported: vec![],
            transports: Default::default(),
            layer: Default::default(),
        }
    }

    /// Add an ACCEPT header to the endpoints capabilities
    pub fn add_accept<A>(&mut self, accepted: A)
    where
        A: Into<Accept>,
    {
        self.accept.push(accepted.into())
    }

    /// Add an ALLOW header to the endpoints capabilities
    pub fn add_allow<A>(&mut self, allowed: A)
    where
        A: Into<Allow>,
    {
        self.allow.push(allowed.into())
    }

    /// Add an SUPPORTED header to the endpoints capabilities
    pub fn add_supported<A>(&mut self, supported: A)
    where
        A: Into<Supported>,
    {
        self.supported.push(supported.into())
    }

    /// Add an unmanaged transport to the endpoint which will never vanish or break (e.g. UDP)
    pub fn add_unmanaged_transport<T>(&mut self, transport: T) -> &mut Self
    where
        T: Transport,
    {
        self.transports.insert_unmanaged(transport);
        self
    }

    /// Add a transport factory to the endpoint
    pub fn add_transport_factory(&mut self, factory: Arc<dyn Factory>) -> &mut Self {
        self.transports.insert_factory(factory);
        self
    }

    /// Add a implementation of [`Layer`] to the endpoint.
    ///
    /// Note that the insertion order is relevant in how the SIP Stack may react to requests,
    /// as its the same order in that modules are called on incoming requests.
    ///
    /// Returns a [`LayerKey`] which can later be used to access the added layer.
    pub fn add_layer<L>(&mut self, layer: L) -> LayerKey<L>
    where
        L: Layer,
    {
        let index = self.layer.len();

        self.layer.push(Box::new(layer));

        LayerKey {
            index,
            m: PhantomData::<fn() -> L>,
        }
    }

    /// "Subscribe" to the creation of the endpoint.
    ///
    /// The broadcast channel will receive the endpoint on successful creation or error if the
    /// builder is prematurely dropped. On error any task waiting for the endpoint should exit.
    pub fn subscribe(&self) -> broadcast::Receiver<Endpoint> {
        self.sender.subscribe()
    }

    /// Complete building the endpoint
    pub fn build(&mut self) -> Endpoint {
        let mut layer = take(&mut self.layer).into_boxed_slice();
        for layer in layer.iter_mut() {
            layer.init(self);
        }

        let inner = Inner {
            accept: take(&mut self.accept),
            allow: take(&mut self.allow),
            supported: take(&mut self.supported),
            parser: Default::default(),
            transports: self.transports.build(),
            transactions: Default::default(),
            layer,
        };

        let inner = Arc::new(inner);

        let endpoint = Endpoint { inner };

        let _ = self.sender.send(endpoint.clone());

        endpoint
    }
}

impl<L: Layer> Index<LayerKey<L>> for Endpoint {
    type Output = L;

    fn index(&self, index: LayerKey<L>) -> &Self::Output {
        self.inner.layer[index.index]
            .downcast_ref()
            .expect("invalid layer key")
    }
}

/// Key which can be used to access a layer which was added to an [`Endpoint`].
pub struct LayerKey<L> {
    index: usize,
    m: PhantomData<fn() -> L>,
}

impl<L> fmt::Debug for LayerKey<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LayerKey").finish()
    }
}

impl<L> Clone for LayerKey<L> {
    fn clone(&self) -> Self {
        Self {
            index: self.index,
            m: self.m,
        }
    }
}

impl<L> Copy for LayerKey<L> {}
