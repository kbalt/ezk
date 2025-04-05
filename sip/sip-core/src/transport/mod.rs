use self::managed::{DropNotifier, ManagedTransportState, MangedTransport, RefOwner, WeakRefOwner};
use self::resolver::ServerEntry;
use self::stun_user::StunUser;
use crate::{Endpoint, Request, Response, Result};
use bytes::Bytes;
use parking_lot::Mutex;
use sip_types::host::{Host, HostPort};
use sip_types::msg::MessageLine;
use sip_types::print::AppendCtx;
use sip_types::uri::SipUri;
use sip_types::Headers;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::mem::take;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::SystemTime;
use std::{fmt, io};
use stun::StunEndpoint;
use stun_types::Message;
use tokio::sync::oneshot;

mod managed;
mod parse;
mod resolver;
pub mod streaming;
mod stun_user;

#[cfg(feature = "tls-native-tls")]
pub mod native_tls;
#[cfg(feature = "tls-rustls")]
pub mod rustls;
pub mod tcp;
pub mod udp;

/// Abstraction over a transport factory.
///
/// It is used to created connection oriented transports
#[async_trait::async_trait]
pub trait Factory: Send + Sync + 'static {
    /// Must return the name of the transport this factory produces. (e.g. UDP, TCP, TLS ...)
    fn name(&self) -> &'static str;

    /// Checks if the factory is eligible for the transport specified inside an uri.
    /// Needs overridable behavior since some transports (like TLS) must accept the `tcp`-string.
    fn matches_transport_param(&self, name: &str) -> bool {
        self.name().eq_ignore_ascii_case(name)
    }

    /// Indicated if the created transport is secure
    fn secure(&self) -> bool;

    /// Create a transport from an `endpoint` and a list of (resolved) addresses.
    ///
    /// Returns the created transport and address used to connect the transport
    async fn create(
        &self,
        endpoint: Endpoint,
        uri: &SipUri,
        addrs: SocketAddr,
    ) -> io::Result<TpHandle>;
}

/// Abstraction over a transport
#[async_trait::async_trait]
pub trait Transport: Debug + Display + Send + Sync + 'static {
    /// Must return the name of the transport. (e.g. UDP, TCP, TLS ...)
    fn name(&self) -> &'static str;

    /// Checks if the transport is eligible for the transport specified inside an uri.
    /// Needs overridable behavior since some transports (like TLS) must accept the `tcp`-string.
    fn matches_transport_param(&self, name: &str) -> bool {
        self.name().eq_ignore_ascii_case(name)
    }

    /// Indicates if the transport is a secure connection (e.g. TLS)
    fn secure(&self) -> bool;

    /// Is the transport reliable, changes how retransmissions in transactions are handled.
    fn reliable(&self) -> bool;

    /// The local address of the transport
    fn bound(&self) -> SocketAddr;

    /// The sent-by address of the transport. This address is where peers can reach this endpoint
    /// from. (e.g. the listener address of a tcp stream)
    fn sent_by(&self) -> SocketAddr;

    /// The direction of the transport
    fn direction(&self) -> Direction;

    /// Use the given transport to send `message` to `target`.
    ///
    /// Connection oriented transports may discard the `target` parameter.
    async fn send(&self, message: &[u8], target: SocketAddr) -> io::Result<()>;
}

/// Wrapper over implementations of [`Transport`].
///
/// Provides reference counting of connection based
///
#[derive(Debug, Clone)]
pub struct TpHandle {
    _ref_guard: Option<RefOwner>,
    transport: Arc<dyn Transport>,
}

impl Deref for TpHandle {
    type Target = dyn Transport;

    fn deref(&self) -> &Self::Target {
        &*self.transport
    }
}

impl PartialEq for TpHandle {
    fn eq(&self, other: &Self) -> bool {
        TpKey::from_dyn(&*self.transport) == TpKey::from_dyn(&*other.transport)
    }
}

impl fmt::Display for TpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.transport.direction() {
            Direction::None => write!(f, "{}", self.transport),
            Direction::Outgoing(_) => write!(f, "outgoing:{}", self.transport),
            Direction::Incoming(_) => write!(f, "incoming:{}", self.transport),
        }
    }
}

impl TpHandle {
    /// Create a new handle over a transport without any lifetime
    /// management. Useful for transports without a connection
    /// or lifetime like UDP.
    pub fn new<T: Transport>(transport: T) -> Self {
        Self {
            _ref_guard: None,
            transport: Arc::new(transport),
        }
    }

    /// Get the [`TpKey`] to identify this transport
    pub fn key(&self) -> TpKey {
        TpKey::from_dyn(&*self.transport)
    }

    fn new_managed<T: Transport>(transport: T) -> (Self, WeakRefOwner, DropNotifier) {
        let (owner, notifier) = managed::ref_counter();

        let weak = owner.downgrade();

        let transport = Self {
            _ref_guard: Some(owner),
            transport: Arc::new(transport),
        };

        (transport, weak, notifier)
    }
}

/// Direction of a transport
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Direction {
    /// No direction because it is datagram based (e.g. UDP)
    None,

    /// A connection oriented transport which has been established by this endpoint
    Outgoing(SocketAddr),

    /// A connection oriented transport which was accepted by this endpoint
    Incoming(SocketAddr),
}

/// Information saved for subsequent request to the same target
///
/// Used to save the transport & resolved socket address of an uri.
/// Can also be used to configure the via_host_port if it needs rewriting.
#[derive(Debug, Default, Clone)]
pub struct TargetTransportInfo {
    /// optional host port to use in the via header
    pub via_host_port: Option<HostPort>,

    /// Transport and remote address used to send
    /// requests to. If not set the request-uri
    /// will be used to populate there accordingly.
    pub transport: Option<(TpHandle, SocketAddr)>,
}

/// Transport related info for a message
#[derive(Debug)]
pub struct MessageTpInfo {
    /// Timestamp the messages was received at
    pub timestamp: SystemTime,

    /// Source address
    pub source: SocketAddr,

    /// The complete buffer containing the message.
    /// Must be truncated to fit the message
    pub buffer: Bytes,

    /// Handle to the transport the messages was received from
    pub transport: TpHandle,
}

/// Message received directly from a transport
pub struct ReceivedMessage {
    /// transport info about the message
    pub tp_info: MessageTpInfo,

    /// Leading line of the message. Notates if the message is a request or response
    pub line: MessageLine,

    /// All headers found inside the message, neither parsed nor validated
    pub headers: Headers,

    /// Body part of the messages as raw bytes
    pub body: Bytes,
}

impl fmt::Display for ReceivedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.line.default_print_ctx())
    }
}

impl ReceivedMessage {
    pub fn new(
        source: SocketAddr,
        buffer: Bytes,
        transport: TpHandle,
        line: MessageLine,
        headers: Headers,
        body: Bytes,
    ) -> Self {
        Self {
            tp_info: MessageTpInfo {
                timestamp: SystemTime::now(),
                source,
                buffer,
                transport,
            },
            line,
            headers,
            body,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutgoingResponse {
    pub msg: Response,
    pub parts: OutgoingParts,
}

#[derive(Debug, Clone)]
pub struct OutgoingRequest {
    pub msg: Request,
    pub parts: OutgoingParts,
}

#[derive(Debug, Clone)]
pub struct OutgoingParts {
    /// Transport the message will be sent with
    pub transport: TpHandle,

    /// Address the message will be sent to
    pub destination: SocketAddr,

    /// Buffer the message got printed into
    pub buffer: Bytes,
}

/// Key used to identify and store transports
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct TpKey {
    /// Name of the transport (taken from [`Transport::name`])
    pub name: &'static str,
    /// Local address of the transport
    pub bound: SocketAddr,
    /// Direction of the transport
    pub direction: Direction,
}

impl TpKey {
    fn from_dyn(transport: &dyn Transport) -> Self {
        Self {
            name: transport.name(),
            bound: transport.bound(),
            direction: transport.direction(),
        }
    }
}

pub(crate) struct Transports {
    unmanaged: Box<[TpHandle]>,
    factories: Box<[Arc<dyn Factory>]>,

    transports: Mutex<HashMap<TpKey, MangedTransport>>,

    stun: StunEndpoint<StunUser>,

    dns_resolver: hickory_resolver::TokioResolver,
}

impl Transports {
    async fn resolve_host_port(&self, host: &Host, port: u16) -> io::Result<Vec<ServerEntry>> {
        match host {
            Host::IP6(ip) => Ok(vec![ServerEntry::from((*ip, port))]),
            Host::IP4(ip) => Ok(vec![ServerEntry::from((*ip, port))]),
            Host::Name(name) => resolver::resolve_host(&self.dns_resolver, name, port).await,
        }
    }

    async fn resolve_uri(&self, uri: &SipUri) -> io::Result<Vec<ServerEntry>> {
        let port = match uri.host_port.port {
            Some(port) => port,
            None if uri.sips => 5061,
            None => 5060,
        };

        self.resolve_host_port(&uri.host_port.host, port).await
    }

    /// Will try to find or create a suitable transport the given Uri
    #[tracing::instrument(name = "select_transport", level = "trace", skip(self, endpoint))]
    pub(crate) async fn select(
        &self,
        endpoint: &Endpoint,
        uri: &SipUri,
    ) -> Result<(TpHandle, SocketAddr)> {
        log::trace!("select transport for {:?}", uri);

        // Resolve host_port to possible remote addresses
        let servers = self.resolve_uri(uri).await?;

        for server in servers {
            // Search unmanaged ones (connectionless, e.g. udp)
            if let Some(transport) = self.find_matching_unmanaged_transport(uri, &server) {
                log::trace!("selected connectionless: {}", transport);

                return Ok((transport.clone(), server.address));
            }

            // Search managed idling transports (connections, e.g. tcp / tls)
            if let Some(found) = self.find_matching_idling_transport(uri, &server) {
                return Ok((found, server.address));
            }

            // No existing transport found, try and connect a new one

            if let Some(found) = self.connect(endpoint, uri, &server).await {
                return Ok((found, server.address));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to select transport for {uri:?}"),
        )
        .into())
    }

    fn find_matching_unmanaged_transport(
        &self,
        uri: &SipUri,
        server: &ServerEntry,
    ) -> Option<&TpHandle> {
        self.unmanaged.iter().find(|tp| {
            let addr_familiy_supported = tp.bound().is_ipv4() == server.address.is_ipv4();

            let transport_name_matches = server
                .transport
                .map(|t| t.as_str() == tp.name())
                .unwrap_or(true);

            let security_level_matches = if uri.sips { tp.secure() } else { true };
            let transport_param_matches = uri
                .uri_params
                .get_val("transport")
                .as_ref()
                .is_none_or(|t| tp.matches_transport_param(t));

            addr_familiy_supported
                && transport_name_matches
                && security_level_matches
                && transport_param_matches
        })
    }

    fn find_matching_idling_transport(
        &self,
        uri: &SipUri,
        server: &ServerEntry,
    ) -> Option<TpHandle> {
        // TODO: do something about this lock
        let mut transports = self.transports.lock();

        for (_, managed) in transports.iter_mut() {
            if let Some(transport) = server.transport {
                if transport.as_str() != managed.transport.name() {
                    continue;
                }
            }

            // Check if the transport is connected to the server's address
            let remote = match managed.transport.direction() {
                Direction::None => unreachable!(),
                Direction::Incoming(_) => continue,
                Direction::Outgoing(remote) => remote,
            };

            if server.address != remote {
                continue;
            }

            // Check if the transport security is sufficient
            if !uri.sips || managed.transport.secure() {
                continue;
            }

            // Check if the transport's name matches the transport parameter
            if let Some(transport_param) = uri.uri_params.get_val("transport") {
                if !managed.transport.matches_transport_param(transport_param) {
                    continue;
                }
            }

            log::trace!("selected transport: {}", managed.transport);

            if let Some(transport) = managed.try_get() {
                return Some(transport);
            } else {
                log::warn!("bug: failed to use transport {}", managed.transport)
            }
        }

        None
    }

    async fn connect(
        &self,
        endpoint: &Endpoint,
        uri: &SipUri,
        server: &ServerEntry,
    ) -> Option<TpHandle> {
        // Try to build new transport with a factory
        for factory in self.factories.iter() {
            if let Some(transport) = server.transport {
                if transport.as_str() != factory.name() {
                    continue;
                }
            }

            if !uri.sips || factory.secure() {
                continue;
            }

            // Check if the transport's name matches the transport parameter
            if let Some(transport_param) = uri.uri_params.get_val("transport") {
                if !factory.matches_transport_param(transport_param) {
                    continue;
                }
            }

            match factory.create(endpoint.clone(), uri, server.address).await {
                Ok(transport) => {
                    log::debug!("created new transport {}", transport);

                    return Some(transport);
                }
                Err(e) => {
                    log::debug!(
                        "Failed to connect to {} with {}, reason = {e}",
                        server.address,
                        factory.name()
                    );
                }
            }
        }

        None
    }

    /// Adds the given connected transport and return a strong tp-handle and notifier
    pub fn add_managed_used<T>(&self, transport: T) -> (TpHandle, DropNotifier)
    where
        T: Transport,
    {
        let (transport, weak, rx) = TpHandle::new_managed(transport);

        let mut transports = self.transports.lock();

        transports.insert(
            transport.key(),
            MangedTransport {
                transport: transport.transport.clone(),
                state: ManagedTransportState::Used(weak),
            },
        );

        (transport, rx)
    }

    /// Adds the transport which is not in use (e.g. it was just accepted).
    ///
    /// Returns a oneshot receiver which yields a [`DropNotifier`].
    /// That notifier will be sent once the transports gets used.
    pub fn add_managed_unused<T>(&self, transport: T) -> oneshot::Receiver<DropNotifier>
    where
        T: Transport,
    {
        let (tx, rx) = oneshot::channel();

        let mut transports = self.transports.lock();

        transports.insert(
            TpKey {
                name: transport.name(),
                bound: transport.bound(),
                direction: transport.direction(),
            },
            MangedTransport {
                transport: Arc::new(transport),
                state: ManagedTransportState::Unused(tx),
            },
        );

        rx
    }

    /// Sets the state of the transport behind the key to unused.
    ///
    /// Returns a oneshot receiver which yields a [`DropNotifier`].
    /// That notifier will be sent once the transports gets reused.
    pub fn set_unused(&self, tp_key: &TpKey) -> oneshot::Receiver<DropNotifier> {
        let (tx, rx) = oneshot::channel();

        let mut transports = self.transports.lock();
        let managed = transports
            .get_mut(tp_key)
            .expect("invalid tp_key to set_unused passed");

        managed.state = ManagedTransportState::Unused(tx);

        rx
    }

    /// Returns the transport behind the key. Sets the state to used if its not
    pub fn set_used(&self, tp_key: &TpKey) -> TpHandle {
        let mut transports = self.transports.lock();
        let managed = transports
            .get_mut(tp_key)
            .expect("invalid tp_key to set_unused passed");

        managed
            .try_get()
            .expect("set_used failed to retrieve TpHandle")
    }

    /// Remove the transport behind the key
    pub fn drop_transport(&self, tp_key: &TpKey) {
        log::trace!("drop transport {:?}", tp_key);

        self.transports.lock().remove(tp_key);
    }

    pub async fn receive_stun(&self, message: Message, source: SocketAddr, transport: TpHandle) {
        self.stun.receive(message, source, transport).await
    }
}

#[derive(Default)]
pub(crate) struct TransportsBuilder {
    unmanaged: Vec<TpHandle>,
    factories: Vec<Arc<dyn Factory>>,
    dns_resolver: Option<hickory_resolver::TokioResolver>,
}

impl TransportsBuilder {
    pub(crate) fn insert_unmanaged(&mut self, transport: TpHandle) {
        assert_eq!(transport.direction(), Direction::None);

        self.unmanaged.push(transport);
    }

    pub(crate) fn insert_factory(&mut self, factory: Arc<dyn Factory>) {
        self.factories.push(factory);
    }

    pub(crate) fn set_dns_resolver(&mut self, dns_resolver: hickory_resolver::TokioResolver) {
        self.dns_resolver = Some(dns_resolver);
    }

    pub(crate) fn build(&mut self) -> Transports {
        let dns_resolver = self.dns_resolver.take().unwrap_or_else(|| {
            hickory_resolver::TokioResolver::builder_tokio()
                .expect("Failed to create default system DNS resolver")
                .build()
        });

        Transports {
            unmanaged: take(&mut self.unmanaged).into_boxed_slice(),
            factories: take(&mut self.factories).into_boxed_slice(),
            stun: StunEndpoint::new(StunUser),
            transports: Default::default(),
            dns_resolver,
        }
    }
}
