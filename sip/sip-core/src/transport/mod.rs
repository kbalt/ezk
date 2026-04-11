use self::resolver::ServerEntry;
use self::stun_user::StunUser;
use crate::transport::streaming::StreamingWrite;
use crate::transport::udp::UdpTransport;
use crate::{Endpoint, Request, Response, Result};
use bytes::Bytes;
use bytesstr::BytesStr;
use parking_lot::{Mutex, MutexGuard};
use sip_types::Headers;
use sip_types::host::{Host, HostPort};
use sip_types::msg::MessageLine;
use sip_types::print::AppendCtx;
use sip_types::uri::SipUri;
use std::fmt::Debug;
use std::mem::take;
use std::net::SocketAddr;
use std::time::SystemTime;
use std::{fmt, io};
use stun::StunEndpoint;
use stun_types::Message;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{broadcast, watch};

mod parse;
mod resolver;
mod streaming;
mod stun_user;
mod udp;

#[derive(Debug)]
pub enum TransportState {
    Ok,
    Closed(TransportCloseReason),
}

#[derive(Debug)]
pub enum TransportCloseReason {
    Inactivity,
    Err(io::Error),
}

#[derive(Clone, Debug)]
pub struct TpHandle {
    transport: Transport,
}

impl TpHandle {
    pub(crate) fn name(&self) -> &'static str {
        match &self.transport {
            Transport::Udp(..) => "UDP",
            Transport::Connection(connection) => match connection {
                Connection::Tcp(..) => "TCP",
                #[cfg(feature = "tls-rustls")]
                Connection::Rustls(..) => "TLS",
                #[cfg(feature = "tls-native-tls")]
                Connection::NativeTls(..) => "TLS",
            },
        }
    }

    pub fn is_udp(&self) -> bool {
        match self.transport {
            Transport::Udp(..) => true,
            Transport::Connection(..) => false,
        }
    }

    pub(crate) fn is_reliable(&self) -> bool {
        !self.is_udp()
    }

    /// Get the address the transports socket is bound to
    pub fn bound(&self) -> SocketAddr {
        match &self.transport {
            Transport::Udp(udp_transport) => udp_transport.bound,
            Transport::Connection(connection) => connection.bound(),
        }
    }

    /// Get the remote address if the transport is a TCP/TLS connection
    pub fn connection_remote(&self) -> Option<SocketAddr> {
        match &self.transport {
            Transport::Udp(..) => None,
            Transport::Connection(connection) => Some(connection.remote()),
        }
    }

    /// Send some data in `buf` to `addr`. Connection based transports will ignore `addr`.
    pub async fn send(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        match &self.transport {
            Transport::Udp(udp_transport) => udp_transport.send_to(buf, addr).await,
            Transport::Connection(connection) => connection.send(buf).await,
        }
    }

    /// Returns a receiver that reflects the current state of this transport
    pub fn watch_state(&self) -> watch::Receiver<TransportState> {
        match &self.transport {
            Transport::Udp(udp) => udp.state_receiver(),
            Transport::Connection(connection) => connection.state_receiver(),
        }
    }
}

#[derive(Clone, Debug)]
enum Transport {
    Udp(UdpTransport),
    Connection(Connection),
}

#[derive(Clone, Debug)]
enum Connection {
    Tcp(StreamingWrite<TcpStream>),
    #[cfg(feature = "tls-rustls")]
    Rustls(StreamingWrite<tokio_rustls::TlsStream<TcpStream>>),
    #[cfg(feature = "tls-native-tls")]
    NativeTls(StreamingWrite<tokio_native_tls::TlsStream<TcpStream>>),
}

impl Connection {
    pub(crate) async fn send(&self, buf: &[u8]) -> io::Result<()> {
        match &self {
            Connection::Tcp(w) => w.send(buf).await,
            #[cfg(feature = "tls-rustls")]
            Connection::Rustls(w) => w.send(buf).await,
            #[cfg(feature = "tls-native-tls")]
            Connection::NativeTls(w) => w.send(buf).await,
        }
    }

    fn bound(&self) -> SocketAddr {
        match self {
            Connection::Tcp(t) => t.bound,
            #[cfg(feature = "tls-rustls")]
            Connection::Rustls(t) => t.bound,
            #[cfg(feature = "tls-native-tls")]
            Connection::NativeTls(t) => t.bound,
        }
    }

    fn remote(&self) -> SocketAddr {
        match self {
            Connection::Tcp(t) => t.remote,
            #[cfg(feature = "tls-rustls")]
            Connection::Rustls(t) => t.remote,
            #[cfg(feature = "tls-native-tls")]
            Connection::NativeTls(t) => t.remote,
        }
    }

    fn is_tls(&self) -> bool {
        match self {
            Connection::Tcp(..) => false,
            #[cfg(feature = "tls-rustls")]
            Connection::Rustls(..) => true,
            #[cfg(feature = "tls-native-tls")]
            Connection::NativeTls(..) => true,
        }
    }

    fn state_receiver(&self) -> watch::Receiver<TransportState> {
        match self {
            Connection::Tcp(t) => t.state_receiver(),
            #[cfg(feature = "tls-rustls")]
            Connection::Rustls(t) => t.state_receiver(),
            #[cfg(feature = "tls-native-tls")]
            Connection::NativeTls(t) => t.state_receiver(),
        }
    }
}

impl From<StreamingWrite<TcpStream>> for Connection {
    fn from(value: StreamingWrite<TcpStream>) -> Self {
        Connection::Tcp(value)
    }
}

#[cfg(feature = "tls-rustls")]
impl From<StreamingWrite<tokio_rustls::TlsStream<TcpStream>>> for Connection {
    fn from(value: StreamingWrite<tokio_rustls::TlsStream<TcpStream>>) -> Self {
        Connection::Rustls(value)
    }
}

#[cfg(feature = "tls-native-tls")]
impl From<StreamingWrite<tokio_native_tls::TlsStream<TcpStream>>> for Connection {
    fn from(value: StreamingWrite<tokio_native_tls::TlsStream<TcpStream>>) -> Self {
        Connection::NativeTls(value)
    }
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

pub(crate) struct Transports {
    udp_sockets: Mutex<Vec<UdpTransport>>,
    connections: Mutex<Vec<Connection>>,

    tcp_connect_bind_addr: Option<SocketAddr>,

    #[cfg(feature = "tls-rustls")]
    rustls_connector: Option<tokio_rustls::TlsConnector>,
    #[cfg(feature = "tls-native-tls")]
    native_tls_connector: Option<tokio_native_tls::TlsConnector>,

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

        if let Some(transport) = uri.uri_params.get_val("transport") {
            return self
                .select_transport_by_uri_param(endpoint, uri, transport)
                .await;
        }

        let servers = self.resolve_uri(uri).await?;

        {
            let connections = self.connections.lock();

            // First check if theres an active connection to any of the resolved servers
            for server in &servers {
                match server.transport {
                    Some(resolver::Transport::Udp) => {}
                    Some(resolver::Transport::Tcp) => {
                        if let Some(connection) =
                            find_existing_tcp_connection(&servers, &connections)
                        {
                            return Ok((
                                TpHandle {
                                    transport: Transport::Connection(connection.clone()),
                                },
                                server.address,
                            ));
                        }
                    }
                    Some(resolver::Transport::TlsOverTcp) => {
                        if let Some(connection) =
                            find_existing_tls_connection(&servers, &connections)
                        {
                            return Ok((
                                TpHandle {
                                    transport: Transport::Connection(connection.clone()),
                                },
                                server.address,
                            ));
                        }
                    }
                    None => {
                        // server entries without transport type will be handled later, if everything else fails
                    }
                }
            }
        }

        // No active connection found, find the first compatible entry
        for server in &servers {
            match server.transport {
                Some(resolver::Transport::Udp) | None => {
                    if let Some(udp) = self.udp_sockets.lock().first() {
                        return Ok((
                            TpHandle {
                                transport: Transport::Udp(udp.clone()),
                            },
                            server.address,
                        ));
                    }
                }
                Some(resolver::Transport::Tcp) => {
                    let stream = match self.connect_tcp(server.address).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            log::debug!("Failed to connect to {}, {e}", server.address);
                            continue;
                        }
                    };

                    let local = stream.local_addr()?;

                    let write =
                        streaming::spawn_receive(endpoint.clone(), stream, local, server.address);

                    return Ok((
                        TpHandle {
                            transport: Transport::Connection(write.into()),
                        },
                        server.address,
                    ));
                }
                Some(resolver::Transport::TlsOverTcp) => {
                    #[cfg(feature = "tls-rustls")]
                    if let Some(connector) = &self.rustls_connector {
                        match self
                            .connect_rustls(endpoint, connector, uri, server.address)
                            .await
                        {
                            Ok(v) => return Ok(v),
                            Err(e) => {
                                log::debug!(
                                    "Failed to connect to {} using rustls {e}",
                                    server.address
                                );
                            }
                        }
                    }

                    #[cfg(feature = "tls-native-tls")]
                    if let Some(connector) = &self.native_tls_connector {
                        match self
                            .connect_native_tls(endpoint, connector, uri, server.address)
                            .await
                        {
                            Ok(v) => return Ok(v),
                            Err(e) => {
                                log::debug!(
                                    "Failed to connect to {} using native-tls {e}",
                                    server.address
                                );
                            }
                        }
                    }
                }
            }
        }

        Err(io::Error::other(format!("Failed to select transport for {uri:?}")).into())
    }

    async fn resolve_host_port_with_known_transport(
        &self,
        transport: resolver::Transport,
        host: &Host,
        port: u16,
    ) -> io::Result<Vec<ServerEntry>> {
        match host {
            Host::IP6(ip) => Ok(vec![ServerEntry::from((*ip, port))]),
            Host::IP4(ip) => Ok(vec![ServerEntry::from((*ip, port))]),
            Host::Name(name) => {
                resolver::resolve_host_with_known_transport(
                    &self.dns_resolver,
                    transport,
                    name,
                    port,
                )
                .await
            }
        }
    }

    async fn resolve_uri_with_known_transport(
        &self,
        transport: resolver::Transport,
        uri: &SipUri,
    ) -> io::Result<Vec<ServerEntry>> {
        let port = match uri.host_port.port {
            Some(port) => port,
            None if uri.sips => 5061,
            None => 5060,
        };

        self.resolve_host_port_with_known_transport(transport, &uri.host_port.host, port)
            .await
    }

    async fn select_transport_by_uri_param(
        &self,
        endpoint: &Endpoint,
        uri: &SipUri,
        param: &BytesStr,
    ) -> std::result::Result<(TpHandle, SocketAddr), crate::Error> {
        if param.eq_ignore_ascii_case("udp") {
            let servers = self
                .resolve_uri_with_known_transport(resolver::Transport::Udp, uri)
                .await?;

            let server_entry = servers.first().ok_or_else(|| {
                io::Error::other(format!("Failed to find DNS records for uri {uri:?}"))
            })?;

            let udp_sockets = self.udp_sockets.lock();

            let udp_transport = udp_sockets.first().ok_or_else(|| {
                io::Error::other(
                    "Uri transport param requires UDP transport, but none is available",
                )
            })?;

            Ok((
                TpHandle {
                    transport: Transport::Udp(udp_transport.clone()),
                },
                server_entry.address,
            ))
        } else if param.eq_ignore_ascii_case("tcp") {
            let servers = self
                .resolve_uri_with_known_transport(resolver::Transport::Tcp, uri)
                .await?;

            // Check for existing connection
            {
                let connections = self.connections.lock();
                if let Some(connection) = find_existing_tcp_connection(&servers, &connections) {
                    return Ok((
                        TpHandle {
                            transport: Transport::Connection(connection.clone()),
                        },
                        connection.remote(),
                    ));
                }
            }

            for server in servers {
                let stream = match self.connect_tcp(server.address).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::debug!("Failed to connect to {}, {e}", server.address);
                        continue;
                    }
                };

                let local = stream.local_addr()?;

                let write =
                    streaming::spawn_receive(endpoint.clone(), stream, local, server.address);

                return Ok((
                    TpHandle {
                        transport: Transport::Connection(write.into()),
                    },
                    server.address,
                ));
            }

            Err(io::Error::other(format!("Failed to connect to {uri:?} via TCP")).into())
        } else if param.eq_ignore_ascii_case("tls") {
            let servers = self
                .resolve_uri_with_known_transport(resolver::Transport::TlsOverTcp, uri)
                .await?;

            {
                let connections = self.connections.lock();

                if let Some(connection) = find_existing_tls_connection(&servers, &connections) {
                    return Ok((
                        TpHandle {
                            transport: Transport::Connection(connection.clone()),
                        },
                        connection.remote(),
                    ));
                }
            }

            #[cfg(any(feature = "tls-rustls", feature = "tls-native-tls"))]
            for server in servers {
                #[cfg(feature = "tls-rustls")]
                if let Some(connector) = &self.rustls_connector {
                    match self
                        .connect_rustls(endpoint, connector, uri, server.address)
                        .await
                    {
                        Ok(v) => return Ok(v),
                        Err(e) => {
                            log::debug!("Failed to connect to {} using rustls {e}", server.address);
                        }
                    }
                }

                #[cfg(feature = "tls-native-tls")]
                if let Some(connector) = &self.native_tls_connector {
                    match self
                        .connect_native_tls(endpoint, connector, uri, server.address)
                        .await
                    {
                        Ok(v) => return Ok(v),
                        Err(e) => {
                            log::debug!(
                                "Failed to connect to {} using native-tls {e}",
                                server.address
                            );
                        }
                    }
                }
            }

            Err(io::Error::other(format!("Failed to connect to {uri:?} via TLS")).into())
        } else {
            Err(io::Error::other(format!(
                "Failed to select transport for {uri:?}, unknown transport {param:?}"
            ))
            .into())
        }
    }

    #[cfg(feature = "tls-rustls")]
    async fn connect_rustls(
        &self,
        endpoint: &Endpoint,
        connector: &tokio_rustls::TlsConnector,
        uri: &SipUri,
        address: SocketAddr,
    ) -> Result<(TpHandle, SocketAddr)> {
        use rustls_pki_types::{IpAddr, ServerName};

        let server_name = match uri.host_port.host {
            Host::Name(ref name) => ServerName::try_from(name.as_str())
                .map_err(io::Error::other)?
                .to_owned(),
            Host::IP4(ip) => ServerName::IpAddress(IpAddr::V4(ip.into())),
            Host::IP6(ip) => ServerName::IpAddress(IpAddr::V6(ip.into())),
        };

        let stream = self.connect_tcp(address).await?;
        let local = stream.local_addr()?;

        let stream = tokio_rustls::TlsStream::Client(connector.connect(server_name, stream).await?);

        let write = streaming::spawn_receive(endpoint.clone(), stream, local, address);

        Ok((
            TpHandle {
                transport: Transport::Connection(write.into()),
            },
            address,
        ))
    }

    #[cfg(feature = "tls-native-tls")]
    async fn connect_native_tls(
        &self,
        endpoint: &Endpoint,
        connector: &tokio_native_tls::TlsConnector,
        uri: &SipUri,
        address: SocketAddr,
    ) -> Result<(TpHandle, SocketAddr)> {
        // Best effort to guess the domain. If the `Host` a valid domain this will work,
        // but sometimes it might be an IP address or invalid domain. In that case this might succeed anyway
        // since the TlsConnector might be configured to not use SNI and/or hostname verification
        let domain = uri.host_port.host.to_string();

        let stream = self.connect_tcp(address).await?;
        let local = stream.local_addr()?;

        let stream = connector
            .connect(&domain, stream)
            .await
            .map_err(io::Error::other)?;

        let write = streaming::spawn_receive(endpoint.clone(), stream, local, address);

        Ok((
            TpHandle {
                transport: Transport::Connection(write.into()),
            },
            address,
        ))
    }

    async fn connect_tcp(&self, address: SocketAddr) -> Result<TcpStream, io::Error> {
        if let Some(bind_addr) = self.tcp_connect_bind_addr {
            let socket = match bind_addr {
                SocketAddr::V4(..) => TcpSocket::new_v4()?,
                SocketAddr::V6(..) => TcpSocket::new_v6()?,
            };

            socket.set_reuseaddr(true)?;
            socket.bind(bind_addr)?;
            socket.connect(address).await
        } else {
            TcpStream::connect(address).await
        }
    }

    pub(crate) async fn receive_stun(
        &self,
        message: Message,
        source: SocketAddr,
        transport: TpHandle,
    ) {
        self.stun.receive(message, source, transport).await
    }
}

fn find_existing_tcp_connection<'a>(
    servers: &[ServerEntry],
    connections: &'a MutexGuard<'_, Vec<Connection>>,
) -> Option<&'a Connection> {
    connections.iter().find(|connection| {
        matches!(connection, Connection::Tcp(..))
            && servers.iter().any(|s| s.address == connection.remote())
    })
}

fn find_existing_tls_connection<'a>(
    servers: &[ServerEntry],
    connections: &'a MutexGuard<'_, Vec<Connection>>,
) -> Option<&'a Connection> {
    connections.iter().find(|connection| {
        connection.is_tls() && servers.iter().any(|s| s.address == connection.remote())
    })
}

#[derive(Default)]
pub(crate) struct TransportsBuilder {
    udp_sockets: Vec<UdpTransport>,

    tcp_connect_bind_addr: Option<SocketAddr>,

    #[cfg(feature = "tls-rustls")]
    rustls_connector: Option<tokio_rustls::TlsConnector>,

    #[cfg(feature = "tls-native-tls")]
    native_tls_connector: Option<tokio_native_tls::TlsConnector>,

    dns_resolver: Option<hickory_resolver::TokioResolver>,
}

impl TransportsBuilder {
    pub(crate) fn set_dns_resolver(&mut self, dns_resolver: hickory_resolver::TokioResolver) {
        self.dns_resolver = Some(dns_resolver);
    }

    pub(super) async fn bind_udp(
        &mut self,
        endpoint: broadcast::Receiver<Endpoint>,
        addr: SocketAddr,
    ) -> io::Result<TpHandle> {
        let udp = UdpTransport::bind(endpoint, addr).await?;

        self.udp_sockets.push(udp.clone());

        Ok(TpHandle {
            transport: Transport::Udp(udp),
        })
    }

    pub(super) async fn listen_tcp(
        &mut self,
        endpoint: broadcast::Receiver<Endpoint>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        streaming::bind_tcp(endpoint, addr).await
    }

    #[cfg(feature = "tls-rustls")]
    pub(super) async fn listen_rustls(
        &mut self,
        endpoint: broadcast::Receiver<Endpoint>,
        addr: SocketAddr,
        acceptor: tokio_rustls::TlsAcceptor,
    ) -> io::Result<()> {
        streaming::bind_rustls(endpoint, addr, acceptor).await
    }

    #[cfg(feature = "tls-native-tls")]
    pub(super) async fn listen_native_tls(
        &mut self,
        endpoint: broadcast::Receiver<Endpoint>,
        addr: SocketAddr,
        acceptor: tokio_native_tls::TlsAcceptor,
    ) -> io::Result<()> {
        streaming::bind_native_tls(endpoint, addr, acceptor).await
    }

    pub(crate) fn set_tcp_connect_bind_addr(&mut self, addr: SocketAddr) {
        self.tcp_connect_bind_addr = Some(addr);
    }

    #[cfg(feature = "tls-rustls")]
    pub(crate) fn set_rustls_connector(&mut self, connector: tokio_rustls::TlsConnector) {
        self.rustls_connector = Some(connector);
    }

    #[cfg(feature = "tls-native-tls")]
    pub(crate) fn set_native_tls_connector(&mut self, connector: tokio_native_tls::TlsConnector) {
        self.native_tls_connector = Some(connector);
    }

    pub(crate) fn build(&mut self) -> Transports {
        let dns_resolver = self.dns_resolver.take().unwrap_or_else(|| {
            hickory_resolver::TokioResolver::builder_tokio()
                .expect("Failed to create default system DNS resolver")
                .build()
        });

        Transports {
            udp_sockets: Mutex::new(take(&mut self.udp_sockets)),
            connections: Mutex::new(Vec::new()),
            tcp_connect_bind_addr: self.tcp_connect_bind_addr,
            #[cfg(feature = "tls-rustls")]
            rustls_connector: self.rustls_connector.take(),
            #[cfg(feature = "tls-native-tls")]
            native_tls_connector: self.native_tls_connector.take(),
            stun: StunEndpoint::new(StunUser),
            dns_resolver,
        }
    }
}
