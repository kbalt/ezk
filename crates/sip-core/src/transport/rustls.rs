use super::streaming::{
    StreamingFactory, StreamingListener, StreamingListenerBuilder, StreamingTransport,
};
use rustls_pki_types::{IpAddr, ServerName};
use sip_types::{host::Host, uri::UriInfo};
use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

// ==== Connector

#[async_trait::async_trait]
impl StreamingFactory for TlsConnector {
    type Transport = TlsStream<TcpStream>;

    async fn connect<A: ToSocketAddrs + Send>(
        &self,
        uri_info: &UriInfo,
        addr: A,
    ) -> io::Result<Self::Transport> {
        let server_name = match uri_info.host_port.host {
            Host::Name(ref name) => ServerName::try_from(name.as_str())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                .to_owned(),
            Host::IP4(ip) => ServerName::IpAddress(IpAddr::V4(ip.into())),
            Host::IP6(ip) => ServerName::IpAddress(IpAddr::V6(ip.into())),
        };

        let stream = TcpStream::connect(addr).await?;
        let stream = self.connect(server_name, stream).await?;

        Ok(TlsStream::Client(stream))
    }
}

// ==== Listener

#[async_trait::async_trait]
impl StreamingListenerBuilder for TlsAcceptor {
    type Transport = TlsStream<TcpStream>;
    type StreamingListener = TlsAcceptStream;

    async fn bind<A: ToSocketAddrs + Send>(
        self,
        addr: A,
    ) -> io::Result<(Self::StreamingListener, SocketAddr)> {
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;

        Ok((
            TlsAcceptStream {
                listener,
                acceptor: self,
            },
            bound,
        ))
    }
}

pub struct TlsAcceptStream {
    acceptor: TlsAcceptor,
    listener: TcpListener,
}

#[async_trait::async_trait]
impl StreamingListener for TlsAcceptStream {
    type Transport = TlsStream<TcpStream>;

    async fn accept(&mut self) -> io::Result<(Self::Transport, SocketAddr)> {
        let (stream, remote) = self.listener.accept().await?;
        let stream = self.acceptor.accept(stream).await?;
        Ok((TlsStream::Server(stream), remote))
    }
}

// ==== Transport

impl StreamingTransport for TlsStream<TcpStream> {
    const NAME: &'static str = "TLS";
    const SECURE: bool = true;

    fn matches_transport_param(name: &str) -> bool {
        name.eq_ignore_ascii_case("tls") || name.eq_ignore_ascii_case("tcp")
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.peer_addr()
    }
}
