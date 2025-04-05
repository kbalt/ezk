use super::streaming::{
    StreamingFactory, StreamingListener, StreamingListenerBuilder, StreamingTransport,
};
use sip_types::uri::SipUri;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_native_tls::{native_tls, TlsAcceptor, TlsConnector, TlsStream};

// ==== Connector

#[async_trait::async_trait]
impl StreamingFactory for TlsConnector {
    type Transport = TlsStream<TcpStream>;

    async fn connect<A: ToSocketAddrs + Send>(
        &self,
        uri: &SipUri,
        addr: SocketAddr,
    ) -> io::Result<Self::Transport> {
        // Best effort to guess the domain. If the `Host` a valid domain this will work,
        // but sometimes it might be an IP address or invalid domain. In that case this might succeed anyway
        // since the TlsConnector might be configured to not use SNI and/or hostname verification
        let domain = uri.host_port.host.to_string();

        let stream = TcpStream::connect(addr).await?;
        let stream = self
            .connect(&domain, stream)
            .await
            .map_err(native_tls_err_to_io_err)?;

        Ok(stream)
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
        let stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(native_tls_err_to_io_err)?;
        Ok((stream, remote))
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
        self.get_ref().get_ref().get_ref().local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().get_ref().get_ref().peer_addr()
    }
}

fn native_tls_err_to_io_err(e: native_tls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}
