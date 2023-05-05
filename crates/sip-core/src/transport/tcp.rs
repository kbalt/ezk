use super::streaming::{
    StreamingFactory, StreamingListener, StreamingListenerBuilder, StreamingTransport,
};
use sip_types::uri::UriInfo;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream, ToSocketAddrs};

// ==== Connector

#[derive(Default)]
pub struct TcpConnector {
    _priv: (),
}

impl TcpConnector {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl StreamingFactory for TcpConnector {
    type Transport = TcpStream;

    async fn connect<A: ToSocketAddrs + Send>(
        &self,
        _: &UriInfo,
        addr: A,
    ) -> io::Result<Self::Transport> {
        TcpStream::connect(addr).await
    }
}

// ==== Listener

#[derive(Default)]
pub struct TcpListener {
    _priv: (),
}

impl TcpListener {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl StreamingListenerBuilder for TcpListener {
    type Transport = TcpStream;
    type StreamingListener = TokioTcpListener;

    async fn bind<A: ToSocketAddrs + Send>(
        self,
        addr: A,
    ) -> io::Result<(Self::StreamingListener, SocketAddr)> {
        let listener = TokioTcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;

        Ok((listener, bound))
    }
}

#[async_trait::async_trait]
impl StreamingListener for TokioTcpListener {
    type Transport = TcpStream;

    async fn accept(&mut self) -> io::Result<(Self::Transport, SocketAddr)> {
        TokioTcpListener::accept(self).await
    }
}

// ==== Transport

impl StreamingTransport for TcpStream {
    const NAME: &'static str = "TCP";
    const SECURE: bool = false;

    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }
}
