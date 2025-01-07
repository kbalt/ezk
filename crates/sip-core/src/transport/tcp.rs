use super::streaming::{
    StreamingFactory, StreamingListener, StreamingListenerBuilder, StreamingTransport,
};
use sip_types::uri::UriInfo;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener as TokioTcpListener, TcpSocket, TcpStream, ToSocketAddrs};

// ==== Connector

#[derive(Default)]
pub struct TcpConnector {
    _priv: (),
    bind_addr: Option<SocketAddr>,
}

impl TcpConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_bind(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr: Some(bind_addr),
            ..Self::default()
        }
    }
}

#[async_trait::async_trait]
impl StreamingFactory for TcpConnector {
    type Transport = TcpStream;

    async fn connect<A: ToSocketAddrs + Send>(
        &self,
        _: &UriInfo,
        addr: SocketAddr,
    ) -> io::Result<Self::Transport> {
        if let Some(bind_addr) = self.bind_addr {
            let socket = match bind_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4()?,
                SocketAddr::V6(_) => TcpSocket::new_v6()?,
            };
            socket.set_reuseaddr(true)?;
            socket.bind(bind_addr)?;
            socket.connect(addr).await
        } else {
            TcpStream::connect(addr).await
        }
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
