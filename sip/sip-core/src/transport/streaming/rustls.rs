use super::{StreamingListener, StreamingTransport};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsStream};

pub(super) struct TlsAcceptStream {
    acceptor: TlsAcceptor,
    listener: TcpListener,
}

impl TlsAcceptStream {
    pub(super) fn new(acceptor: TlsAcceptor, listener: TcpListener) -> Self {
        Self { acceptor, listener }
    }
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

impl StreamingTransport for TlsStream<TcpStream> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.local_addr()
    }
}
