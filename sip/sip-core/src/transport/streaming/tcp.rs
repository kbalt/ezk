use super::{StreamingListener, StreamingTransport};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

#[async_trait::async_trait]
impl StreamingListener for TokioTcpListener {
    type Transport = TcpStream;

    async fn accept(&mut self) -> io::Result<(Self::Transport, SocketAddr)> {
        TokioTcpListener::accept(self).await
    }
}

impl StreamingTransport for TcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }
}
