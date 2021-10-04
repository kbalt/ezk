use super::generalized::{Streaming, StreamingTransport};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_stream::Stream;

#[derive(Debug)]
pub struct Tcp;

#[async_trait::async_trait]
impl StreamingTransport for Tcp {
    type Streaming = TcpStream;
    type Incoming = TcpAcceptStream;

    const NAME: &'static str = "TCP";
    const SECURE: bool = false;

    async fn connect<A: ToSocketAddrs + Send>(&self, addr: A) -> io::Result<Self::Streaming> {
        TcpStream::connect(addr).await
    }

    async fn bind<A: ToSocketAddrs + Send>(
        &self,
        addr: A,
    ) -> io::Result<(Self::Incoming, SocketAddr)> {
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;

        Ok((TcpAcceptStream(listener), bound))
    }
}

impl Streaming for TcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }
}

pub struct TcpAcceptStream(TcpListener);

impl Stream for TcpAcceptStream {
    type Item = io::Result<(TcpStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.0).poll_accept(cx) {
            Poll::Ready(ready) => Poll::Ready(Some(ready)),
            Poll::Pending => Poll::Pending,
        }
    }
}
