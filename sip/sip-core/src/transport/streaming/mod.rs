use crate::Endpoint;
use crate::transport::{
    ReceivedMessage, TpHandle, Transport, TransportCloseReason, TransportState,
};
use decode::{Item, StreamingDecoder};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use std::{io, time::Duration};
use tokio::io::WriteHalf;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, split},
    sync::{Mutex, broadcast},
    time::interval,
};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;

mod decode;
#[cfg(feature = "tls-native-tls")]
mod native_tls;
#[cfg(feature = "tls-rustls")]
mod rustls;
mod tcp;

pub(super) trait StreamingTransport: AsyncWrite + AsyncRead + Send + Sync + 'static {
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

#[async_trait::async_trait]
pub(super) trait StreamingListener: Send + Sync {
    type Transport: StreamingTransport;

    async fn accept(&mut self) -> io::Result<(Self::Transport, SocketAddr)>;
}

#[derive(Debug)]
pub(super) struct StreamingWrite<T> {
    pub(super) bound: SocketAddr,
    pub(super) remote: SocketAddr,

    state: watch::Receiver<TransportState>,

    write: Arc<Mutex<WriteHalf<T>>>,
    modified: Arc<parking_lot::Mutex<Instant>>,
}

impl<T> Clone for StreamingWrite<T> {
    fn clone(&self) -> Self {
        *self.modified.lock() = Instant::now();

        Self {
            bound: self.bound,
            remote: self.remote,
            state: self.state.clone(),
            write: self.write.clone(),
            modified: self.modified.clone(),
        }
    }
}

impl<T> Drop for StreamingWrite<T> {
    fn drop(&mut self) {
        *self.modified.lock() = Instant::now();
    }
}

impl<T: AsyncWrite> StreamingWrite<T> {
    pub(super) async fn send(&self, buf: &[u8]) -> io::Result<()> {
        self.write.lock().await.write_all(buf).await
    }

    pub(super) fn state_receiver(&self) -> watch::Receiver<TransportState> {
        self.state.clone()
    }

    // TODO: workaround comparing connections
    fn ptr_eq<U>(&self, rhs: &StreamingWrite<U>) -> bool {
        let lhs = Arc::as_ptr(&self.write).cast::<()>();
        let rhs = Arc::as_ptr(&rhs.write).cast::<()>();

        lhs == rhs
    }
}

async fn task_accept<I>(mut endpoint: broadcast::Receiver<Endpoint>, mut incoming: I)
where
    I: StreamingListener,
    super::Connection: From<StreamingWrite<I::Transport>>,
{
    let endpoint = match endpoint.recv().await.ok() {
        Some(endpoint) => endpoint,
        None => return,
    };

    loop {
        match incoming.accept().await {
            Ok((stream, remote)) => {
                let local = match stream.local_addr() {
                    Ok(local) => local,
                    Err(e) => {
                        log::error!("Could not retrieve local addr for incoming stream {e}");
                        continue;
                    }
                };

                log::trace!("Connection accepted from {remote} on {local}");

                spawn_receive(endpoint.clone(), stream, local, remote);
            }
            Err(e) => log::error!("Error accepting connection, {e}"),
        }
    }
}

pub(super) fn spawn_receive<S: StreamingTransport>(
    endpoint: Endpoint,
    stream: S,
    bound: SocketAddr,
    remote: SocketAddr,
) -> StreamingWrite<S>
where
    super::Connection: From<StreamingWrite<S>>,
{
    let (read, write) = split(stream);

    let write = Arc::new(Mutex::new(write));

    let (state_tx, state_rx) = watch::channel(TransportState::Ok);

    let stream = StreamingWrite {
        bound,
        remote,
        state: state_rx,
        write: write.clone(),
        modified: Arc::new(parking_lot::Mutex::new(Instant::now())),
    };

    endpoint
        .transports()
        .connections
        .lock()
        .push(stream.clone().into());

    let read = FramedRead::new(read, StreamingDecoder::default());

    tokio::spawn(receive_task(
        endpoint,
        read,
        stream.clone(),
        remote,
        state_tx,
    ));

    stream
}

async fn receive_task<T>(
    endpoint: Endpoint,
    mut framed: FramedRead<ReadHalf<T>, StreamingDecoder>,
    transport: StreamingWrite<T>,
    remote: SocketAddr,
    state_tx: watch::Sender<TransportState>,
) where
    T: StreamingTransport,
    super::Connection: From<StreamingWrite<T>>,
{
    let mut drop_guard = RemoveConnectionOnDrop {
        endpoint: &endpoint,
        transport: &transport,
        removed: false,
    };

    let mut keep_alive_request_interval = interval(Duration::from_secs(10));

    loop {
        let item = tokio::select! {
            item = framed.next() => item,
            _ = keep_alive_request_interval.tick() => {
                // Check if the connection is still being used
                {
                    // Lock connection list to avoid the connecting being cloned between testing reference count & removing it
                    let connections = endpoint.transports().connections.lock();

                    if Arc::strong_count(&transport.write) == 2 && transport.modified.lock().elapsed() > Duration::from_mins(15) {
                        log::debug!("Connection to {remote} unused for some time, removing it");
                        let _ = state_tx.send_replace(TransportState::Closed(TransportCloseReason::Inactivity));
                        drop_guard.trigger_locked(connections);
                        return;
                    }
                }

                if let Err(e) = transport.send(b"\r\n\r\n").await {
                    log::debug!("Failed to send keep alive request, {e}");
                }
                continue;
            }
        };

        let message = match item {
            Some(Ok(Item::DecodedMessage(item))) => item,
            Some(Ok(Item::KeepAliveRequest)) => {
                if let Err(e) = transport.send(b"\r\n").await {
                    log::debug!("Failed to respond to keep alive request, {e}");
                }

                continue;
            }
            Some(Ok(Item::KeepAliveResponse)) => {
                // discard responses for now
                continue;
            }
            Some(Err(e)) => {
                log::warn!("An error occurred when reading stream {}", e);
                let _ = state_tx.send_replace(TransportState::Closed(TransportCloseReason::Err(e)));
                return;
            }
            None => {
                log::debug!("Connection closed by remote");
                let _ = state_tx.send_replace(TransportState::Closed(TransportCloseReason::Err(
                    io::Error::from(io::ErrorKind::UnexpectedEof),
                )));
                return;
            }
        };

        let message = ReceivedMessage::new(
            remote,
            message.buffer,
            TpHandle {
                transport: Transport::Connection(transport.clone().into()),
            },
            message.line,
            message.headers,
            message.body,
        );

        endpoint.receive(message);
    }
}

struct RemoveConnectionOnDrop<'e, T> {
    endpoint: &'e Endpoint,
    transport: &'e StreamingWrite<T>,
    removed: bool,
}

impl<T> Drop for RemoveConnectionOnDrop<'_, T> {
    fn drop(&mut self) {
        if self.removed {
            return;
        }

        let connections = self.endpoint.transports().connections.lock();

        self.trigger_locked(connections);
    }
}

impl<'e, T> RemoveConnectionOnDrop<'e, T> {
    fn trigger_locked(
        &mut self,
        mut connections: parking_lot::MutexGuard<'_, Vec<super::Connection>>,
    ) {
        let position = connections.iter().position(|c| match c {
            super::Connection::Tcp(t) => t.ptr_eq(self.transport),
            #[cfg(feature = "tls-rustls")]
            super::Connection::Rustls(t) => t.ptr_eq(self.transport),
            #[cfg(feature = "tls-native-tls")]
            super::Connection::NativeTls(t) => t.ptr_eq(self.transport),
        });

        if let Some(position) = position {
            connections.swap_remove(position);
            self.removed = true;
        }
    }
}

pub(super) async fn bind_tcp(
    endpoint: broadcast::Receiver<Endpoint>,
    addr: SocketAddr,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tokio::spawn(task_accept(endpoint, listener));
    Ok(())
}

#[cfg(feature = "tls-rustls")]
pub(super) async fn bind_rustls(
    endpoint: broadcast::Receiver<Endpoint>,
    addr: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tokio::spawn(task_accept(
        endpoint,
        rustls::TlsAcceptStream::new(acceptor, listener),
    ));
    Ok(())
}

#[cfg(feature = "tls-native-tls")]
pub(super) async fn bind_native_tls(
    endpoint: broadcast::Receiver<Endpoint>,
    addr: SocketAddr,
    acceptor: tokio_native_tls::TlsAcceptor,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tokio::spawn(task_accept(
        endpoint,
        native_tls::TlsAcceptStream::new(acceptor, listener),
    ));
    Ok(())
}
