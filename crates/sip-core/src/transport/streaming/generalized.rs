use super::decode::StreamingDecoder;
use crate::transport::managed::DropNotifier;
use crate::transport::{Direction, Factory, ReceivedMessage, TpHandle, TpKey, Transport};
use crate::{Endpoint, EndpointBuilder};
use sip_types::uri::UriInfo;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;
use std::{fmt, io};
use tokio::io::{split, AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::ToSocketAddrs;
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio::time::{sleep, Sleep};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;

/// Helper trait to implement the transport specific behavior of binding to an address
#[async_trait::async_trait]
pub trait StreamingListenerBuilder: Sized + Send + Sync + 'static {
    type Transport: StreamingTransport;
    type StreamingListener: StreamingListener<Transport = Self::Transport>;

    async fn bind<A: ToSocketAddrs + Send>(
        self,
        addr: A,
    ) -> io::Result<(Self::StreamingListener, SocketAddr)>;

    async fn spawn<A: ToSocketAddrs + Send>(
        self,
        endpoint: &mut EndpointBuilder,
        addr: A,
    ) -> io::Result<()> {
        let (listener, bound) = self.bind(addr).await?;

        log::info!(
            "Accepting {} connections on {}",
            Self::Transport::NAME,
            bound
        );

        tokio::spawn(task_accept(endpoint.subscribe(), listener));

        Ok(())
    }
}

#[async_trait::async_trait]
pub trait StreamingFactory: Send + Sync + 'static {
    type Transport: StreamingTransport;

    async fn connect<A: ToSocketAddrs + Send>(
        &self,
        uri_info: &UriInfo,
        addr: A,
    ) -> io::Result<Self::Transport>;
}

pub trait StreamingTransport: AsyncWrite + AsyncRead + Send + Sync + 'static {
    const NAME: &'static str;
    const SECURE: bool;

    fn matches_transport_param(name: &str) -> bool {
        name.eq_ignore_ascii_case(Self::NAME)
    }

    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
}

#[async_trait::async_trait]
pub trait StreamingListener: Send + Sync {
    type Transport: StreamingTransport;

    async fn accept(&mut self) -> io::Result<(Self::Transport, SocketAddr)>;
}

pub struct StreamingWrite<T> {
    bound: SocketAddr,
    remote: SocketAddr,
    incoming: bool,

    socket: Mutex<WriteHalf<T>>,
}

impl<T: StreamingTransport> fmt::Debug for StreamingWrite<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingWrite")
            .field("bound", &self.bound)
            .field("remote", &self.remote)
            .field("incoming", &self.incoming)
            .finish()
    }
}

impl<T: StreamingTransport> fmt::Display for StreamingWrite<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:bound={}:remote={}", T::NAME, self.bound, self.remote,)
    }
}

#[async_trait::async_trait]
impl<T> Transport for StreamingWrite<T>
where
    T: StreamingTransport,
{
    fn name(&self) -> &'static str {
        T::NAME
    }

    fn matches_transport_param(&self, name: &str) -> bool {
        T::matches_transport_param(name)
    }

    fn secure(&self) -> bool {
        T::SECURE
    }

    fn reliable(&self) -> bool {
        true
    }

    fn bound(&self) -> SocketAddr {
        self.bound
    }

    fn sent_by(&self) -> SocketAddr {
        self.bound
    }

    fn direction(&self) -> Direction {
        if self.incoming {
            Direction::Incoming(self.remote)
        } else {
            Direction::Outgoing(self.remote)
        }
    }

    async fn send(&self, bytes: &[u8], _target: &[SocketAddr]) -> io::Result<()> {
        let mut socket = self.socket.lock().await;
        socket.write_all(bytes).await?;
        socket.flush().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl<T> Factory for T
where
    T: StreamingFactory,
{
    fn name(&self) -> &'static str {
        T::Transport::NAME
    }

    fn secure(&self) -> bool {
        T::Transport::SECURE
    }

    fn matches_transport_param(&self, name: &str) -> bool {
        T::Transport::matches_transport_param(name)
    }

    async fn create(
        &self,
        endpoint: Endpoint,
        uri_info: &UriInfo,
        addrs: &[SocketAddr],
    ) -> io::Result<(TpHandle, SocketAddr)> {
        let mut last_err = io::Error::new(io::ErrorKind::Other, "empty addrs");

        for &addr in addrs {
            log::trace!("trying to connect to {}", addr);

            match self.connect(uri_info, addr).await {
                Ok(stream) => {
                    let local = stream.local_addr()?;
                    let remote = stream.peer_addr()?;

                    let (read, write) = split(stream);

                    let transport = StreamingWrite {
                        bound: local,
                        remote,
                        socket: Mutex::new(write),
                        incoming: false,
                    };

                    let framed = FramedRead::new(read, StreamingDecoder::new(endpoint.parser()));

                    let (transport, notifier) = endpoint.transports().add_managed_used(transport);

                    tokio::spawn(receive_task(
                        endpoint.clone(),
                        framed,
                        ReceiveTaskState::InUse(notifier),
                        local,
                        remote,
                        false,
                    ));

                    return Ok((transport, remote));
                }
                Err(e) => last_err = e,
            };
        }

        Err(last_err)
    }
}

async fn task_accept<I>(mut endpoint: broadcast::Receiver<Endpoint>, mut incoming: I)
where
    I: StreamingListener,
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
                        log::error!("Could not retrieve local addr for incoming stream {}", e);
                        continue;
                    }
                };

                log::trace!("Connection accepted from {} on {}", remote, local);

                let (read, write) = split(stream);

                let transport = StreamingWrite {
                    bound: local,
                    remote,
                    socket: Mutex::new(write),
                    incoming: true,
                };

                let rx = endpoint.transports().add_managed_unused(transport);

                let framed = FramedRead::new(read, StreamingDecoder::new(endpoint.parser()));

                tokio::spawn(receive_task(
                    endpoint.clone(),
                    framed,
                    ReceiveTaskState::Unused(Box::pin(sleep(Duration::from_secs(32))), rx),
                    local,
                    remote,
                    true,
                ));
            }
            Err(e) => log::error!("Error accepting connection, {}", e),
        }
    }
}

enum ReceiveTaskState {
    InUse(DropNotifier),
    Unused(Pin<Box<Sleep>>, oneshot::Receiver<DropNotifier>),
}

async fn receive_task<T>(
    endpoint: Endpoint,
    mut framed: FramedRead<ReadHalf<T>, StreamingDecoder>,
    mut state: ReceiveTaskState,
    local: SocketAddr,
    remote: SocketAddr,
    incoming: bool,
) where
    T: StreamingTransport,
{
    let tp_key = TpKey {
        name: T::NAME,
        bound: local,
        direction: if incoming {
            Direction::Incoming(remote)
        } else {
            Direction::Outgoing(remote)
        },
    };

    let _drop_guard = UnclaimedGuard {
        endpoint: &endpoint,
        tp_key,
    };

    loop {
        let item = match &mut state {
            ReceiveTaskState::InUse(notifier) => {
                tokio::select! {
                    item = framed.next() => {
                        item
                    }
                    _ = notifier => {
                        log::debug!("all refs to transport dropped, destroying soon if not used");
                        let rx = endpoint.transports().set_unused(&tp_key);
                        state = ReceiveTaskState::Unused(Box::pin(sleep(Duration::from_secs(32))), rx);
                        continue;
                    }
                }
            }
            ReceiveTaskState::Unused(timeout, rx) => {
                tokio::select! {
                    item = framed.next() => {
                        item
                    }
                    notifier = rx => {
                        if let Ok(notifier) = notifier {
                            state = ReceiveTaskState::InUse(notifier);

                            continue;
                        } else {
                            log::error!("failed to receive notifier");
                            return;
                        }
                    }
                    _ = timeout => {
                        log::debug!("dropping transport, not used anymore");
                        return;
                    }
                }
            }
        };

        let transport = endpoint.transports().set_used(&tp_key);

        let message = match item {
            Some(Ok(item)) => item,
            Some(Err(e)) => {
                log::warn!("An error occurred when reading {} stream {}", T::NAME, e);
                return;
            }
            None => {
                log::debug!("Connection closed");
                return;
            }
        };

        let message = ReceivedMessage::new(
            remote,
            message.buffer,
            transport,
            message.line,
            message.headers,
            message.body,
        );

        endpoint.receive(message);
    }
}

struct UnclaimedGuard<'e> {
    endpoint: &'e Endpoint,
    tp_key: TpKey,
}

impl Drop for UnclaimedGuard<'_> {
    fn drop(&mut self) {
        self.endpoint.transports().drop_transport(&self.tp_key);
    }
}
