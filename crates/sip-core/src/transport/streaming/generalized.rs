use super::decode::StreamingDecoder;
use crate::transport::managed::DropNotifier;
use crate::transport::{Direction, Factory, ReceivedMessage, TpHandle, TpKey, Transport};
use crate::{Endpoint, EndpointBuilder};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};
use tokio::io::{split, AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::ToSocketAddrs;
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio::time::{sleep, Sleep};
use tokio_stream::{Stream, StreamExt};
use tokio_util::codec::FramedRead;

#[async_trait::async_trait]
pub trait StreamingTransport: Sized + Send + Sync + 'static {
    type Streaming: Streaming;
    type Incoming: Stream<Item = io::Result<(Self::Streaming, SocketAddr)>> + Unpin + Send + Sync;

    const NAME: &'static str;
    const SECURE: bool;

    async fn connect<A: ToSocketAddrs + Send>(&self, addr: A) -> io::Result<Self::Streaming>;
    async fn bind<A: ToSocketAddrs + Send>(
        &self,
        addr: A,
    ) -> io::Result<(Self::Incoming, SocketAddr)>;

    async fn spawn<A: ToSocketAddrs + Send>(
        self,
        endpoint: &mut EndpointBuilder,
        addr: A,
    ) -> io::Result<()> {
        let (listener, bound) = self.bind(addr).await?;

        log::info!("Accepting {} connections on {}", Self::NAME, bound);

        let factory: Arc<dyn Factory> = Arc::new(StreamingFactory::<Self> { inner: self, bound });

        endpoint.add_transport_factory(factory);

        tokio::spawn(task_accept::<Self>(endpoint.subscribe(), listener, bound));

        Ok(())
    }
}

pub trait Streaming: fmt::Debug + AsyncWrite + AsyncRead + Send + Sync {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
}

pub struct StreamingWrite<T>
where
    T: StreamingTransport,
{
    listener: SocketAddr,
    bound: SocketAddr,
    remote: SocketAddr,
    incoming: bool,

    socket: Mutex<WriteHalf<T::Streaming>>,
}

impl<T> fmt::Debug for StreamingWrite<T>
where
    T: StreamingTransport,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingWrite")
            .field("listener", &self.listener)
            .field("bound", &self.bound)
            .field("remote", &self.remote)
            .field("incoming", &self.incoming)
            .field("socket", &self.socket)
            .finish()
    }
}

impl<T> fmt::Display for StreamingWrite<T>
where
    T: StreamingTransport,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:bound={}:remote={}:listener={}",
            T::NAME,
            self.bound,
            self.remote,
            self.listener
        )
    }
}

#[async_trait::async_trait]
impl<T: StreamingTransport> Transport for StreamingWrite<T> {
    fn name(&self) -> &'static str {
        T::NAME
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
        self.listener
    }

    fn direction(&self) -> Direction {
        if self.incoming {
            Direction::Incoming(self.remote)
        } else {
            Direction::Outgoing(self.remote)
        }
    }

    async fn send(&self, bytes: &[u8], _target: SocketAddr) -> io::Result<()> {
        let mut socket = self.socket.lock().await;
        socket.write_all(bytes).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct StreamingFactory<T>
where
    T: StreamingTransport,
{
    inner: T,
    bound: SocketAddr,
}

#[async_trait::async_trait]
impl<T> Factory for StreamingFactory<T>
where
    T: StreamingTransport,
{
    fn name(&self) -> &'static str {
        T::NAME
    }

    fn secure(&self) -> bool {
        T::SECURE
    }

    async fn create(
        &self,
        endpoint: Endpoint,
        addrs: &[SocketAddr],
    ) -> io::Result<(TpHandle, SocketAddr)> {
        let mut last_err = io::Error::new(io::ErrorKind::Other, "empty addrs");

        for &addr in addrs {
            log::trace!("trying to connect to {}", addr);

            match self.inner.connect(addr).await {
                Ok(stream) => {
                    let local = stream.local_addr()?;
                    let remote = stream.peer_addr()?;

                    let (read, write) = split(stream);

                    let transport = StreamingWrite::<T> {
                        listener: self.bound,
                        bound: local,
                        remote,
                        socket: Mutex::new(write),
                        incoming: false,
                    };

                    let framed = FramedRead::new(read, StreamingDecoder::new(endpoint.parser()));

                    let (transport, notifier) = endpoint.transports().add_managed_used(transport);

                    tokio::spawn(receive_task::<T>(
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

async fn task_accept<T>(
    mut endpoint: broadcast::Receiver<Endpoint>,
    mut incoming: T::Incoming,
    bound: SocketAddr,
) where
    T: StreamingTransport,
{
    let endpoint = match endpoint.recv().await.ok() {
        Some(endpoint) => endpoint,
        None => return,
    };

    loop {
        match incoming.next().await {
            Some(Ok((stream, remote))) => {
                let local = match stream.local_addr() {
                    Ok(local) => local,
                    Err(e) => {
                        log::error!("Could not retrieve local addr for incoming stream {}", e);
                        continue;
                    }
                };

                log::trace!("Connection accepted from {} on {}", remote, local);

                let (read, write) = split(stream);

                let transport = StreamingWrite::<T> {
                    listener: bound,
                    bound: local,
                    remote,
                    socket: Mutex::new(write),
                    incoming: true,
                };

                let rx = endpoint.transports().add_managed_unused(transport);

                let framed = FramedRead::new(read, StreamingDecoder::new(endpoint.parser()));

                tokio::spawn(receive_task::<T>(
                    endpoint.clone(),
                    framed,
                    ReceiveTaskState::Unused(Box::pin(sleep(Duration::from_secs(32))), rx),
                    local,
                    remote,
                    true,
                ));
            }
            Some(Err(e)) => log::error!("Error accepting connection, {}", e),
            None => log::error!("Error accepting connection"),
        }
    }
}

enum ReceiveTaskState {
    InUse(DropNotifier),
    Unused(Pin<Box<Sleep>>, oneshot::Receiver<DropNotifier>),
}

async fn receive_task<T>(
    endpoint: Endpoint,
    mut framed: FramedRead<ReadHalf<T::Streaming>, StreamingDecoder>,
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
