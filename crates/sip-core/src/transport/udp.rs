use crate::transport::{parse_line, Direction, ReceivedMessage, TpHandle, Transport};
use crate::{Endpoint, EndpointBuilder, Error, Result, WithStatus};
use anyhow::anyhow;
use bytes::Bytes;
use sip_types::header::typed::ContentLength;
use sip_types::msg::{MessageLine, PullParser};
use sip_types::parse::ParseCtx;
use sip_types::{Code, Headers};
use std::net::SocketAddr;
use std::str::from_utf8;
use std::sync::Arc;
use std::{fmt, io};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::broadcast;

const UDP: &str = "UDP";
const MAX_MSG_SIZE: usize = u16::MAX as usize;

#[derive(Debug)]
struct Inner {
    bound: SocketAddr,
    socket: UdpSocket,
}

#[derive(Debug)]
pub struct Udp {
    inner: Arc<Inner>,
}

impl fmt::Display for Udp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "udp:bound={}", self.inner.bound)
    }
}

impl Udp {
    pub async fn spawn<A>(builder: &mut EndpointBuilder, addr: A) -> io::Result<()>
    where
        A: ToSocketAddrs,
    {
        let socket = UdpSocket::bind(addr).await?;
        let bound = socket.local_addr()?;

        log::info!("Bound UDP to {}", bound);

        let inner = Arc::new(Inner { bound, socket });

        tokio::spawn(receive_task(builder.subscribe(), inner.clone()));

        builder.add_unmanaged_transport(Udp { inner });

        Ok(())
    }
}

#[async_trait::async_trait]
impl Transport for Udp {
    fn name(&self) -> &'static str {
        UDP
    }

    fn secure(&self) -> bool {
        false
    }

    fn reliable(&self) -> bool {
        false
    }

    fn bound(&self) -> SocketAddr {
        self.inner.bound
    }

    fn sent_by(&self) -> SocketAddr {
        self.inner.bound
    }

    fn direction(&self) -> Direction {
        Direction::None
    }

    async fn send(&self, bytes: &[u8], target: &[SocketAddr]) -> io::Result<()> {
        let target = target
            .iter()
            .find(|ip| ip.is_ipv4() == self.bound().is_ipv4());

        if let Some(target) = target {
            self.inner.socket.send_to(bytes, target).await.map(|_| ())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "no compatible address family available",
            ))
        }
    }
}

async fn receive_task(mut endpoint: broadcast::Receiver<Endpoint>, inner: Arc<Inner>) {
    let endpoint = match endpoint.recv().await.ok() {
        Some(endpoint) => endpoint,
        None => return,
    };

    let mut buffer = vec![0u8; MAX_MSG_SIZE];

    loop {
        let result = inner.socket.recv_from(&mut buffer).await;

        if let Err(e) = handle_msg(&endpoint, &inner, result, &buffer).await {
            log::error!("UDP recv error {:?}", e);
        }
    }
}

async fn handle_msg(
    endpoint: &Endpoint,
    inner: &Arc<Inner>,
    result: io::Result<(usize, SocketAddr)>,
    bytes: &[u8],
) -> Result<()> {
    let (len, remote) = result?;

    let buf = Bytes::copy_from_slice(&bytes[..len]);

    let mut parser = PullParser::new(&buf, 0);

    let mut message_line = None;
    let mut headers = Headers::new();

    for item in &mut parser {
        match item {
            Ok(line) => {
                let line = from_utf8(line)?;

                if message_line.is_none() {
                    let ctx = ParseCtx::new(&buf, endpoint.parser());

                    match MessageLine::parse(ctx)(line) {
                        Ok((_, line)) => {
                            message_line = Some(line);
                        }
                        Err(_) => {
                            return Err(Error {
                                status: Code::BAD_REQUEST,
                                error: Some(anyhow!("Invalid Request/Status Line")),
                            });
                        }
                    }
                } else {
                    parse_line(&buf, line, &mut headers)?;
                }
            }
            Err(_) => {
                return Err(Error {
                    status: Code::BAD_REQUEST,
                    error: Some(anyhow!("Message Incomplete")),
                });
            }
        }
    }

    let head_end = parser.head_end();

    // look for optional content-length header
    let body = match headers.get_named::<ContentLength>() {
        Ok(len) => {
            if len.0 == 0 {
                Bytes::new()
            } else if buf.len() >= head_end + len.0 {
                buf.slice(head_end..head_end + len.0)
            } else {
                return Err(Error {
                    status: Code::BAD_REQUEST,
                    error: Some(anyhow!("Message Body Incomplete")),
                });
            }
        }
        Err(_) => {
            log::trace!("no valid content-length given, guessing body length from udp frame");

            if head_end == buf.len() {
                Bytes::new()
            } else {
                buf.slice(head_end..)
            }
        }
    };

    let line = message_line.status(Code::BAD_REQUEST)?;

    let msg = ReceivedMessage::new(
        remote,
        buf,
        // TODO avoid creating a new handle on each message
        TpHandle::new(Udp {
            inner: inner.clone(),
        }),
        line,
        headers,
        body,
    );

    endpoint.receive(msg);

    Ok(())
}
