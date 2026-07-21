use ezk_sip_ua::{
    MakeCallError, MediaBackend, OutboundCall, dialog::DialogLayer, invite::InviteLayer,
};
use sdp_types::SessionDescription;
use sip_auth::{DigestAuthenticator, DigestCredentials, DigestError, DigestUser};
use sip_core::Endpoint;
use std::{convert::Infallible, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

const REALM: &str = "proxy.example.org";
const NONCE: &str = "fixed-proxy-nonce";
const CHALLENGE: &str = "Proxy-Authenticate: Digest realm=\"proxy.example.org\", nonce=\"fixed-proxy-nonce\", algorithm=MD5, opaque=\"proxy-token\"\r\n";

struct NoMedia;

impl MediaBackend for NoMedia {
    type Error = Infallible;
    type Event = Infallible;

    fn has_media(&self) -> bool {
        false
    }

    async fn create_sdp_offer(&mut self) -> Result<SessionDescription, Self::Error> {
        panic!("initial authentication must not create SDP without media")
    }

    async fn receive_sdp_answer(&mut self, _: SessionDescription) -> Result<(), Self::Error> {
        panic!("initial authentication must not process SDP")
    }

    async fn receive_sdp_offer(
        &mut self,
        _: SessionDescription,
    ) -> Result<SessionDescription, Self::Error> {
        panic!("initial authentication must not process SDP")
    }

    async fn run(&mut self) -> Result<Self::Event, Self::Error> {
        std::future::pending().await
    }
}

fn optional_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

fn header<'a>(request: &'a str, name: &str) -> &'a str {
    optional_header(request, name).unwrap_or_else(|| panic!("missing {name} header in {request}"))
}

fn uri(request: &str) -> &str {
    request.split_whitespace().nth(1).unwrap()
}

fn branch(request: &str) -> &str {
    header(request, "Via")
        .split(';')
        .find_map(|parameter| parameter.strip_prefix("branch="))
        .expect("Via must contain branch")
}

fn cseq(request: &str, method: &str) -> u32 {
    let (number, actual_method) = header(request, "CSeq").split_once(' ').unwrap();
    assert_eq!(actual_method, method);
    number.parse().unwrap()
}

async fn receive(socket: &UdpSocket) -> (String, SocketAddr) {
    let mut buffer = [0; 8192];
    let (length, source) = socket.recv_from(&mut buffer).await.unwrap();
    (
        String::from_utf8(buffer[..length].to_vec()).unwrap(),
        source,
    )
}

async fn respond(socket: &UdpSocket, destination: SocketAddr, request: &str, ringing: bool) {
    let status = if ringing {
        "180 Ringing"
    } else {
        "407 Proxy Authentication Required"
    };
    let mut response = format!("SIP/2.0 {status}\r\n");
    for name in ["Via", "From", "Call-ID", "CSeq"] {
        response.push_str(&format!("{name}: {}\r\n", header(request, name)));
    }
    response.push_str(&format!("To: {};tag=proxy-peer\r\n", header(request, "To")));
    if ringing {
        response.push_str(&format!(
            "Contact: <sip:bob@{}>\r\n",
            socket.local_addr().unwrap()
        ));
    } else {
        response.push_str(CHALLENGE);
    }
    response.push_str("Content-Length: 0\r\n\r\n");
    socket
        .send_to(response.as_bytes(), destination)
        .await
        .unwrap();
}

fn assert_ack(ack: &str, invite: &str) {
    assert!(ack.starts_with("ACK "), "{ack}");
    assert_eq!(uri(ack), uri(invite));
    assert_eq!(branch(ack), branch(invite));
    assert_eq!(cseq(ack, "ACK"), cseq(invite, "INVITE"));
    for name in ["Call-ID", "From"] {
        assert_eq!(header(ack, name), header(invite, name));
    }
    assert_eq!(
        header(ack, "To"),
        format!("{};tag=proxy-peer", header(invite, "To"))
    );
}

fn assert_retry(retry: &str, original: &str) {
    assert!(retry.starts_with("INVITE "), "{retry}");
    assert_eq!(uri(retry), uri(original));
    for name in ["Call-ID", "From", "To", "Contact"] {
        assert_eq!(header(retry, name), header(original, name));
    }
    assert_eq!(cseq(retry, "INVITE"), cseq(original, "INVITE") + 1);
    assert_ne!(branch(retry), branch(original));
    assert_eq!(header(retry, "Content-Length"), "0");
    assert!(optional_header(retry, "Authorization").is_none());

    let authorization = header(retry, "Proxy-Authorization");
    let fields: Vec<_> = authorization
        .strip_prefix("Digest ")
        .expect("must use Digest authentication")
        .split(',')
        .map(|field| {
            let (name, value) = field.trim().split_once('=').unwrap();
            (name, value.trim_matches('"'))
        })
        .collect();
    let field = |name| {
        fields
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    };
    assert_eq!(field("username"), Some("alice"));
    assert_eq!(field("realm"), Some(REALM));
    assert_eq!(field("nonce"), Some(NONCE));
    assert_eq!(field("uri"), Some(uri(original)));
    assert_eq!(field("algorithm"), Some("MD5"));
    assert_eq!(field("opaque"), Some("proxy-token"));
    for name in ["qop", "nc", "cnonce"] {
        assert_eq!(field(name), None);
    }
    // RFC 2617 no-qop calculation, independent of DigestAuthenticator helpers.
    let ha1 = format!("{:x}", md5::compute(format!("alice:{REALM}:secret")));
    let ha2 = format!("{:x}", md5::compute(format!("INVITE:{}", uri(original))));
    let expected = format!("{:x}", md5::compute(format!("{ha1}:{NONCE}:{ha2}")));
    assert_eq!(field("response"), Some(expected.as_str()));
}

async fn peer(socket: &UdpSocket, reject_retry: bool) {
    let (original, client) = receive(socket).await;
    assert!(original.starts_with("INVITE "), "{original}");
    assert!(optional_header(&original, "Proxy-Authorization").is_none());
    assert!(optional_header(&original, "Authorization").is_none());
    assert_eq!(header(&original, "Content-Length"), "0");
    respond(socket, client, &original, false).await;

    let mut original_acked = false;
    let retry = loop {
        let (request, source) = receive(socket).await;
        assert_eq!(source, client);
        if request.starts_with("ACK ") {
            assert_ack(&request, &original);
            original_acked = true;
        } else if branch(&request) == branch(&original) {
            assert_eq!(
                request, original,
                "only identical INVITE retransmissions allowed"
            );
            respond(socket, client, &original, false).await;
        } else {
            assert!(
                original_acked,
                "failure ACK must precede authenticated retry"
            );
            assert_retry(&request, &original);
            break request;
        }
    };
    respond(socket, client, &retry, !reject_retry).await;

    if reject_retry {
        loop {
            let (request, source) = receive(socket).await;
            assert_eq!(source, client);
            if request.starts_with("ACK ") && branch(&request) == branch(&retry) {
                assert_ack(&request, &retry);
                break;
            }
            handle_retransmission(socket, client, &request, &original, &retry, reject_retry).await;
        }
    }

    // Absolute deadline, longer than UDP T1 (500 ms); duplicate packets cannot
    // reset it. A fresh INVITE, CANCEL, or any unexpected send fails the test.
    let quiet = timeout(Duration::from_millis(750), async {
        loop {
            let (request, source) = receive(socket).await;
            assert_eq!(source, client);
            handle_retransmission(socket, client, &request, &original, &retry, reject_retry).await;
        }
    })
    .await;
    assert!(quiet.is_err());
}

async fn handle_retransmission(
    socket: &UdpSocket,
    client: SocketAddr,
    request: &str,
    original: &str,
    retry: &str,
    reject_retry: bool,
) {
    if request.starts_with("ACK ") {
        if branch(request) == branch(original) {
            assert_ack(request, original);
        } else {
            assert!(reject_retry, "ringing must not generate an ACK");
            assert_ack(request, retry);
        }
    } else if request == original {
        respond(socket, client, original, false).await;
    } else if request == retry {
        respond(socket, client, retry, !reject_retry).await;
    } else {
        panic!("unexpected send (including a third INVITE): {request}");
    }
}

async fn scenario(reject_retry: bool) {
    timeout(Duration::from_secs(10), async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = format!("sip:bob@{}", socket.local_addr().unwrap())
            .parse()
            .unwrap();
        let mut builder = Endpoint::builder();
        let transport = builder
            .bind_udp("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        builder.add_layer(DialogLayer::default());
        builder.add_layer(InviteLayer::default());
        let endpoint = builder.build();
        let contact = sip_types::header::typed::Contact::new(
            format!("<sip:alice@{}>", transport.bound())
                .parse()
                .unwrap(),
        );
        let mut credentials = DigestCredentials::new();
        credentials.add_for_realm(REALM, DigestUser::new("alice", "secret"));

        let (_, result) = tokio::join!(
            peer(&socket, reject_retry),
            OutboundCall::make(
                endpoint,
                DigestAuthenticator::new(credentials),
                "<sip:alice@example.org>".parse().unwrap(),
                contact,
                target,
                NoMedia,
            ),
        );
        if reject_retry {
            match result {
                Err(MakeCallError::Auth(DigestError::FailedToAuthenticate(realms))) => {
                    assert_eq!(realms.as_slice(), [REALM]);
                }
                Err(error) => panic!("expected authentication failure, got {error:?}"),
                Ok(_) => panic!("repeated challenge must fail authentication"),
            }
        } else {
            // make() succeeds on the tagged 180. No call completion or CANCEL
            // is needed to exercise initial authentication.
            drop(result.expect("authenticated retry must reach the early dialog"));
        }
    })
    .await
    .expect("loopback outbound authentication must finish within 10 seconds");
}

#[tokio::test]
async fn proxy_digest_challenge_retries_invite_and_reaches_ringing() {
    scenario(false).await;
}

#[tokio::test]
async fn repeated_proxy_digest_challenge_is_acked_and_fails_authentication() {
    scenario(true).await;
}
