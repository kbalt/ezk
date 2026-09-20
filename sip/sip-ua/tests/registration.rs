use ezk_sip_ua::{RegistrarConfig, Registration};
use sip_auth::DigestAuthenticator;
use sip_core::Endpoint;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const EXPIRY: u32 = 3600;

fn header<'a>(request: &'a str, name: &str) -> &'a str {
    request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .unwrap_or_else(|| panic!("missing {name} header in {request}"))
        .1
        .trim()
}

async fn receive_register(socket: &mut BufStream<TcpStream>) -> String {
    let mut request = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(socket.read_line(&mut line).await.unwrap(), 0, "early EOF");
        // TCP keep-alives can appear between SIP messages.
        if request.is_empty() && line == "\r\n" {
            continue;
        }
        request.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    assert!(request.starts_with("REGISTER "), "{request}");
    assert_eq!(header(&request, "Content-Length"), "0");
    request
}

async fn respond_ok(socket: &mut BufStream<TcpStream>, request: &str, expires: u32) {
    let mut response = String::from("SIP/2.0 200 OK\r\n");
    for name in ["Via", "From", "Call-ID", "CSeq", "Contact"] {
        response.push_str(&format!("{name}: {}\r\n", header(request, name)));
    }
    response.push_str(&format!(
        "To: {};tag=registrar\r\nExpires: {expires}\r\nContent-Length: 0\r\n\r\n",
        header(request, "To"),
    ));
    socket.write_all(response.as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
}

async fn accept_and_register(listener: &TcpListener) -> (BufStream<TcpStream>, String) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut socket = BufStream::new(socket);
    let request = receive_register(&mut socket).await;
    respond_ok(&mut socket, &request, EXPIRY).await;
    (socket, request)
}

#[tokio::test]
async fn tcp_closure_fails_registration_and_retry_reconnects() {
    timeout(Duration::from_secs(60), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let registrar = format!("sip:{};transport=tcp", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let config = RegistrarConfig::new("alice".into(), registrar)
            .with_custom_expiry(Duration::from_secs(EXPIRY.into()));
        let mut endpoint = Endpoint::builder();
        endpoint.add_allow(sip_types::Method::REGISTER);
        let endpoint = endpoint.build();

        let ((socket, request), registration) = tokio::join!(
            accept_and_register(&listener),
            Registration::register(
                endpoint,
                config,
                DigestAuthenticator::new(Default::default()),
            ),
        );
        assert!(header(&request, "Expires").parse::<u32>().unwrap() > 0);
        let mut registration = registration.unwrap();
        assert!(registration.is_registered());

        // Close only after the initial registration succeeds. The registrar's
        // one-hour expiry puts refresh far beyond the failure deadline below.
        drop(socket);
        timeout(
            Duration::from_secs(15),
            registration.wait_for_registration_failure(),
        )
        .await
        .expect("TCP closure must fail registration without waiting for refresh");
        assert!(!registration.is_registered());

        let ((mut socket, request), result) = tokio::join!(
            accept_and_register(&listener),
            registration.retry_register(DigestAuthenticator::new(Default::default())),
        );
        assert_eq!(header(&request, "Expires"), EXPIRY.to_string());
        result.unwrap();
        assert!(registration.is_registered());

        // Drop must still unregister the binding over the healthy second socket.
        drop(registration);
        let unregister = receive_register(&mut socket).await;
        assert_eq!(header(&unregister, "Expires"), "0");
        assert_eq!(header(&unregister, "Call-ID"), header(&request, "Call-ID"));
        assert_eq!(header(&unregister, "Contact"), header(&request, "Contact"));
        respond_ok(&mut socket, &unregister, 0).await;
    })
    .await
    .expect("TCP registration lifecycle must complete within 60 seconds");
}
