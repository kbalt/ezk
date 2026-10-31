//! Regression coverage for answering incoming BYEs.

use ezk_sip_ua::{
    dialog::{Dialog, DialogLayer},
    invite::{
        InviteLayer, create_ack,
        initiator::{InviteInitiator, Response},
        session::{InviteSession, InviteSessionEvent},
    },
};
use sip_core::{Endpoint, IncomingRequest, Layer, MayTake, transaction::TsxResponse};
use sip_types::{
    Method, StatusCode,
    header::typed::Contact,
    uri::{NameAddr, SipUri},
};
use std::time::Duration;
use tokio::{sync::mpsc, time::timeout};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "current_thread")]
async fn answers_remote_bye_before_application_polls_events() -> TestResult {
    timeout(Duration::from_secs(10), async {
        let (mut session, peer) = establish_call().await?;

        // The peer must get its 200 OK before run() is ever polled.
        let response = peer.send_bye().await?;
        assert_eq!(response.line.code, StatusCode::OK);

        assert!(matches!(session.run().await?, InviteSessionEvent::Bye(_)));
        assert!(matches!(
            session.run().await?,
            InviteSessionEvent::Terminated
        ));
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn answers_crossed_bye_before_local_bye_completes() -> TestResult {
    timeout(Duration::from_secs(10), async {
        let (mut session, mut peer) = establish_call().await?;

        let peer_side = async {
            let mut local_bye = peer.recv(Method::BYE).await;

            let response = peer.send_bye().await?;
            assert_eq!(
                response.line.code,
                StatusCode::OK,
                "crossed BYE must receive 200 OK"
            );

            // Withhold the response to our BYE until the crossed BYE has been
            // answered. Holding the session-state lock in terminate() would
            // deadlock this exchange; ignoring the crossed BYE would return 404.
            let response = peer
                .dialog
                .create_response(&local_bye, StatusCode::OK, None)?;
            peer.endpoint
                .create_server_tsx(&mut local_bye)
                .respond(response)
                .await?;
            Ok::<_, sip_core::Error>(())
        };

        // Poll both sides together so a failure on one side cancels the other.
        let (response, ()) = tokio::try_join!(session.terminate(), peer_side)?;
        assert_eq!(response.line.code, StatusCode::OK);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn answers_crossed_bye_after_session_drop() -> TestResult {
    // `Call::terminate` consumes the call, so every `Call` user drops the
    // session right after sending the BYE.
    assert_eq!(crossed_bye_after_terminate(false).await?, StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn answers_crossed_bye_after_usage_drop() -> TestResult {
    // Keeping a reference to the dialog while dropping the INVITE usage used
    // to answer the crossed BYE with 404.
    assert_eq!(crossed_bye_after_terminate(true).await?, StatusCode::OK);
    Ok(())
}

/// Terminates the call, drops the session, then lets the peer send a crossed
/// BYE while our BYE client transaction is still in its UDP Completed state.
async fn crossed_bye_after_terminate(keep_dialog: bool) -> TestResult<StatusCode> {
    timeout(Duration::from_secs(10), async {
        let (mut session, mut peer) = establish_call().await?;

        let peer_side = async {
            let mut bye = peer.recv(Method::BYE).await;
            let response = peer.dialog.create_response(&bye, StatusCode::OK, None)?;
            peer.endpoint
                .create_server_tsx(&mut bye)
                .respond(response)
                .await
        };
        let (response, ()) = tokio::try_join!(session.terminate(), peer_side)?;
        assert_eq!(response.line.code, StatusCode::OK);

        let _dialog = keep_dialog.then(|| session.dialog.clone());
        drop(session);

        Ok(peer.send_bye().await?.line.code)
    })
    .await?
}

/// Hands every incoming request to the scripted peer instead of dialog dispatch.
struct CaptureRequests(mpsc::UnboundedSender<IncomingRequest>);

#[async_trait::async_trait]
impl Layer for CaptureRequests {
    fn name(&self) -> &'static str {
        "capture-requests"
    }

    async fn receive(&self, _: &Endpoint, request: MayTake<'_, IncomingRequest>) {
        let _ = self.0.send(request.take());
    }
}

/// Scripted UAS side of an established dialog.
struct Peer {
    endpoint: Endpoint,
    dialog: Dialog,
    requests: mpsc::UnboundedReceiver<IncomingRequest>,
}

impl Peer {
    async fn recv(&mut self, method: Method) -> IncomingRequest {
        let request = self.requests.recv().await.expect("peer endpoint dropped");
        assert_eq!(request.line.method, method);
        request
    }

    async fn send_bye(&self) -> Result<TsxResponse, sip_core::Error> {
        let bye = self.dialog.create_request(Method::BYE, None);
        let mut target = self.dialog.target_tp_info.lock().await;
        let mut transaction = self.endpoint.send_request(bye, &mut target).await?;
        drop(target);
        transaction.receive_final().await
    }
}

async fn endpoint(user: &str, capture: Option<CaptureRequests>) -> TestResult<(Endpoint, SipUri)> {
    let mut builder = Endpoint::builder();
    if let Some(capture) = capture {
        builder.add_layer(capture);
    }
    builder.add_layer(DialogLayer::default());
    builder.add_layer(InviteLayer::default());
    let addr = builder.bind_udp("127.0.0.1:0".parse()?).await?.bound();
    Ok((builder.build(), format!("sip:{user}@{addr}").parse()?))
}

/// Establishes a dialog from a local `InviteInitiator` to a scripted peer.
async fn establish_call() -> TestResult<(InviteSession, Peer)> {
    let (sender, mut requests) = mpsc::unbounded_channel();
    let (peer, peer_uri) = endpoint("bob", Some(CaptureRequests(sender))).await?;
    let (local, local_uri) = endpoint("alice", None).await?;

    let peer_side = async {
        let mut invite = requests.recv().await.expect("expected INVITE");
        let contact = Contact::new(NameAddr::uri(peer_uri.clone()));
        let dialog = Dialog::new_server(peer.clone(), &invite, contact)?;
        let response = dialog.create_response(&invite, StatusCode::OK, None)?;
        let _ = peer
            .create_server_inv_tsx(&mut invite)
            .respond_success(response)
            .await?;
        let ack = requests.recv().await.expect("expected ACK");
        assert_eq!(ack.line.method, Method::ACK);
        Ok::<_, sip_core::Error>(dialog)
    };

    let local_side = async {
        let contact = Contact::new(NameAddr::uri(local_uri.clone()));
        let mut initiator = InviteInitiator::new(
            local.clone(),
            NameAddr::uri(local_uri),
            contact,
            peer_uri.clone(),
        );
        let invite = initiator.create_invite();
        initiator.send_invite(invite).await?;
        let (session, response) = loop {
            match initiator.receive().await? {
                Response::Session(session, response) => break (session, response),
                Response::Provisional(_) => continue,
                other => panic!("unexpected INVITE response: {other:?}"),
            }
        };
        let mut ack = create_ack(&session.dialog, response.base_headers.cseq.cseq).await?;
        local.send_outgoing_request(&mut ack).await?;
        Ok::<_, sip_core::Error>(session)
    };

    let (session, dialog) = tokio::try_join!(local_side, peer_side)?;
    Ok((
        session,
        Peer {
            endpoint: peer,
            dialog,
            requests,
        },
    ))
}
