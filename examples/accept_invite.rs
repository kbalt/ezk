use rtc::{
    rtp_session::SendRtpPacket,
    sdp::{Codec, Codecs, SdpSession, SdpSessionConfig},
    OpenSslContext,
};
use sdp_types::{Direction, MediaType};
use sip_core::{transport::udp::Udp, Endpoint, IncomingRequest, Layer, MayTake, Result};
use sip_types::{
    header::typed::Contact,
    uri::{NameAddr, SipUri},
    Method, StatusCode,
};
use sip_ua::{
    dialog::DialogLayer, invite::InviteLayer, Call, CallEvent, InboundCall, MediaEvent,
    RtcMediaBackend,
};
use std::time::Duration;
use tokio::{
    select,
    time::{interval, sleep},
};

/// Custom layer which we use to accept incoming invites
struct InviteAcceptLayer {}

#[async_trait::async_trait]
impl Layer for InviteAcceptLayer {
    fn name(&self) -> &'static str {
        "invite-accept-layer"
    }

    async fn receive(&self, endpoint: &Endpoint, request: MayTake<'_, IncomingRequest>) {
        let invite = if request.line.method == Method::INVITE {
            request.take()
        } else {
            return;
        };

        let contact: SipUri = "sip:bob@example.com".parse().unwrap();
        let contact = Contact::new(NameAddr::uri(contact));

        // Setup SDP session
        let mut sdp_session = SdpSession::new(
            OpenSslContext::try_new().unwrap(),
            "192.168.1.128".parse().unwrap(),
            SdpSessionConfig::default(),
        );

        // Define some audio codecs we're able to send & receive
        sdp_session
            .add_local_media(
                Codecs::new(MediaType::Audio).with_codec(Codec::G722),
                Direction::SendRecv,
            )
            .unwrap();

        // Create inbound call
        let mut inbound_call = InboundCall::from_invite(endpoint.clone(), invite, contact)
            .unwrap()
            .with_media(RtcMediaBackend::new(sdp_session));

        // Send a 100 TRYING response to prevent it from retransmitting requests
        inbound_call
            .respond_provisional(StatusCode::TRYING)
            .await
            .unwrap();

        // Wait 3 seconds before finally accepting the call... maybe they hang up?
        select! {
            _ = inbound_call.cancelled() => {
                // they cancelled the call, bail out
                return;
            }
            _ = sleep(Duration::from_secs(3)) => {}
        }

        // accept the call
        let call = inbound_call.accept().await.unwrap();

        call_event_loop(call).await.unwrap();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let mut builder = Endpoint::builder();

    builder.add_layer(DialogLayer::default());
    builder.add_layer(InviteLayer::default());

    builder.add_layer(InviteAcceptLayer {});

    Udp::spawn(&mut builder, "127.0.0.1:5060").await?;

    // Build endpoint to start the SIP Stack
    let _endpoint = builder.build();

    // Busy sleep loop
    loop {
        sleep(Duration::from_secs(1)).await;
    }
}

async fn call_event_loop(
    mut call: Call<RtcMediaBackend>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Enter the call event loop
    loop {
        match call.run().await? {
            CallEvent::Internal(event) => call.handle_internal_event(event).await?,
            CallEvent::Media(MediaEvent::ReceiverAdded {
                mut receiver,
                codec,
            }) => {
                assert_eq!(codec.name, "G722");

                tokio::spawn(async move {
                    while let Some(_rtp_packet) = receiver.recv().await {
                        // decode & play audio
                    }
                });
            }
            CallEvent::Media(MediaEvent::SenderAdded { mut sender, codec }) => {
                let max_mtu = call
                    .media()
                    .sdp_session()
                    .max_payload_size_for_media(sender.media_id())
                    .unwrap();

                tokio::spawn(async move {
                    // send some audio
                    let mut interval = interval(Duration::from_millis(20));

                    loop {
                        let instant = interval.tick().await;

                        // Actually produce and encode some audio
                        let encoded_audio_data = vec![0u8; max_mtu];

                        sender
                            .send(SendRtpPacket::new(
                                instant.into(),
                                codec.pt,
                                encoded_audio_data.into(),
                            ))
                            .await
                            .unwrap();
                    }
                });
            }
            CallEvent::Terminated => return Ok(()),
        }
    }
}
