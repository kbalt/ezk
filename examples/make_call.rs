use rtc::{
    rtp_session::SendRtpPacket,
    sdp::{Codec, Codecs, SdpSession, SdpSessionConfig},
    OpenSslContext,
};
use sdp_types::{Direction, MediaType};
use sip_auth::{DigestAuthenticator, DigestCredentials, DigestUser};
use sip_core::{transport::udp::Udp, Endpoint};
use sip_ua::{
    dialog::DialogLayer, invite::InviteLayer, Call, CallEvent, MediaEvent, RegistrarConfig,
    Registration, RtcMediaBackend,
};
use std::time::Duration;
use tokio::{select, signal::ctrl_c, time::interval};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut builder = Endpoint::builder();

    // Make a UDP transport
    Udp::spawn(&mut builder, "0.0.0.0:5060").await.unwrap();

    // Add Dialog & INVITE capabilities
    builder.add_layer(DialogLayer::default());
    builder.add_layer(InviteLayer::default());

    let endpoint = builder.build();

    // Create credentials for bob
    let mut credentials = DigestCredentials::new();
    credentials.add_for_realm("example.org", DigestUser::new("bob", "hunter2"));

    // Register bob
    let registration = Registration::register(
        endpoint,
        RegistrarConfig::new("bob".into(), "sip:example.org".parse()?),
        DigestAuthenticator::new(credentials.clone()),
    )
    .await?;

    // Call alice

    // Setup SDP session
    let mut sdp_session = SdpSession::new(
        OpenSslContext::try_new()?,
        "192.168.1.128".parse()?,
        SdpSessionConfig::default(),
    );

    // Define some audio codecs
    let audio = sdp_session
        .add_local_media(
            Codecs::new(MediaType::Audio).with_codec(Codec::G722),
            Direction::SendRecv,
        )
        .unwrap();

    // Add an audio stream using the previously defined codecs
    sdp_session.add_media(audio, Direction::SendRecv, None, None);

    let mut outbound_call = registration
        .make_call(
            "alice".into(),
            DigestAuthenticator::new(credentials.clone()),
            RtcMediaBackend::new(sdp_session),
        )
        .await?;

    // Wait for the call to be responded to, or cancel it
    let unacknowledged_call = select! {
        result = outbound_call.wait_for_completion() => result?,
        _ = ctrl_c() => {
            outbound_call.cancel().await?;
            return Ok(());
        }
    };

    // Complete the call setup
    let call = unacknowledged_call.finish().await?;

    call_event_loop(call).await?;

    Ok(())
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
