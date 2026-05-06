use sip_core::{Endpoint, EndpointBuilder, IncomingRequest, Layer, MayTake, Result};
use sip_types::{
    header::typed::{Contact, Expires},
    Method, StatusCode,
};
use sip_ua::{dialog::DialogLayer, invite::InviteLayer};
use std::time::Duration;
use tokio::time::sleep;

/// Custom layer which we use to accept incoming invites
struct InviteAcceptLayer {}

#[async_trait::async_trait]
impl Layer for InviteAcceptLayer {
    fn name(&self) -> &'static str {
        "registrar-layer"
    }

    fn init(&mut self, endpoint: &mut EndpointBuilder) {
        endpoint.add_allow(Method::REGISTER);
    }

    async fn receive(&self, endpoint: &Endpoint, request: MayTake<'_, IncomingRequest>) {
        let mut register = if request.line.method == Method::REGISTER {
            request.take()
        } else {
            return;
        };

        let tsx = endpoint.create_server_tsx(&mut register);

        let Ok(_contact) = register.headers.get_named::<Contact>() else {
            let response = endpoint.create_response(
                &register,
                StatusCode::BAD_REQUEST,
                Some("Missing Contact Header".into()),
            );
            tsx.respond(response).await.unwrap();
            return;
        };

        let Ok(_expires) = register.headers.get_named::<Expires>() else {
            let response = endpoint.create_response(
                &register,
                StatusCode::BAD_REQUEST,
                Some("Missing Expires Header".into()),
            );
            tsx.respond(response).await.unwrap();
            return;
        };

        // do something with contact & expires header

        let mut response = endpoint.create_response(&register, StatusCode::OK, None);
        response.msg.headers.insert_named(&Expires(30));
        tsx.respond(response).await.unwrap();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let mut builder = Endpoint::builder();

    builder.add_layer(DialogLayer::default());
    builder.add_layer(InviteLayer::default());

    builder.add_layer(InviteAcceptLayer {});

    builder.bind_udp("127.0.0.1:5060".parse().unwrap()).await?;
    builder
        .listen_tcp("127.0.0.1:5060".parse().unwrap())
        .await?;

    // Build endpoint to start the SIP Stack
    let _endpoint = builder.build();

    // Busy sleep loop
    loop {
        sleep(Duration::from_secs(1)).await;
    }
}
