use ezk_rtc::sdp::{BundlePolicy, SdpSessionConfig};
use sdp_types::Direction;

use crate::common::{make_session, satisfy_transport_changes};

mod common;

#[test]
fn exchange_multiple_media_bundled() {
    let (audio, mut offer_session) = make_session(SdpSessionConfig {
        offer_ice: false,
        bundle_policy: BundlePolicy::MaxBundle,
        ..Default::default()
    });

    let (_, mut answer_session) = make_session(SdpSessionConfig {
        offer_ice: false,
        ..Default::default()
    });

    offer_session.add_media(audio, Direction::SendRecv);
    offer_session.add_media(audio, Direction::SendRecv);

    assert_eq!(offer_session.pending_media_iter().count(), 2);
    assert_eq!(answer_session.pending_media_iter().count(), 0);

    satisfy_transport_changes(&mut offer_session, 1000);

    let offer = offer_session.create_sdp_offer();
    let answer = answer_session.receive_sdp_offer(offer).unwrap();
    satisfy_transport_changes(&mut answer_session, 1000);
    let answer = answer_session.create_sdp_answer(answer);

    offer_session.receive_sdp_answer(answer).unwrap();

    satisfy_transport_changes(&mut offer_session, 1000);

    assert_eq!(offer_session.media_iter().count(), 2);
    assert_eq!(answer_session.media_iter().count(), 2);
}
