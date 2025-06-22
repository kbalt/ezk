use bytesstr::BytesStr;
use common::{make_session, satisfy_transport_changes};
use ezk_rtc::sdp::{BundlePolicy, RtcpMuxPolicy, SdpSessionConfig};
use sdp_types::{Direction, SessionDescription};

mod common;

#[test]
fn offer_ice_credentials_not_in_offer_when_ice_is_disabled() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_ice: false,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 1000);

    {
        let offer = session.create_sdp_offer();

        // Make sure credentials are in the session level and not in media level
        assert!(offer.ice_pwd.is_none());
        assert!(offer.ice_ufrag.is_none());
        assert!(offer.media_descriptions[0].ice_ufrag.is_none());
        assert!(offer.media_descriptions[0].ice_pwd.is_none());
    }

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 2000);

    {
        let offer = session.create_sdp_offer();

        assert!(offer.ice_pwd.is_none());
        assert!(offer.ice_ufrag.is_none());
        assert!(offer.media_descriptions[0].ice_ufrag.is_none());
        assert!(offer.media_descriptions[0].ice_pwd.is_none());
        assert!(offer.media_descriptions[1].ice_ufrag.is_none());
        assert!(offer.media_descriptions[1].ice_pwd.is_none());
    }
}

#[test]
fn offer_ice_credentials_in_offer_when_ice_is_enabled() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_ice: true,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 1000);

    {
        let offer = session.create_sdp_offer();

        // Make sure credentials are in the session level and not in media level
        assert!(offer.ice_pwd.is_some());
        assert!(offer.ice_ufrag.is_some());
        assert!(offer.media_descriptions[0].ice_ufrag.is_none());
        assert!(offer.media_descriptions[0].ice_pwd.is_none());
    }

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 2000);

    {
        let offer = session.create_sdp_offer();

        assert!(offer.ice_pwd.is_some());
        assert!(offer.ice_ufrag.is_some());
        assert!(offer.media_descriptions[0].ice_ufrag.is_none());
        assert!(offer.media_descriptions[0].ice_pwd.is_none());
        assert!(offer.media_descriptions[1].ice_ufrag.is_none());
        assert!(offer.media_descriptions[1].ice_pwd.is_none());
    }
}

#[test]
fn offer_ice_candidates_when_bundle_policy_max_compat() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_ice: true,
        bundle_policy: BundlePolicy::MaxCompat,
        rtcp_mux_policy: RtcpMuxPolicy::Require,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 1000);

    {
        let offer = session.create_sdp_offer();

        // Make sure credentials are set globally
        assert!(offer.ice_pwd.is_some());
        assert!(offer.ice_ufrag.is_some());

        assert_eq!(offer.media_descriptions[0].ice_candidates.len(), 1);
        assert_eq!(offer.media_descriptions[0].ice_candidates[0].port, 1000);
    }

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 2000);

    {
        let offer = session.create_sdp_offer();

        assert_eq!(offer.media_descriptions[0].ice_candidates.len(), 1);
        assert_eq!(offer.media_descriptions[0].ice_candidates[0].port, 1000);

        assert_eq!(offer.media_descriptions[1].ice_candidates.len(), 1);
        assert_eq!(offer.media_descriptions[1].ice_candidates[0].port, 2000);
    }
}

#[test]
fn offer_ice_candidates_when_bundle_policy_max_bundle() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_ice: true,
        bundle_policy: BundlePolicy::MaxBundle,
        rtcp_mux_policy: RtcpMuxPolicy::Require,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 1000);

    {
        let offer = session.create_sdp_offer();

        // Make sure credentials are set globally
        assert!(offer.ice_pwd.is_some());
        assert!(offer.ice_ufrag.is_some());

        assert_eq!(offer.media_descriptions[0].ice_candidates.len(), 1);
        assert_eq!(offer.media_descriptions[0].ice_candidates[0].port, 1000);
    }

    session.add_media(audio, Direction::SendRecv);

    {
        let offer = session.create_sdp_offer();

        assert_eq!(offer.media_descriptions[0].ice_candidates.len(), 1);
        assert_eq!(offer.media_descriptions[0].ice_candidates[0].port, 1000);

        assert_eq!(offer.media_descriptions[1].ice_candidates.len(), 1);
        assert_eq!(offer.media_descriptions[1].ice_candidates[0].port, 1000);
    }
}

#[test]
fn offer_ice_candidates_when_rtcp_mux_policy_negotiate() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_ice: true,
        bundle_policy: BundlePolicy::MaxBundle,
        rtcp_mux_policy: RtcpMuxPolicy::Negotiate,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 1000);

    {
        let offer = session.create_sdp_offer();

        // 2 Candidates must exist
        assert_eq!(offer.media_descriptions[0].ice_candidates.len(), 2);

        // RTP candidiate
        assert_eq!(offer.media_descriptions[0].ice_candidates[0].port, 1000);
        assert_eq!(offer.media_descriptions[0].ice_candidates[0].component, 1);

        // RTCP candidate
        assert_eq!(offer.media_descriptions[0].ice_candidates[1].port, 1001);
        assert_eq!(offer.media_descriptions[0].ice_candidates[1].component, 2);
    }
}

#[test]
fn offer_ice_candidates_when_rtcp_mux_policy_require() {
    let (audio, mut session) = make_session(SdpSessionConfig {
        offer_ice: true,
        bundle_policy: BundlePolicy::MaxBundle,
        rtcp_mux_policy: RtcpMuxPolicy::Require,
        ..Default::default()
    });

    session.add_media(audio, Direction::SendRecv);

    satisfy_transport_changes(&mut session, 1000);

    {
        let offer = session.create_sdp_offer();

        // Only a single RTP candidate must exist
        assert_eq!(offer.media_descriptions[0].ice_candidates.len(), 1);
        assert_eq!(offer.media_descriptions[0].ice_candidates[0].port, 1000);
        assert_eq!(offer.media_descriptions[0].ice_candidates[0].component, 1);
    }
}

#[test]
fn answer_ice_credentials_when_ice_is_disabled() {
    let (_audio, mut session) = make_session(SdpSessionConfig {
        offer_ice: false,
        ..Default::default()
    });

    let offer = "\
v=0
o=- 524 21259 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
a=ice-ufrag:f5F7oDQ0
a=ice-pwd:vLiEsihNsKc6V5lqHDx2FhsX6n9aF2qg
m=audio 1000 RTP/AVP 9
a=rtpmap:9 G722/8000/1
a=rtcp-mux
a=candidate:13578383605728834170 1 UDP 2126511615 127.0.0.1 1000 typ host
";

    let offer = SessionDescription::parse(&BytesStr::from_static(offer)).unwrap();

    let answer = session.receive_sdp_offer(offer).unwrap();

    satisfy_transport_changes(&mut session, 1000);

    let answer = session.create_sdp_answer(answer);

    assert!(answer.ice_ufrag.is_some());
    assert!(answer.ice_pwd.is_some());
    assert_eq!(answer.media_descriptions[0].ice_candidates.len(), 1);
}
