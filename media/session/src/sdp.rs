use crate::codecs::NegotiatedCodec;
use crate::events::{MediaAdded, MediaChanged, TransportChange, TransportRequiredChanges};
use crate::transport::{Transport, TransportBuilder};
use crate::{
    ActiveMedia, DirectionBools, Error, Event, MediaId, PendingChange, SdpSession, TransportEntry,
    TransportId,
};
use bytesstr::BytesStr;
use rtp::{RtpSession, Ssrc};
use sdp_types::{
    Connection, Direction, Fmtp, Group, IceOptions, IcePassword, IceUsernameFragment, Media,
    MediaDescription, MediaType, Origin, Rtcp, RtpMap, SessionDescription, Time, TransportProtocol,
};
use std::{
    collections::HashMap,
    mem::replace,
    time::{Duration, Instant},
};

/// Some additional information to create a SDP answer. Must be passed into [`SdpSession::create_sdp_answer`].
///
/// All pending transport changes must be handled before creating the answer.
pub struct SdpAnswerState(Vec<SdpResponseEntry>);

enum SdpResponseEntry {
    Active(MediaId),
    Rejected {
        media_type: MediaType,
        mid: Option<BytesStr>,
    },
}

impl SdpSession {
    /// Receive a SDP offer in this session.
    ///
    /// Returns an opaque response state object which can be used to create the actual response SDP.
    /// Before the SDP response can be created, the user must make all necessary changes to the transports using [`transport_changes`](Self::transport_changes)
    ///
    /// The actual answer can be created using [`create_sdp_answer`](Self::create_sdp_answer).
    pub fn receive_sdp_offer(
        &mut self,
        offer: SessionDescription,
    ) -> Result<SdpAnswerState, Error> {
        let mut new_state = vec![];
        let mut response = vec![];

        for (mline, remote_media_desc) in offer.media_descriptions.iter().enumerate() {
            let requested_direction: DirectionBools = remote_media_desc.direction.flipped().into();

            // First thing: Search the current state for an entry that matches this description - and update accordingly
            let matched_position = self
                .state
                .iter()
                .position(|media| media.matches(&self.transports, remote_media_desc));

            if let Some(position) = matched_position {
                self.update_active_media(requested_direction, self.state[position].id);
                let media = self.state.remove(position);
                response.push(SdpResponseEntry::Active(media.id));
                new_state.push(media);
                continue;
            }

            // Choose local media for this media description
            let chosen_media = self.local_media.iter_mut().find_map(|(id, local_media)| {
                local_media
                    .maybe_use_for_offer(remote_media_desc)
                    .map(|config| (id, config))
            });

            let Some((local_media_id, (codec, codec_pt, negotiated_direction))) = chosen_media
            else {
                // no local media found for this
                response.push(SdpResponseEntry::Rejected {
                    media_type: remote_media_desc.media.media_type,
                    mid: remote_media_desc.mid.clone(),
                });

                log::debug!("Rejecting mline={mline}, no compatible local media found");
                continue;
            };

            let media_id = self.next_media_id.step();

            // Get or create transport for the m-line
            let transport = self.get_or_create_transport(&new_state, &offer, remote_media_desc)?;

            let Some(transport) = transport else {
                // No transport was found or created, reject media
                response.push(SdpResponseEntry::Rejected {
                    media_type: remote_media_desc.media.media_type,
                    mid: remote_media_desc.mid.clone(),
                });

                log::debug!("Rejecting mline={mline}, no compatible transport found");
                continue;
            };

            let recv_fmtp = remote_media_desc
                .fmtp
                .iter()
                .find(|f| f.format == codec_pt)
                .map(|f| f.params.to_string());

            self.events.push_back(Event::MediaAdded(MediaAdded {
                id: media_id,
                transport_id: transport,
                local_media_id,
                direction: negotiated_direction.into(),
                codec: NegotiatedCodec {
                    send_pt: codec_pt,
                    recv_pt: codec_pt,
                    name: codec.name.clone(),
                    clock_rate: codec.clock_rate,
                    channels: codec.channels,
                    send_fmtp: codec.fmtp.clone(),
                    recv_fmtp,
                },
            }));

            response.push(SdpResponseEntry::Active(media_id));
            new_state.push(ActiveMedia {
                id: media_id,
                local_media_id,
                media_type: remote_media_desc.media.media_type,
                rtp_session: RtpSession::new(Ssrc(rand::random()), codec.clock_rate),
                avpf: is_avpf(&remote_media_desc.media.proto),
                next_rtcp: Instant::now() + Duration::from_secs(5),
                rtcp_interval: rtcp_interval(remote_media_desc.media.media_type),
                mid: remote_media_desc.mid.clone(),
                direction: negotiated_direction,
                transport,
                codec_pt,
                codec,
            });
        }

        // Store new state and destroy all media sessions
        let removed_media = replace(&mut self.state, new_state);

        for media in removed_media {
            self.local_media[media.local_media_id].use_count -= 1;
            self.events.push_back(Event::MediaRemoved(media.id));
        }

        self.remove_unused_transports();

        Ok(SdpAnswerState(response))
    }

    /// Remove all transports that are not being used anymore
    fn remove_unused_transports(&mut self) {
        self.transports.retain(|id, _| {
            // Is the transport in use by active media?
            let in_use_by_active = self.state.iter().any(|media| media.transport == id);

            // Is the transport in use by any pending changes?
            let in_use_by_pending = self.pending_changes.iter().any(|change| {
                if let PendingChange::AddMedia(add_media) = change {
                    add_media.bundle_transport == id || add_media.standalone_transport == Some(id)
                } else {
                    false
                }
            });

            if in_use_by_active || in_use_by_pending {
                true
            } else {
                self.transport_changes.push(TransportChange::Remove(id));
                false
            }
        });
    }

    fn update_active_media(&mut self, requested_direction: DirectionBools, media_id: MediaId) {
        let media = self
            .state
            .iter_mut()
            .find(|m| m.id == media_id)
            .expect("media_id must be valid");

        if media.direction != requested_direction {
            self.events.push_back(Event::MediaChanged(MediaChanged {
                id: media_id,
                old_direction: media.direction.into(),
                new_direction: requested_direction.into(),
            }));

            media.direction = requested_direction;
        }
    }

    /// Get or create a transport for the given media description
    ///
    /// If the transport type is unknown or cannot be created Ok(None) is returned. The media section must then be declined.
    fn get_or_create_transport(
        &mut self,
        new_state: &[ActiveMedia],
        session_desc: &SessionDescription,
        remote_media_desc: &MediaDescription,
    ) -> Result<Option<TransportId>, Error> {
        // See if there's a transport to be reused via BUNDLE group
        if let Some(id) = remote_media_desc
            .mid
            .as_ref()
            .and_then(|mid| self.find_bundled_transport(new_state, session_desc, mid))
        {
            return Ok(Some(id));
        }

        // TODO: this is very messy, create_from_offer return Ok(None) if the transport is not supported
        let maybe_transport_id =
            self.transports
                .try_insert_with_key(|id| -> Result<TransportEntry, Option<_>> {
                    Transport::create_from_offer(
                        &mut self.transport_state,
                        TransportRequiredChanges::new(id, &mut self.transport_changes),
                        session_desc,
                        remote_media_desc,
                    )
                    .map_err(Some)?
                    .map(TransportEntry::Transport)
                    .ok_or(None)
                });

        match maybe_transport_id {
            Ok(id) => Ok(Some(id)),
            Err(Some(err)) => Err(err),
            Err(None) => Ok(None),
        }
    }

    fn find_bundled_transport(
        &self,
        new_state: &[ActiveMedia],
        offer: &SessionDescription,
        mid: &BytesStr,
    ) -> Option<TransportId> {
        let group = offer
            .group
            .iter()
            .find(|g| g.typ == "BUNDLE" && g.mids.contains(mid))?;

        new_state.iter().chain(&self.state).find_map(|m| {
            let mid = m.mid.as_ref()?;

            group.mids.contains(mid).then_some(m.transport)
        })
    }

    /// Create an SDP Answer from a given state, which must be created by a previous call to [`SdpSession::receive_sdp_offer`].
    ///
    /// # Panics
    ///
    /// This function will panic if any transport has not been assigned a port.
    pub fn create_sdp_answer(&self, state: SdpAnswerState) -> SessionDescription {
        let mut media_descriptions = vec![];

        for entry in state.0 {
            let active = match entry {
                SdpResponseEntry::Active(media_id) => self
                    .state
                    .iter()
                    .find(|media| media.id == media_id)
                    .unwrap(),
                SdpResponseEntry::Rejected { media_type, mid } => {
                    let mut desc = MediaDescription::rejected(media_type);
                    desc.mid = mid;
                    media_descriptions.push(desc);
                    continue;
                }
            };

            media_descriptions.push(self.media_description_for_active(active, None));
        }

        let mut sess_desc = SessionDescription {
            origin: Origin {
                username: "-".into(),
                session_id: self.id.to_string().into(),
                session_version: self.version.to_string().into(),
                address: self.address.into(),
            },
            name: "-".into(),
            connection: Some(Connection {
                address: self.address.into(),
                ttl: None,
                num: None,
            }),
            bandwidth: vec![],
            time: Time { start: 0, stop: 0 },
            direction: Direction::SendRecv,
            group: self.build_bundle_groups(false),
            extmap: vec![],
            extmap_allow_mixed: true,
            ice_lite: false,
            ice_options: IceOptions::default(),
            ice_ufrag: None,
            ice_pwd: None,
            setup: None,
            fingerprint: vec![],
            attributes: vec![],
            media_descriptions,
        };

        if let Some(ice_credentials) = self
            .transports
            .values()
            .find_map(|t| Some(t.ice_agent()?.credentials()))
        {
            sess_desc.ice_ufrag = Some(IceUsernameFragment {
                ufrag: ice_credentials.ufrag.clone().into(),
            });

            sess_desc.ice_pwd = Some(IcePassword {
                pwd: ice_credentials.pwd.clone().into(),
            });
        }

        sess_desc
    }

    pub fn create_sdp_offer(&self) -> SessionDescription {
        let mut media_descriptions = vec![];

        // Put the current media sessions in the offer
        for media in &self.state {
            let mut override_direction = None;

            // Apply requested changes
            for change in &self.pending_changes {
                match change {
                    PendingChange::AddMedia(..) => {}
                    PendingChange::RemoveMedia(media_id) => {
                        if media.id == *media_id {
                            continue;
                        }
                    }
                    PendingChange::ChangeDirection(media_id, direction) => {
                        if media.id == *media_id {
                            override_direction = Some(*direction);
                        }
                    }
                }
            }

            media_descriptions.push(self.media_description_for_active(media, override_direction));
        }

        // Add all pending added media
        for change in &self.pending_changes {
            let PendingChange::AddMedia(pending_media) = change else {
                continue;
            };

            let local_media = &self.local_media[pending_media.local_media_id];
            let transport = &self.transports[pending_media
                .standalone_transport
                .unwrap_or(pending_media.bundle_transport)];

            let (local_rtp_port, local_rtcp_port) = match &transport {
                TransportEntry::Transport(transport) => {
                    (transport.local_rtp_port, transport.local_rtcp_port)
                }
                TransportEntry::TransportBuilder(transport_builder) => (
                    transport_builder.local_rtp_port,
                    transport_builder.local_rtcp_port,
                ),
            };

            let mut rtpmap = vec![];
            let mut fmtp = vec![];
            let mut fmts = vec![];

            for codec in &local_media.codecs.codecs {
                let pt = codec.pt.expect("pt is set when adding the codec");

                fmts.push(pt);

                rtpmap.push(RtpMap {
                    payload: pt,
                    encoding: codec.name.as_ref().into(),
                    clock_rate: codec.clock_rate,
                    params: codec.channels.map(|c| c.to_string().into()),
                });

                // TODO: are multiple fmtps allowed?
                if let Some(param) = &codec.fmtp {
                    fmtp.push(Fmtp {
                        format: pt,
                        params: param.as_str().into(),
                    });
                }
            }

            let mut media_desc = MediaDescription {
                media: Media {
                    media_type: local_media.codecs.media_type,
                    port: local_rtp_port.expect("rtp port not set for transport"),
                    ports_num: None,
                    proto: transport.type_().sdp_type(pending_media.use_avpf),
                    fmts,
                },
                connection: None,
                bandwidth: vec![],
                direction: pending_media.direction,
                rtcp: local_rtcp_port.map(|port| Rtcp {
                    port,
                    address: None,
                }),
                // always offer rtcp-mux
                rtcp_mux: true,
                mid: Some(pending_media.mid.as_str().into()),
                rtpmap,
                fmtp,
                ice_ufrag: None,
                ice_pwd: None,
                ice_candidates: vec![],
                ice_end_of_candidates: false,
                crypto: vec![],
                extmap: vec![],
                extmap_allow_mixed: false,
                ssrc: vec![],
                setup: None,
                fingerprint: vec![],
                attributes: vec![],
            };

            transport.populate_desc(&mut media_desc);

            media_descriptions.push(media_desc);
        }

        let mut sess_desc = SessionDescription {
            origin: Origin {
                username: "-".into(),
                session_id: self.id.to_string().into(),
                session_version: self.version.to_string().into(),
                address: self.address.into(),
            },
            name: "-".into(),
            connection: Some(Connection {
                address: self.address.into(),
                ttl: None,
                num: None,
            }),
            bandwidth: vec![],
            time: Time { start: 0, stop: 0 },
            direction: Direction::SendRecv,
            group: self.build_bundle_groups(true),
            extmap: vec![],
            extmap_allow_mixed: true,
            ice_lite: false,
            ice_options: IceOptions::default(),
            ice_ufrag: None,
            ice_pwd: None,
            setup: None,
            fingerprint: vec![],
            attributes: vec![],
            media_descriptions,
        };

        if let Some(ice_credentials) = self
            .transports
            .values()
            .find_map(|t| Some(t.ice_agent()?.credentials()))
        {
            sess_desc.ice_ufrag = Some(IceUsernameFragment {
                ufrag: ice_credentials.ufrag.clone().into(),
            });

            sess_desc.ice_pwd = Some(IcePassword {
                pwd: ice_credentials.pwd.clone().into(),
            });
        }

        sess_desc
    }

    /// Receive a SDP answer after sending an offer.
    pub fn receive_sdp_answer(&mut self, answer: SessionDescription) {
        'next_media_desc: for (mline, remote_media_desc) in
            answer.media_descriptions.iter().enumerate()
        {
            // Skip any rejected answers
            if remote_media_desc.direction == Direction::Inactive {
                continue;
            }

            let requested_direction: DirectionBools = remote_media_desc.direction.flipped().into();

            // Try to match an active media session, while filtering out media that is to be deleted
            for media in &mut self.state {
                let pending_removal = self
                    .pending_changes
                    .iter()
                    .any(|c| matches!(c, PendingChange::RemoveMedia(id) if *id == media.id));

                if pending_removal {
                    // Ignore this active media since it's supposed to be removed
                    continue;
                }

                if media.matches(&self.transports, remote_media_desc) {
                    // // TODO: update media
                    // let _ = requested_direction;
                    let media_id = media.id;
                    self.update_active_media(requested_direction, media_id);
                    continue 'next_media_desc;
                }
            }

            // Try to match a new media session
            for pending_change in &self.pending_changes {
                let PendingChange::AddMedia(pending_media) = pending_change else {
                    continue;
                };

                if !pending_media.matches_answer(&self.transports, remote_media_desc) {
                    continue;
                }

                // Check which transport to use, (standalone or bundled)
                let is_bundled = answer.group.iter().any(|group| {
                    group.typ == "BUNDLE"
                        && group.mids.iter().any(|m| m.as_str() == pending_media.mid)
                });

                let transport_id = if is_bundled {
                    pending_media.bundle_transport
                } else {
                    // TODO: return an error here instead, we required BUNDLE, but it is not supported
                    pending_media.standalone_transport.unwrap()
                };

                // Build transport if necessary
                if let TransportEntry::TransportBuilder(transport_builder) =
                    &mut self.transports[transport_id]
                {
                    let transport_builder =
                        replace(transport_builder, TransportBuilder::placeholder());

                    let transport = transport_builder.build_from_answer(
                        &mut self.transport_state,
                        TransportRequiredChanges::new(transport_id, &mut self.transport_changes),
                        &answer,
                        remote_media_desc,
                    );

                    self.transports[transport_id] = TransportEntry::Transport(transport);
                }

                let (codec, codec_pt, direction) = self.local_media[pending_media.local_media_id]
                    .choose_codec_from_answer(remote_media_desc)
                    .unwrap();

                let recv_fmtp = remote_media_desc
                    .fmtp
                    .iter()
                    .find(|f| f.format == codec_pt)
                    .map(|f| f.params.to_string());

                self.events.push_back(Event::MediaAdded(MediaAdded {
                    id: pending_media.id,
                    transport_id,
                    local_media_id: pending_media.local_media_id,
                    direction: direction.into(),
                    codec: NegotiatedCodec {
                        send_pt: codec_pt,
                        recv_pt: codec_pt,
                        name: codec.name.clone(),
                        clock_rate: codec.clock_rate,
                        channels: codec.channels,
                        send_fmtp: codec.fmtp.clone(),
                        recv_fmtp,
                    },
                }));

                self.state.push(ActiveMedia {
                    id: pending_media.id,
                    local_media_id: pending_media.local_media_id,
                    media_type: pending_media.media_type,
                    rtp_session: RtpSession::new(Ssrc(rand::random()), codec.clock_rate),
                    avpf: pending_media.use_avpf,
                    next_rtcp: Instant::now() + Duration::from_secs(5),
                    rtcp_interval: rtcp_interval(pending_media.media_type),
                    mid: remote_media_desc.mid.clone(),
                    direction,
                    transport: transport_id,
                    codec_pt,
                    codec,
                });

                continue 'next_media_desc;
            }

            // TODO: hard error?
            log::warn!("Failed to match mline={mline} to any offered media");
        }

        self.pending_changes.clear();
        self.remove_unused_transports();
    }

    fn media_description_for_active(
        &self,
        active: &ActiveMedia,
        override_direction: Option<Direction>,
    ) -> MediaDescription {
        let rtpmap = RtpMap {
            payload: active.codec_pt,
            encoding: active.codec.name.as_ref().into(),
            clock_rate: active.codec.clock_rate,
            params: Default::default(),
        };

        let fmtp = active.codec.fmtp.as_ref().map(|param| Fmtp {
            format: active.codec_pt,
            params: param.as_str().into(),
        });

        let transport = self.transports[active.transport].unwrap();

        let mut media_desc = MediaDescription {
            media: Media {
                media_type: active.media_type,
                port: transport
                    .local_rtp_port
                    .expect("Did not set port for RTP socket"),
                ports_num: None,
                proto: transport.type_().sdp_type(active.avpf),
                fmts: vec![active.codec_pt],
            },
            connection: None,
            bandwidth: vec![],
            direction: override_direction.unwrap_or(active.direction.into()),
            rtcp: transport.local_rtcp_port.map(|port| Rtcp {
                port,
                address: None,
            }),
            rtcp_mux: transport.remote_rtp_address == transport.remote_rtcp_address,
            mid: active.mid.clone(),
            rtpmap: vec![rtpmap],
            fmtp: fmtp.into_iter().collect(),
            ice_ufrag: None,
            ice_pwd: None,
            ice_candidates: vec![],
            ice_end_of_candidates: false,
            crypto: vec![],
            extmap: vec![],
            extmap_allow_mixed: false,
            ssrc: vec![],
            setup: None,
            fingerprint: vec![],
            attributes: vec![],
        };

        transport.populate_desc(&mut media_desc);

        media_desc
    }

    fn build_bundle_groups(&self, include_pending_changes: bool) -> Vec<Group> {
        let mut bundle_groups: HashMap<TransportId, Vec<BytesStr>> = HashMap::new();

        for media in &self.state {
            if let Some(mid) = media.mid.clone() {
                bundle_groups.entry(media.transport).or_default().push(mid);
            }
        }

        if include_pending_changes {
            for change in &self.pending_changes {
                if let PendingChange::AddMedia(pending_media) = change {
                    bundle_groups
                        .entry(pending_media.bundle_transport)
                        .or_default()
                        .push(pending_media.mid.as_str().into());
                }
            }
        }

        bundle_groups
            .into_values()
            .filter(|c| !c.is_empty())
            .map(|mids| Group {
                typ: BytesStr::from_static("BUNDLE"),
                mids,
            })
            .collect()
    }
}

fn is_avpf(t: &TransportProtocol) -> bool {
    match t {
        TransportProtocol::RtpAvpf
        | TransportProtocol::RtpSavpf
        | TransportProtocol::UdpTlsRtpSavpf => true,
        TransportProtocol::Unspecified
        | TransportProtocol::RtpAvp
        | TransportProtocol::RtpSavp
        | TransportProtocol::UdpTlsRtpSavp
        | TransportProtocol::Other(..) => false,
    }
}

fn rtcp_interval(media_type: MediaType) -> Duration {
    match media_type {
        MediaType::Video => Duration::from_secs(1),
        _ => Duration::from_secs(5),
    }
}
