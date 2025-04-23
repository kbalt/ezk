use super::events::{MediaAdded, MediaChanged, TransportChange};
use super::media::Media;
use super::transport::{Transport, TransportBuilder};
use super::{DirectionBools, Event, PendingChange, SessionState, TransportEntry};
use crate::codecs::{NegotiatedCodec, NegotiatedDtmf};
use crate::{Error, MediaId, TransportId};
use bytesstr::BytesStr;
use sdp_types::{
    Connection, Direction, Fmtp, Group, IceOptions, IcePassword, IceUsernameFragment,
    MediaDescription, MediaType, Origin, Rtcp, RtpMap, SessionDescription, Time, TransportProtocol,
};
use std::mem::take;
use std::{collections::HashMap, mem::replace};

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

impl SessionState {
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
                self.update_active_media(requested_direction, self.state[position].id());
                let media = self.state.remove(position);
                response.push(SdpResponseEntry::Active(media.id()));
                new_state.push(media);
                continue;
            }

            // Choose local media for this media description
            let chosen_media = self.local_media.iter_mut().find_map(|(id, local_media)| {
                local_media
                    .maybe_use_for_offer(remote_media_desc)
                    .map(|config| (id, config))
            });

            let Some((local_media_id, chosen_codec)) = chosen_media else {
                // no local media found for this
                response.push(SdpResponseEntry::Rejected {
                    media_type: remote_media_desc.media.media_type,
                    mid: remote_media_desc.mid.clone(),
                });

                log::debug!("Rejecting mline={mline}, no compatible local media found");
                continue;
            };

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
                .find(|f| f.format == chosen_codec.remote_pt)
                .map(|f| f.params.to_string());

            let dtmf = if let Some(dtmf_pt) = chosen_codec.dtmf {
                let fmtp = remote_media_desc
                    .fmtp
                    .iter()
                    .find(|fmtp| fmtp.format == dtmf_pt)
                    .map(|fmtp| fmtp.params.to_string());

                Some(NegotiatedDtmf { pt: dtmf_pt, fmtp })
            } else {
                None
            };

            let media_id = self.next_media_id.increment();
            self.events.push_back(Event::MediaAdded(MediaAdded {
                id: media_id,
                transport_id: transport,
                local_media_id,
                direction: chosen_codec.direction.into(),
                codec: NegotiatedCodec {
                    send_pt: chosen_codec.remote_pt,
                    recv_pt: chosen_codec.remote_pt,
                    name: chosen_codec.codec.name.clone(),
                    clock_rate: chosen_codec.codec.clock_rate,
                    channels: chosen_codec.codec.channels,
                    send_fmtp: chosen_codec.codec.fmtp.clone(),
                    recv_fmtp,
                    dtmf,
                },
            }));

            response.push(SdpResponseEntry::Active(media_id));
            new_state.push(Media::new(
                media_id,
                local_media_id,
                remote_media_desc.media.media_type,
                remote_media_desc.mid.clone(),
                chosen_codec.direction,
                is_avpf(&remote_media_desc.media.proto),
                transport,
                chosen_codec.remote_pt,
                chosen_codec.codec,
                chosen_codec.dtmf,
            ));
        }

        // Store new state and destroy all media sessions
        let removed_media = replace(&mut self.state, new_state);

        for media in removed_media {
            self.local_media[media.local_media_id()].use_count -= 1;
            self.events.push_back(Event::MediaRemoved(media.id()));
        }

        self.remove_unused_transports();

        Ok(SdpAnswerState(response))
    }

    /// Remove all transports that are not being used anymore
    fn remove_unused_transports(&mut self) {
        self.transports.retain(|id, _| {
            // Is the transport in use by active media?
            let in_use_by_active = self.state.iter().any(|media| media.transport_id() == id);

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
            .find(|media| media.id() == media_id)
            .expect("media_id must be valid");

        if media.direction() != requested_direction.into() {
            self.events.push_back(Event::MediaChanged(MediaChanged {
                id: media_id,
                old_direction: media.direction(),
                new_direction: requested_direction.into(),
            }));

            media.set_direction(requested_direction);
        }
    }

    /// Get or create a transport for the given media description
    ///
    /// If the transport type is unknown or cannot be created Ok(None) is returned. The media section must then be declined.
    fn get_or_create_transport(
        &mut self,
        new_state: &[Media],
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
                        id,
                        &mut self.transport_state,
                        &mut self.transport_changes,
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
        new_state: &[Media],
        offer: &SessionDescription,
        mid: &BytesStr,
    ) -> Option<TransportId> {
        let group = offer
            .group
            .iter()
            .find(|g| g.typ == "BUNDLE" && g.mids.contains(mid))?;

        new_state.iter().chain(&self.state).find_map(|media| {
            let mid = media.mid()?;

            group
                .mids
                .iter()
                .any(|v| v == mid)
                .then_some(media.transport_id())
        })
    }

    /// Create an SDP Answer from a given state, which must be created by a previous call to [`SessionState::receive_sdp_offer`].
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
                    .find(|media| media.id() == media_id)
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
                        if media.id() == *media_id {
                            continue;
                        }
                    }
                    PendingChange::ChangeDirection(media_id, direction) => {
                        if media.id() == *media_id {
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

                if let Some(param) = &codec.fmtp {
                    fmtp.push(Fmtp {
                        format: pt,
                        params: param.as_str().into(),
                    });
                }
            }

            for &(pt, clock_rate) in &local_media.dtmf {
                rtpmap.push(RtpMap {
                    payload: pt,
                    encoding: "telephone-event".into(),
                    clock_rate,
                    params: None,
                });
                fmts.push(pt);
            }

            let mut media_desc = MediaDescription {
                media: sdp_types::Media {
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
                    .any(|c| matches!(c, PendingChange::RemoveMedia(id) if *id == media.id()));

                if pending_removal {
                    // Ignore this active media since it's supposed to be removed
                    continue;
                }

                if media.matches(&self.transports, remote_media_desc) {
                    let media_id = media.id();
                    self.update_active_media(requested_direction, media_id);
                    continue 'next_media_desc;
                }
            }

            // Try to match a new media session
            for (i, pending_change) in self.pending_changes.iter().enumerate() {
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
                        transport_id,
                        &mut self.transport_state,
                        &mut self.transport_changes,
                        &answer,
                        remote_media_desc,
                    );

                    self.transports[transport_id] = TransportEntry::Transport(transport);
                }

                let chosen_codec = self.local_media[pending_media.local_media_id]
                    .choose_codec_from_answer(remote_media_desc)
                    .unwrap();

                let recv_fmtp = remote_media_desc
                    .fmtp
                    .iter()
                    .find(|f| f.format == chosen_codec.remote_pt)
                    .map(|f| f.params.to_string());

                let dtmf = if let Some(dtmf_pt) = chosen_codec.dtmf {
                    let fmtp = remote_media_desc
                        .fmtp
                        .iter()
                        .find(|fmtp| fmtp.format == dtmf_pt)
                        .map(|fmtp| fmtp.params.to_string());

                    Some(NegotiatedDtmf { pt: dtmf_pt, fmtp })
                } else {
                    None
                };

                self.events.push_back(Event::MediaAdded(MediaAdded {
                    id: pending_media.id,
                    transport_id,
                    local_media_id: pending_media.local_media_id,
                    direction: chosen_codec.direction.into(),
                    codec: NegotiatedCodec {
                        send_pt: chosen_codec.remote_pt,
                        recv_pt: chosen_codec.remote_pt,
                        name: chosen_codec.codec.name.clone(),
                        clock_rate: chosen_codec.codec.clock_rate,
                        channels: chosen_codec.codec.channels,
                        send_fmtp: chosen_codec.codec.fmtp.clone(),
                        recv_fmtp,
                        dtmf,
                    },
                }));

                self.state.push(Media::new(
                    pending_media.id,
                    pending_media.local_media_id,
                    pending_media.media_type,
                    remote_media_desc.mid.clone(),
                    chosen_codec.direction,
                    pending_media.use_avpf,
                    transport_id,
                    chosen_codec.remote_pt,
                    chosen_codec.codec,
                    chosen_codec.dtmf,
                ));

                // remove the matched pending added media to avoid doubly matching it
                self.pending_changes.remove(i);

                continue 'next_media_desc;
            }

            // TODO: hard error?
            log::warn!("Failed to match mline={mline} to any offered media");
        }

        // remove all media that is pending removal
        for change in take(&mut self.pending_changes) {
            if let PendingChange::RemoveMedia(media_id) = change {
                self.state.retain(|m| {
                    if m.id() == media_id {
                        self.events.push_back(Event::MediaRemoved(media_id));
                        false
                    } else {
                        true
                    }
                });
            }
        }

        self.remove_unused_transports();
    }

    fn media_description_for_active(
        &self,
        media: &Media,
        override_direction: Option<Direction>,
    ) -> MediaDescription {
        let (codec, codec_pt) = media.codec_with_pt();

        let mut rtpmap = vec![];
        let mut fmtp = vec![];

        rtpmap.push(RtpMap {
            payload: codec_pt,
            encoding: codec.name.as_ref().into(),
            clock_rate: codec.clock_rate,
            params: Default::default(),
        });

        fmtp.extend(codec.fmtp.as_ref().map(|param| Fmtp {
            format: codec_pt,
            params: param.as_str().into(),
        }));

        let transport = self.transports[media.transport_id()].unwrap();

        let mut media_desc = MediaDescription {
            media: sdp_types::Media {
                media_type: self.local_media[media.local_media_id()].codecs.media_type,
                port: transport
                    .local_rtp_port
                    .expect("Did not set port for RTP socket"),
                ports_num: None,
                proto: transport.type_().sdp_type(media.use_avpf()),
                fmts: vec![codec_pt],
            },
            connection: None,
            bandwidth: vec![],
            direction: override_direction.unwrap_or(media.direction()),
            rtcp: transport.local_rtcp_port.map(|port| Rtcp {
                port,
                address: None,
            }),
            rtcp_mux: transport.remote_rtp_address == transport.remote_rtcp_address,
            mid: media.mid().map(Into::into),
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

        media_desc
    }

    fn build_bundle_groups(&self, include_pending_changes: bool) -> Vec<Group> {
        let mut bundle_groups: HashMap<TransportId, Vec<BytesStr>> = HashMap::new();

        for media in &self.state {
            if let Some(mid) = media.mid() {
                bundle_groups
                    .entry(media.transport_id())
                    .or_default()
                    .push(mid.into());
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
