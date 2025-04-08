use sip_core::transaction::TsxResponse;
use sip_core::transport::OutgoingResponse;
use sip_core::{IncomingRequest, Request};
use sip_types::header::typed::{MinSe, Refresher, Require, SessionExpires};
use sip_types::header::HeaderError;
use sip_types::Name;
use std::future::pending;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::{sleep, Sleep};

/// Config of the `timer` extension used by the acceptor
pub struct AcceptorTimerConfig {
    pub refresher: Refresher,
    pub interval_secs: u32,
}

impl Default for AcceptorTimerConfig {
    fn default() -> Self {
        Self {
            refresher: Refresher::Uac,
            interval_secs: 1800,
        }
    }
}

impl AcceptorTimerConfig {
    /// Takes the final successful response and the invite the response belongs to.
    /// Populates the given response with an `Session-Expires` header and returns a
    /// proper `SessionTimer` object to be used inside a session.
    pub fn on_responding_success(
        &mut self,
        response: &mut OutgoingResponse,
        invite: &IncomingRequest,
    ) -> SessionTimer {
        let delta_secs = if let Ok(min_se) = invite.headers.get_named::<MinSe>() {
            min_se.0.max(self.interval_secs)
        } else {
            self.interval_secs
        };

        let real_delta_secs;

        // Map unspecified -> Uac as usually if none is specified
        // the UAC side is responsible for refreshes
        self.refresher = match self.refresher {
            Refresher::Uas => {
                real_delta_secs = delta_secs / 2;
                Refresher::Uas
            }
            Refresher::Unspecified | Refresher::Uac => {
                real_delta_secs = delta_secs;
                Refresher::Uac
            }
        };

        response.msg.headers.insert_named(&Require("timer".into()));
        response.msg.headers.insert_named(&SessionExpires {
            delta_secs,
            refresher: self.refresher,
        });

        let sleep = sleep(Duration::from_secs(real_delta_secs as u64));

        SessionTimer {
            refresher: self.refresher,
            real_delta_secs,
            interval: RefreshInterval::Sleeping(Box::pin(sleep)),
        }
    }
}

/// Config of the `timer` extension used by the initiator
#[derive(Debug, Clone, Copy)]
pub struct InitiatorTimerConfig {
    pub expires_secs: Option<u32>,
    pub refresher: Refresher,
    pub expires_secs_min: u32,
}

impl InitiatorTimerConfig {
    pub fn populate_request(&self, request: &mut Request) {
        if let Some(expires_secs) = self.expires_secs {
            request.headers.insert_named(&SessionExpires {
                delta_secs: expires_secs,
                refresher: self.refresher,
            });
        }

        request.headers.insert(Name::SUPPORTED, "timer");
        request.headers.insert_named(&MinSe(self.expires_secs_min));
    }

    pub fn create_timer_from_response(
        &self,
        response: &TsxResponse,
    ) -> Result<SessionTimer, HeaderError> {
        if let Some(se) = response
            .headers
            .try_get_named::<SessionExpires>()
            .transpose()?
        {
            let real_delta_secs;

            let refresher = match se.refresher {
                Refresher::Uas => {
                    real_delta_secs = se.delta_secs;
                    Refresher::Uas
                }
                Refresher::Unspecified | Refresher::Uac => {
                    real_delta_secs = se.delta_secs / 2;
                    Refresher::Uac
                }
            };

            let sleep = sleep(Duration::from_secs(real_delta_secs as u64));

            Ok(SessionTimer {
                refresher,
                real_delta_secs,
                interval: RefreshInterval::Sleeping(Box::pin(sleep)),
            })
        } else {
            Ok(SessionTimer::new_unsupported())
        }
    }
}

/// Timer which is used to track whenever a session is expired
/// and when it needs to be refreshed depending on the refresher
#[derive(Debug)]
pub struct SessionTimer {
    pub refresher: Refresher,
    pub real_delta_secs: u32,
    pub interval: RefreshInterval,
}

impl SessionTimer {
    /// Create a new session timer that will never expire.
    /// Useful for sessions with peers that do not support the `timer` extension.
    pub fn new_unsupported() -> Self {
        Self {
            refresher: Refresher::Unspecified,
            real_delta_secs: 0,
            interval: RefreshInterval::Unsupported,
        }
    }

    /// Wait for the session to expire. Will never return if no session expiry is set
    pub async fn wait(&mut self) {
        match &mut self.interval {
            RefreshInterval::Unsupported => pending().await,
            RefreshInterval::Sleeping(sleep) => sleep.await,
        }
    }

    /// Resets the timer. Must be called after refreshing the session.
    pub fn reset(&mut self) {
        match &mut self.interval {
            RefreshInterval::Unsupported => {}
            RefreshInterval::Sleeping(sleep_) => {
                sleep_.set(sleep(Duration::from_secs(self.real_delta_secs as u64)))
            }
        }
    }

    /// Populate headers of an INVITE refresh request
    pub fn populate_refresh(&mut self, request: &mut Request) {
        if let RefreshInterval::Unsupported = &mut self.interval {
            return;
        }

        request.headers.insert(Name::SUPPORTED, "timer");
        request.headers.insert(Name::REQUIRE, "timer");
    }
}

#[derive(Debug)]
pub enum RefreshInterval {
    Unsupported,
    Sleeping(Pin<Box<Sleep>>),
}
