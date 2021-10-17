use sip_core::{transport::OutgoingResponse, IncomingRequest};
use sip_types::header::typed::{MinSe, Refresher, Require, SessionExpires};
use std::{future::pending, pin::Pin, time::Duration};
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
                real_delta_secs = delta_secs - 10;
                Refresher::Uas
            }
            Refresher::Unspecified | Refresher::Uac => {
                real_delta_secs = delta_secs + 10;
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
}

#[derive(Debug)]
pub enum RefreshInterval {
    Unsupported,
    Sleeping(Pin<Box<Sleep>>),
}
