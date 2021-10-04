//! Contains the URI trait, SIP and NameAddr implementation

use crate::host::HostPort;
use crate::print::{Print, PrintCtx};
use crate::uri::sip::SipUri;
use downcast_rs::Downcast;
use std::borrow::Cow;
use std::fmt;

#[macro_use]
pub mod params;
mod name_addr;
pub mod sip;

pub use name_addr::NameAddr;

/// Represents a URI.
pub trait Uri: Print + Send + Sync + fmt::Debug + Downcast + 'static {
    /// Returns [`UriInfo`]
    fn info(&self) -> UriInfo<'_>;

    /// Compares this uri to the other uri.
    fn compare(&self, other: &dyn Uri) -> bool;

    /// Returns a clone of the uri
    fn clone_boxed(&self) -> Box<dyn Uri>;
}

impl<T: Uri> From<T> for Box<dyn Uri> {
    fn from(t: T) -> Self {
        Box::new(t)
    }
}

downcast_rs::impl_downcast!(Uri);

impl Print for Box<dyn Uri> {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        Print::print(&(**self), f, ctx)
    }
}

impl Uri for sip::SipUri {
    fn info(&self) -> UriInfo<'_> {
        UriInfo {
            transport: self
                .uri_params
                .get_val("transport")
                .map(|transport| Cow::Borrowed(transport.as_str())),
            secure: self.sips,
            host_port: self.host_port.clone(),
        }
    }

    fn compare(&self, other: &dyn Uri) -> bool {
        if let Some(other) = other.downcast_ref::<Self>() {
            self.compare(other)
        } else {
            false
        }
    }

    fn clone_boxed(&self) -> Box<dyn Uri> {
        Box::new(SipUri::clone(self))
    }
}

impl Clone for Box<dyn Uri> {
    fn clone(&self) -> Self {
        self.clone_boxed()
    }
}

/// [`Uri`]s can specify information used to determine their target and how to reach it
pub struct UriInfo<'i> {
    /// Some uris can specify a specific transport
    pub transport: Option<Cow<'i, str>>,

    /// The URI __must__ be used in a secure context
    pub secure: bool,

    /// [`HostPort`] part of the uri
    pub host_port: HostPort,
}

impl UriInfo<'_> {
    pub fn allows_security_level(&self, secure: bool) -> bool {
        if self.secure {
            secure
        } else {
            true
        }
    }
}
