//! Printing utilities for SIP message components

use crate::method::Method;
use std::fmt;
use std::fmt::Formatter;
use std::ops::Deref;

/// Context in which an URI is being printed
#[derive(Copy, Clone)]
pub enum UriContext {
    /// The URI is being printed inside the request-line
    ReqUri,

    /// The URI is being printed inside an From/To header
    FromTo,

    /// The URI is being printed inside an Contact header
    Contact,

    /// The URI is being printed inside an Route/RecordRoute etc header
    Routing,
}

/// SIP message context for printing sip types
#[derive(Default, Copy, Clone)]
pub struct PrintCtx<'a> {
    /// method of the request being printed
    pub method: Option<&'a Method>,
    pub uri: Option<UriContext>,
}

/// Implements [`fmt::Display`] where `T` implements [`Print`] and passes its context to [`Print::print`]
///
/// Constructed using [`AppendCtx::print_ctx`].
pub struct WithPrintCtx<'a, T: ?Sized> {
    pub ctx: PrintCtx<'a>,
    _self: &'a T,
}

impl<T: Print> fmt::Display for WithPrintCtx<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Print::print(self._self, f, self.ctx)
    }
}

impl<T> Deref for WithPrintCtx<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self._self
    }
}

/// Helper trait to wrap types that implement [`Print`] into [`WithPrintCtx`]
pub trait AppendCtx: Sized {
    /// Wrap a type inside a [`WithPrintCtx`] so it implements display
    fn print_ctx<'a>(&'a self, ctx: PrintCtx<'a>) -> WithPrintCtx<'a, Self> {
        WithPrintCtx { ctx, _self: self }
    }

    /// Wraps a type inside [`WithPrintCtx`] containing a 'empty' [`PrintCtx`].
    ///
    /// Useful for tests
    fn default_print_ctx(&self) -> WithPrintCtx<'_, Self> {
        self.print_ctx(Default::default())
    }
}

impl<T: Print> AppendCtx for T {}

/// Trait similar to [`fmt::Display`] with the difference that it also takes a [`PrintCtx`]
///
/// It is used to print types which require the context of the message they are printed in.
pub trait Print {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result;
}

impl<T: fmt::Display> Print for T {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Implements std::fmt::Debug for byte-slices.
/// Useful to print ascii with special characters escaped
// taken from bytes crate with some small changes
pub struct BytesPrint<'b>(pub &'b [u8]);

impl fmt::Debug for BytesPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in self.0 {
            if b == b'\n' {
                writeln!(f, "\\n")?;
            } else if b == b'\r' {
                write!(f, "\\r")?;
            } else if b == b'\t' {
                write!(f, "\\t")?;
            } else if b == b'\\' || b == b'"' {
                write!(f, "\\{}", b as char)?;
            } else if b == b'\0' {
                write!(f, "\\0")?;
            // ASCII printable
            } else if (0x20..0x7f).contains(&b) {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "\\x{:02x}", b)?;
            }
        }
        Ok(())
    }
}
