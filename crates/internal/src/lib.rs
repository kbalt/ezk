//! Internal EZK util functions shared between crates.

mod error;
mod ws;

pub type IResult<I, O> = nom::IResult<I, O, ParseError>;
pub use error::ParseError;
pub use nom::Finish;
pub use ws::ws;
