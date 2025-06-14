//! Internal EZK util functions shared between crates.

mod ws;

pub type IResult<I, O> = nom::IResult<I, O, nom::error::VerboseError<I>>;
pub use nom::Finish;
use nom::error::VerboseError;
pub use ws::ws;

pub fn verbose_error_to_owned(i: VerboseError<&str>) -> VerboseError<String> {
    VerboseError {
        errors: i
            .errors
            .into_iter()
            .map(|(i, kind)| (i.into(), kind))
            .collect(),
    }
}

pub fn identity<E>() -> impl Fn(&str) -> nom::IResult<&str, &str, E> {
    move |i| Ok(("", i))
}
