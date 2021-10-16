use std::fmt;

#[derive(Debug)]
pub struct ParseError {
    wrapping: anyhow::Error,
}

impl From<anyhow::Error> for ParseError {
    fn from(wrapping: anyhow::Error) -> Self {
        Self { wrapping }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.wrapping.fmt(f)
    }
}

impl std::error::Error for ParseError {}

impl<I> nom::error::ParseError<I> for ParseError {
    fn from_error_kind(_: I, kind: nom::error::ErrorKind) -> Self {
        Self {
            wrapping: anyhow::anyhow!("failed at {}", kind.description()),
        }
    }

    fn append(_: I, kind: nom::error::ErrorKind, other: Self) -> Self {
        Self {
            wrapping: other
                .wrapping
                .context(format!("failed at {}", kind.description())),
        }
    }
}

impl<I> nom::error::ContextError<I> for ParseError {
    fn add_context(_: I, ctx: &'static str, other: Self) -> Self {
        Self {
            wrapping: other.wrapping.context(ctx),
        }
    }
}

impl<I, E> nom::error::FromExternalError<I, E> for ParseError
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from_external_error(_: I, _: nom::error::ErrorKind, e: E) -> Self {
        Self {
            wrapping: anyhow::Error::new(e),
        }
    }
}
