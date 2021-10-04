use sip_types::header::HeaderError;
use sip_types::Code;
use std::error::Error as StdError;
use std::str::Utf8Error;
use std::{fmt, io};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[macro_export]
macro_rules! bail_status {
    ($status:expr) => {
        return Err($crate::Error::new($status))
    };
}

#[derive(Debug)]
pub struct Error {
    pub status: Code,
    pub error: Option<anyhow::Error>,
}

impl Error {
    pub fn new(status: Code) -> Self {
        Self {
            status,
            error: None,
        }
    }

    pub fn new_error<E>(status: Code, error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            status,
            error: Some(anyhow::Error::new(error)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "status={}", self.status.into_u16())?;

        if let Some(text) = self.status.text() {
            write!(f, " ({})", text)?;
        }

        if let Some(error) = &self.error {
            write!(f, " {}", error)?;
        }

        Ok(())
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self {
            status: Code::SERVICE_UNAVAILABLE,
            error: Some(anyhow::Error::new(error)),
        }
    }
}

impl From<HeaderError> for Error {
    fn from(error: HeaderError) -> Self {
        Self {
            status: Code::BAD_REQUEST,
            error: Some(anyhow::Error::new(error)),
        }
    }
}

impl From<Utf8Error> for Error {
    fn from(error: Utf8Error) -> Self {
        Self {
            status: Code::BAD_REQUEST,
            error: Some(anyhow::Error::new(error)),
        }
    }
}

pub trait WithStatus<T> {
    fn status(self, status: Code) -> Result<T, Error>;
}

impl<T> WithStatus<T> for Option<T> {
    fn status(self, status: Code) -> Result<T, Error> {
        self.ok_or(Error {
            status,
            error: None,
        })
    }
}

impl<T> WithStatus<T> for Result<T, Error> {
    fn status(self, status: Code) -> Result<T, Error> {
        self.map_err(|error| Error { status, ..error })
    }
}

impl<T, E> WithStatus<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn status(self, status: Code) -> Result<T, Error> {
        self.map_err(|error| Error {
            status,
            error: Some(anyhow::Error::new(error)),
        })
    }
}
