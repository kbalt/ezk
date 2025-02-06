use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum Setup {
    Active,
    Passive,
    ActPass,
    HoldConn,
}

impl Setup {
    fn as_str(&self) -> &'static str {
        match self {
            Setup::Active => "active",
            Setup::Passive => "passive",
            Setup::ActPass => "actpass",
            Setup::HoldConn => "holdconn",
        }
    }
}

impl fmt::Display for Setup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
