use std::fmt;

#[derive(Debug)]
pub struct LabError(pub String);

impl LabError {
    pub fn new(msg: impl Into<String>) -> Self {
        LabError(msg.into())
    }
}

impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LabError {}

impl From<serde_json::Error> for LabError {
    fn from(e: serde_json::Error) -> Self {
        LabError(e.to_string())
    }
}

impl From<std::io::Error> for LabError {
    fn from(e: std::io::Error) -> Self {
        LabError(e.to_string())
    }
}

impl From<std::str::Utf8Error> for LabError {
    fn from(e: std::str::Utf8Error) -> Self {
        LabError(e.to_string())
    }
}

impl From<std::num::TryFromIntError> for LabError {
    fn from(e: std::num::TryFromIntError) -> Self {
        LabError(e.to_string())
    }
}

pub type LabResult<T> = Result<T, LabError>;
