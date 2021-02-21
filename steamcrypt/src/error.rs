/// An error that can occur while using this library.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ErrorKind::SessionKeyGeneration => write!(f, "failed to generate a SessionKey"),
            ErrorKind::OpenSSL(e) => write!(f, "{}", e),
        }
    }
}

impl Error {
    /// Create a new struct with a specific `ErrorKind`.
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Error { kind }
    }

    /// Return the kind of error captured.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::new(ErrorKind::OpenSSL(e))
    }
}

#[derive(Debug)]
/// Kinds of errors that can occur.
pub enum ErrorKind {
    /// An general error that occurred while generating a SessionKey.
    SessionKeyGeneration,
    /// An error that occurred while using OpenSSL functions.
    ///
    /// Contains the stacktrace from the actual OpenSSL error.
    OpenSSL(openssl::error::ErrorStack),
}
