use std::fmt;
use std::io;

/// Every failure r7z reports. Variants carry enough context to print a useful message.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The input is not an archive r7z recognizes.
    NotArchive,
    /// Structural damage in archive metadata.
    Corrupt(String),
    /// A valid archive feature that r7z does not implement.
    Unsupported(String),
    /// Encrypted content was found and no password was supplied.
    PasswordRequired,
    /// Decoding failed inside encrypted data, which almost always means a wrong password.
    WrongPassword,
    /// Decoded data did not match its stored checksum.
    Checksum(String),
    /// Bad command-line usage.
    Usage(String),
    /// The caller asked the operation to stop.
    Cancelled,
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corrupt(msg.into())
    }
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported(msg.into())
    }
    pub fn usage(msg: impl Into<String>) -> Self {
        Error::Usage(msg.into())
    }

    /// Converts a codec I/O error back into a typed error when it wraps one.
    pub fn from_codec(e: io::Error) -> Self {
        if e.get_ref()
            .map(|inner| inner.is::<Error>())
            .unwrap_or(false)
        {
            let inner = e.into_inner().unwrap();
            return *inner.downcast::<Error>().unwrap();
        }
        match e.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
                Error::Corrupt(format!("data error: {e}"))
            }
            _ => Error::Io(e),
        }
    }

    /// Wraps this error so it can travel through `io::Read`/`io::Write` and be recovered.
    pub fn into_io(self) -> io::Error {
        match self {
            Error::Io(e) => e,
            other => io::Error::other(other),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::NotArchive => write!(f, "not a supported archive"),
            Error::Corrupt(m) => write!(f, "archive is corrupt: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::PasswordRequired => write!(f, "archive is encrypted; a password is required"),
            Error::WrongPassword => write!(f, "wrong password (or corrupted encrypted data)"),
            Error::Checksum(m) => write!(f, "CRC mismatch: {m}"),
            Error::Usage(m) => write!(f, "{m}"),
            Error::Cancelled => write!(f, "cancelled"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::from_codec(e)
    }
}
