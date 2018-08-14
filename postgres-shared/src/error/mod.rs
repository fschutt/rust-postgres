//! Errors.

use fallible_iterator::FallibleIterator;
use postgres_protocol::message::backend::{ErrorFields, FallibleIteratorError};
use std::error;
use std::convert::From;
use std::fmt;

pub use self::sqlstate::*;

mod sqlstate;

/// The severity of a Postgres error or notice.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Severity {
    /// PANIC
    Panic,
    /// FATAL
    Fatal,
    /// ERROR
    Error,
    /// WARNING
    Warning,
    /// NOTICE
    Notice,
    /// DEBUG
    Debug,
    /// INFO
    Info,
    /// LOG
    Log,
}

impl fmt::Display for Severity {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            Severity::Panic => "PANIC",
            Severity::Fatal => "FATAL",
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
            Severity::Notice => "NOTICE",
            Severity::Debug => "DEBUG",
            Severity::Info => "INFO",
            Severity::Log => "LOG",
        };
        fmt.write_str(s)
    }
}

impl Severity {
    fn from_str(s: &str) -> Option<Severity> {
        match s {
            "PANIC" => Some(Severity::Panic),
            "FATAL" => Some(Severity::Fatal),
            "ERROR" => Some(Severity::Error),
            "WARNING" => Some(Severity::Warning),
            "NOTICE" => Some(Severity::Notice),
            "DEBUG" => Some(Severity::Debug),
            "INFO" => Some(Severity::Info),
            "LOG" => Some(Severity::Log),
            _ => None,
        }
    }
}

/// A Postgres error or notice.
#[derive(Clone, PartialEq, Eq)]
pub struct DbError {
    /// The field contents are ERROR, FATAL, or PANIC (in an error message),
    /// or WARNING, NOTICE, DEBUG, INFO, or LOG (in a notice message), or a
    /// localized translation of one of these.
    pub severity: String,

    /// A parsed, nonlocalized version of `severity`. (PostgreSQL 9.6+)
    pub parsed_severity: Option<Severity>,

    /// The SQLSTATE code for the error.
    pub code: SqlState,

    /// The primary human-readable error message. This should be accurate but
    /// terse (typically one line).
    pub message: String,

    /// An optional secondary error message carrying more detail about the
    /// problem. Might run to multiple lines.
    pub detail: Option<String>,

    /// An optional suggestion what to do about the problem. This is intended
    /// to differ from Detail in that it offers advice (potentially
    /// inappropriate) rather than hard facts. Might run to multiple lines.
    pub hint: Option<String>,

    /// An optional error cursor position into either the original query string
    /// or an internally generated query.
    pub position: Option<ErrorPosition>,

    /// An indication of the context in which the error occurred. Presently
    /// this includes a call stack traceback of active procedural language
    /// functions and internally-generated queries. The trace is one entry per
    /// line, most recent first.
    pub where_: Option<String>,

    /// If the error was associated with a specific database object, the name
    /// of the schema containing that object, if any. (PostgreSQL 9.3+)
    pub schema: Option<String>,

    /// If the error was associated with a specific table, the name of the
    /// table. (Refer to the schema name field for the name of the table's
    /// schema.) (PostgreSQL 9.3+)
    pub table: Option<String>,

    /// If the error was associated with a specific table column, the name of
    /// the column. (Refer to the schema and table name fields to identify the
    /// table.) (PostgreSQL 9.3+)
    pub column: Option<String>,

    /// If the error was associated with a specific data type, the name of the
    /// data type. (Refer to the schema name field for the name of the data
    /// type's schema.) (PostgreSQL 9.3+)
    pub datatype: Option<String>,

    /// If the error was associated with a specific constraint, the name of the
    /// constraint. Refer to fields listed above for the associated table or
    /// domain. (For this purpose, indexes are treated as constraints, even if
    /// they weren't created with constraint syntax.) (PostgreSQL 9.3+)
    pub constraint: Option<String>,

    /// The file name of the source-code location where the error was reported.
    pub file: Option<String>,

    /// The line number of the source-code location where the error was
    /// reported.
    pub line: Option<u32>,

    /// The name of the source-code routine reporting the error.
    pub routine: Option<String>,

    _p: (),
}

#[derive(Debug, Clone)]
pub enum DbErrorCreateError {
    FieldDidNotContainInteger(char),
    FieldMissing(char),
    AMissingButBPresent { a: char, b: char },
    InvalidMessageLength(FallibleIteratorError),
}

impl From<FallibleIteratorError> for DbErrorCreateError {
    fn from(e: FallibleIteratorError) -> Self {
        DbErrorCreateError::InvalidMessageLength(e)
    }
}

impl DbError {
    #[doc(hidden)]
    pub fn new(fields: &mut ErrorFields) -> Result<DbError, DbErrorCreateError> {
        let mut severity = None;
        let mut parsed_severity = None;
        let mut code = None;
        let mut message = None;
        let mut detail = None;
        let mut hint = None;
        let mut normal_position = None;
        let mut internal_position = None;
        let mut internal_query = None;
        let mut where_ = None;
        let mut schema = None;
        let mut table = None;
        let mut column = None;
        let mut datatype = None;
        let mut constraint = None;
        let mut file = None;
        let mut line = None;
        let mut routine = None;

        while let Some(field) = fields.next()? {
            match field.type_() {
                b'S' => severity = Some(field.value().to_owned()),
                b'C' => code = Some(SqlState::from_code(field.value())),
                b'M' => message = Some(field.value().to_owned()),
                b'D' => detail = Some(field.value().to_owned()),
                b'H' => hint = Some(field.value().to_owned()),
                b'P' => {
                    normal_position = Some(field.value().parse::<u32>().map_err(|_|
                        DbErrorCreateError::FieldDidNotContainInteger('P'))?);
                }
                b'p' => {
                    internal_position = Some(field.value().parse::<u32>().map_err(|_|
                        DbErrorCreateError::FieldDidNotContainInteger('p'))?);
                }
                b'q' => internal_query = Some(field.value().to_owned()),
                b'W' => where_ = Some(field.value().to_owned()),
                b's' => schema = Some(field.value().to_owned()),
                b't' => table = Some(field.value().to_owned()),
                b'c' => column = Some(field.value().to_owned()),
                b'd' => datatype = Some(field.value().to_owned()),
                b'n' => constraint = Some(field.value().to_owned()),
                b'F' => file = Some(field.value().to_owned()),
                b'L' => {
                    line = Some(field.value().parse::<u32>().map_err(|_|
                        DbErrorCreateError::FieldDidNotContainInteger('L'))?);
                }
                b'R' => routine = Some(field.value().to_owned()),
                b'V' => {
                    parsed_severity = Some(Severity::from_str(field.value()).ok_or_else(||
                        DbErrorCreateError::FieldDidNotContainInteger('V'))?);
                }
                _ => {}
            }
        }

        Ok(DbError {
            severity: severity.ok_or_else(|| DbErrorCreateError::FieldMissing('S'))?,
            parsed_severity: parsed_severity,
            code: code.ok_or_else(|| DbErrorCreateError::FieldMissing('C'))?,
            message: message.ok_or_else(|| DbErrorCreateError::FieldMissing('M'))?,
            detail: detail,
            hint: hint,
            position: match normal_position {
                Some(position) => Some(ErrorPosition::Normal(position)),
                None => {
                    match internal_position {
                        Some(position) => {
                            Some(ErrorPosition::Internal {
                                position: position,
                                query: internal_query.ok_or_else(||
                                    DbErrorCreateError::AMissingButBPresent { a: 'q', b: 'p' })?,
                            })
                        }
                        None => None,
                    }
                }
            },
            where_: where_,
            schema: schema,
            table: table,
            column: column,
            datatype: datatype,
            constraint: constraint,
            file: file,
            line: line,
            routine: routine,
            _p: (),
        })
    }
}

// manual impl to leave out _p
impl fmt::Debug for DbError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("DbError")
            .field("severity", &self.severity)
            .field("parsed_severity", &self.parsed_severity)
            .field("code", &self.code)
            .field("message", &self.message)
            .field("detail", &self.detail)
            .field("hint", &self.hint)
            .field("position", &self.position)
            .field("where_", &self.where_)
            .field("schema", &self.schema)
            .field("table", &self.table)
            .field("column", &self.column)
            .field("datatype", &self.datatype)
            .field("constraint", &self.constraint)
            .field("file", &self.file)
            .field("line", &self.line)
            .field("routine", &self.routine)
            .finish()
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}: {}", self.severity, self.message)
    }
}

impl error::Error for DbError {
    fn description(&self) -> &str {
        &self.message
    }
}

/// Represents the position of an error in a query.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ErrorPosition {
    /// A position in the original query.
    Normal(u32),
    /// A position in an internally generated query.
    Internal {
        /// The byte position.
        position: u32,
        /// A query generated by the Postgres server.
        query: String,
    },
}

#[derive(Debug, Clone)]
pub enum UrlParseError {
    InvalidConnectionTimeout,
    InvalidKeepalive,
    DecodeError(DecodeError),
}

impl From<DecodeError> for UrlParseError {
    fn from(e: DecodeError) -> Self {
        UrlParseError::DecodeError(e)
    }
}

impl fmt::Display for UrlParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::UrlParseError::*;
        match self {
            InvalidConnectionTimeout => write!(f, "invalid connection timeout"),
            InvalidKeepalive => write!(f, "invalid keepalive"),
            DecodeError(e) => write!(f, "{}", e),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DecodeError {
    Component(ComponentDecodeError),
    Scheme(SchemeDecodeError),
    Authority(AuthorityDecodeError),
    Path(PathDecodeError),
    QueryFragment(QueryFragmentDecodeError)
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DecodeError::*;
        match *self {
            Component(ref c) => write!(f, "{}", c),
            Scheme(ref s) => write!(f, "{}", s),
            Authority(ref a) => write!(f, "{}", a),
            Path(ref p) => write!(f, "{}", p),
            QueryFragment(ref q) => write!(f, "{}", q),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ComponentDecodeError {
    NoTwoTrailingBytes,
    PercentageSignNotEscaped,
}

impl fmt::Display for ComponentDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ComponentDecodeError::*;
        match self {
            NoTwoTrailingBytes => write!(f, "no two trailing bytes"),
            PercentageSignNotEscaped => write!(f, "% sign not escaped"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AuthorityDecodeError {
    /// Illegal character in authority
    IllegalCharacterAuthority,
    /// Illegal characters in IPv6 address.
    IllegalCharacterIPv6,
    /// Invalid ':' in authority.
    InvalidDoubleColon,
    /// Invalid '@' in authority.
    InvalidAtSign,
    /// Non-digit characters in port.
    PortHasNonDigitChars,
    /// Failed to parse port: {:?}, port
    FailedToParsePort(String),
}

impl fmt::Display for AuthorityDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::AuthorityDecodeError::*;
        match self {
            IllegalCharacterAuthority => write!(f, "Illegal character in authority"),
            IllegalCharacterIPv6 => write!(f, "Illegal characters in IPv6 address"),
            InvalidDoubleColon => write!(f, "Invalid ':' in authority"),
            InvalidAtSign => write!(f, "Invalid '@' in authority"),
            PortHasNonDigitChars => write!(f, "Non-digit characters in port number"),
            FailedToParsePort(port) => write!(f, "Failed to parse port: {}", port),
        }
    }
}

#[derive(Debug, Clone)]
pub enum QueryFragmentDecodeError {
    /// Query didn't start with '?': '{}..'
    QueryDidntStartWithQuestionMark(String)
}

impl fmt::Display for QueryFragmentDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::QueryFragmentDecodeError::*;
        match self {
            QueryDidntStartWithQuestionMark(before_fragment) => write!(f, "Query didn't start with '?': '{}..'", before_fragment),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PathDecodeError {
    /// Invalid character in path.
    InvalidCharacter,
    /// Non-empty path must begin with '/' in presence of authority.
    PathMustStartWithSlash
}

impl fmt::Display for PathDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::PathDecodeError::*;
        match self {
            InvalidCharacter => write!(f, "Invalid character in path"),
            PathMustStartWithSlash => write!(f, "Non-empty path must begin with '/' in presence of authority"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SchemeDecodeError {
    // "url: Scheme must begin with a letter."
    SchemeMustBeginWithLetter,
    // "url: Scheme cannot be empty."
    EmptyScheme,
    // "url: Scheme must be terminated with a colon."
    SchemeNotTerminatedWithColon,
    InvalidCharacter,
}

impl fmt::Display for SchemeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SchemeDecodeError::*;
        match self {
            SchemeMustBeginWithLetter => write!(f, "url: Scheme must begin with a letter"),
            EmptyScheme => write!(f, "url: Scheme cannot be empty"),
            SchemeNotTerminatedWithColon => write!(f, "url: Scheme must be terminated with a colon"),
            InvalidCharacter => write!(f, "url: Scheme contains invalid character(s)")
        }
    }
}

#[derive(Debug, Clone)]
pub enum TlsError {
    /// the server does not support TLS
    TlsUnsupported,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::TlsError::*;
        match self {
            TlsUnsupported => write!(f, "the server does not support TLS"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PostgresIoError {
    // io::Error
}

impl fmt::Display for PostgresIoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::PostgresIoError::*;
        // TODO: build TlsError!!!
        write!(f, "postgres IO error")
    }
}

#[derive(Debug, Clone)]
pub enum ServerError {
    // the server returned an unexpected response
    UnexpectedResponse,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ServerError::*;
        match self {
            UnexpectedResponse => write!(f, "the server returned an unexpected response"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConversionError {
    // Box<error::Error + Sync + Send>
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ConversionError::*;
        // TODO: build TlsError!!!
        write!(f, "conversion error")
    }
}

/// An error communicating with the Postgres server.
#[derive(Debug, Clone)]
pub enum Error {
    ConnectParams(UrlParseError),
    Tls(TlsError),
    Db(DbError),
    Io(PostgresIoError),
    Conversion(ConversionError),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use self::ErrorKind::*;
        match self.0 {
            ConnectParams(ref err) => write!(fmt, "ConnectParams Error: {}", err),
            Tls(ref err) => write!(fmt, "TLS Error: {}", err),
            Db(ref err) => write!(fmt, "DB Error: {}", err),
            Io(ref err) => write!(fmt, "IO Error: {}", err),
            Conversion(ref err) => write!(fmt, "Conversion Error: {}", err),
        }
    }
}

impl Error {
    /// Returns the SQLSTATE error code associated with this error if it is a DB
    /// error.
    pub fn code(&self) -> Option<&SqlState> {
        use self::Error::*;
        match self {
            Db(ref err) => Some(&err.code),
            _ => None
        }
    }
}