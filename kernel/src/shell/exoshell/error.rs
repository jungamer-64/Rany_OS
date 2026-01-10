// ============================================================================
// src/shell/exoshell/error.rs - ExoShell Error Handling
// ============================================================================

use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt::{self, Display};
use crate::shell::exoshell::parser::error::ParseError;

/// Shell core errors
#[derive(Debug, Clone)]
pub enum ShellError {
    /// Errors occurring during parsing
    Parse(ParseError),
    /// Function Argument Errors
    ArgumentError(String),
    /// Command not found
    CommandNotFound(String),
    /// Variable not found
    VariableNotFound(String),
    /// Runtime evaluation error
    Runtime(String),
    /// Permission denied
    AccessDenied(String),
    /// IO Error
    Io(String),
    /// Generic/Custom error
    Custom(Cow<'static, str>),
}

impl Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellError::Parse(e) => write!(f, "Parse Error: {}", e),
            ShellError::ArgumentError(msg) => write!(f, "Argument Error: {}", msg),
            ShellError::CommandNotFound(cmd) => write!(f, "Command not found: '{}'", cmd),
            ShellError::VariableNotFound(var) => write!(f, "Variable not defined: '{}'", var),
            ShellError::Runtime(msg) => write!(f, "Runtime Error: {}", msg),
            ShellError::AccessDenied(msg) => write!(f, "Access Denied: {}", msg),
            ShellError::Io(msg) => write!(f, "I/O Error: {}", msg),
            ShellError::Custom(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl From<ParseError> for ShellError {
    fn from(err: ParseError) -> Self {
        ShellError::Parse(err)
    }
}

pub type ExoResult<T> = Result<T, ShellError>;
