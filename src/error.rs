//! Errors returned by this crate.

use alloc::string::String;

/// Result alias for dynamic resolution operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Dynamic resolution error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The requested function was not found in the module's export table.
    #[error("function not found: {0}")]
    FunctionNotFound(String),
    /// The requested module was not found in the PEB loader list.
    #[error("module not found: {0}")]
    ModuleNotFound(String),
    /// The System Service Number (SSN) could not be extracted from the syscall stub.
    #[error("ssn not found for: {0}")]
    SsnNotFound(String),
    /// The syscall instruction address could not be located in the stub.
    #[error("syscall instruction not found in: {0}")]
    SyscallAddrNotFound(String),
}