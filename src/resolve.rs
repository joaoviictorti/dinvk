use core::ffi::c_void;
use alloc::string::ToString;

use crate::module::Module;
use crate::error::{Error, Result};
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use crate::sys::{get_syscall_address, find_ssn};

/// Resolves a function address from a module.
///
/// # Safety
///
/// `module` must point to the start of a valid PE image that remains loaded
/// while the returned address is used.
pub unsafe fn resolve_fn(module: *mut c_void, function: &str) -> Result<*mut c_void> {
    unsafe { Module::from_ptr(module) }
        .and_then(|m| m.proc(function))
        .ok_or_else(|| Error::FunctionNotFound(function.to_string()))
}

/// Resolves the SSN and syscall instruction address for a native API.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub fn resolve_syscall(function: &str) -> Result<(u16, usize)> {
    let ntdll = Module::find("ntdll.dll")
        .ok_or_else(|| Error::ModuleNotFound("ntdll.dll".into()))?;

    let addr = ntdll
        .proc(function)
        .ok_or_else(|| Error::FunctionNotFound(function.to_string()))?;

    let ssn = unsafe { find_ssn(function, &ntdll) }
        .ok_or_else(|| Error::SsnNotFound(function.to_string()))?;

    let syscall_addr = unsafe { get_syscall_address(addr) }
        .ok_or_else(|| Error::SyscallAddrNotFound(function.to_string()))?;

    Ok((ssn, syscall_addr))
}

/// Resolves the function pointer for a native API (ARM64).
///
/// ARM64 calls the NT function directly since indirect syscalls
/// are not applicable (SSN is encoded in the SVC instruction).
#[cfg(target_arch = "aarch64")]
pub fn resolve_syscall(function: &str) -> Result<*mut c_void> {
    let ntdll = Module::find("ntdll.dll")
        .ok_or_else(|| Error::ModuleNotFound("ntdll.dll".into()))?;

    ntdll
        .proc(function)
        .ok_or_else(|| Error::FunctionNotFound(function.to_string()))
}
