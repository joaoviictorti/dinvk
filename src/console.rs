//! Simple wrapper utilities for writing formatted text directly to the
//! Windows console.

use alloc::vec::Vec;
use core::{fmt::{self, Write}, ptr};

use crate::types::WriteConsoleAFn;
use crate::winapis::GetStdHandle;
use crate::module::get_module_address;
use crate::dinvoke;

/// `ConsoleWriter` is a custom implementation of `core::fmt::Write`.
pub struct ConsoleWriter;

impl Write for ConsoleWriter {
    /// Writes a string to the Windows console using `WriteConsoleA`.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let buffer = Vec::from(s.as_bytes());
        let kernel32 = get_module_address(obfstr::obfstr!("KERNEL32.DLL"), None);
        dinvoke!(
            kernel32,
            obfstr::obfstr!("WriteConsoleA"),
            WriteConsoleAFn,
            GetStdHandle((-11i32) as u32),
            buffer.as_ptr(),
            buffer.len() as u32,
            ptr::null_mut(),
            ptr::null_mut()
        );

        Ok(())
    }
}