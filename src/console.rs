//! Simple wrapper utilities for writing formatted text directly to the
//! Windows console using `WriteConsoleA`.

use alloc::vec::Vec;
use core::{fmt::{self, Write}, ptr};
use super::data::WriteConsoleAFn;
use super::winapis::GetStdHandle;
use super::module::get_module_address;
use super::dinvoke;

/// `ConsoleWriter` is a custom implementation of `core::fmt::Write`
/// that writes formatted strings directly to the Windows console.
pub struct ConsoleWriter;

impl Write for ConsoleWriter {
    /// Writes a string to the Windows console using `WriteConsoleA`.
    ///
    /// # Argument
    /// 
    /// * `s` - The string to be written to the console.
    ///
    /// # Returns
    /// 
    /// Indicates whether the write operation was successful.
    fn write_str(&mut self, s: &str) -> fmt::Result {       
        // Convert the string into a byte buffer
        let buffer = Vec::from(s.as_bytes());
        
        // Retrieve the handle for `KERNEL32.DLL`
        let kernel32 = get_module_address(obfstr::obfstr!("KERNEL32.DLL"), None);

        // Dynamically invoke `WriteConsoleA`
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