// Copyright (c) 2025 joaoviictorti
// Licensed under the MIT License. See LICENSE file in the project root for details.

//! Custom panic handler support.

use core::{fmt::Write, panic::PanicInfo};
use obfstr::obfstr as s;
use super::ConsoleWriter;

/// Handles panics by printing detailed error information to the console.
pub fn panic_handler(info: &PanicInfo) -> ! {
    let mut console = ConsoleWriter;
    let _ = writeln!(console, "{}", s!("Thread Panicked!"));

    if let Some(location) = info.location() {
        let _ = writeln!(
            console,
            "   --> {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }

    let _ = writeln!(console, "{} {}", s!("   panic message:"), info.message());
    loop {}
}
