/// Handles panics by printing detailed error information to the console.
///
/// # Example
///
/// ```rust,ignore
/// use core::panic::PanicInfo;
///
/// #[cfg(not(test))]
/// #[panic_handler]
/// fn panic_handler(info: &PanicInfo) -> ! {
///     dinvk::panic::dinvk_handler(info)
/// }
///
/// fn main() {
///     panic!("Something went wrong!"); // Will trigger `dinvk_handler`
/// }
/// ```
///
/// # Limitations
/// 
/// - Does not unwind the stack (designed for `panic = "abort"` configurations).
pub fn dinvk_handler(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    use crate::ConsoleWriter;
    use obfstr::obfstr as s;

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
