/// Macro to dynamically invoke a function from a specified module.
/// 
/// # Arguments
/// 
/// * `$module` - Module address for the api to be called.
/// * `$function` - A string slice with the name of the function to invoke.
/// * `$ty` - The type of the function to cast to, including its signature.
/// * `$($arg-expr),*` - A variadic list of arguments to pass to the function.
/// 
/// # Example
/// 
/// ```
/// let ntdll = get_ntdll_address();
/// let result = dinvoke!(ntdll, "NtQueryInformationProcess", extern "system" fn(...) -> u32, ...);
/// ``` 
#[macro_export]
macro_rules! dinvoke {
    ($module:expr, $function:expr, $ty:ty, $($arg:expr),*) => {{
        // Get the address of the function in the specified module.
        let address = $crate::GetProcAddress($module, $function, None);
        if address.is_null() {
            None
        } else {
            // Transmute the function pointer to the desired type and invoke it with the provided arguments.
            let func = unsafe { core::mem::transmute::<*mut core::ffi::c_void, $ty>(address) };
            Some(unsafe { func($($arg),*) })
        }
    }};
}

/// Macro to perform a system call (syscall) by dynamically resolving its function name.
///
/// # Arguments
///
/// * `$function_name` - A string slice representing the name of the syscall function.
/// * `$($args:expr),+` - A variadic list of arguments to pass to the syscall.
///
/// # Example
///
/// ```
/// syscall!("NtQueryInformationProcess", ...);
/// ```
#[macro_export]
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
macro_rules! syscall {
    ($function_name:expr, $($y:expr), +) => {{
        // Retrieve the address of ntdll.dll
        let ntdll = $crate::get_ntdll_address();

        // Get the address of the specified function in ntdll.dll
        let addr = $crate::GetProcAddress(ntdll, $function_name, None);

        // Retrieve the SSN for the target function
        let ssn = match $crate::ssn($function_name, ntdll) {
            Some(v) => v,
            None => return Err(-1),
        };

        // Calculate the syscall address
        let syscall_addr = match $crate::get_syscall_address(addr) {
            Some(v) => v,
            None => return Err(-2),
        };

        // Count the number of arguments provided
        let cnt = 0u32 $(+ { let _ = &$y; 1u32 })+;
        
        // Perform the syscall using inline assembly
        Ok::<_, i32>(unsafe { $crate::asm::do_syscall(ssn, syscall_addr, cnt, $($y),+) })
    }};
}

/// Prints output to the Windows console.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        
        let mut console = $crate::ConsoleWriter;
        let _ = writeln!(console, $($arg)*);
    }};
}