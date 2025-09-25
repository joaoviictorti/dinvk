/// Macro to dynamically invoke a function from a specified module.
/// 
/// # Arguments
/// 
/// * `$module` - Module address for the api to be called (e.g., `"ntdll.dll"`).
/// * `$function` - A string slice with the name of the function to invoke (e.g., `"NtQueryInformationProcess"`).
/// * `$ty` - The type of the function to cast to, including its signature.
/// * `$($arg-expr),*` - A variadic list of arguments to pass to the function.
/// 
/// # Example
/// 
/// ```rust,ignore
/// let ntdll = get_ntdll_address();
/// let result = dinvoke!(ntdll, "NtQueryInformationProcess", extern "system" fn(...) -> u32, arg1, arg2);
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
/// * `$function_name` - A string slice representing the name of the syscall function (e.g., `"NtQueryInformationProcess"`).
/// * `$($args:expr),+` - A variadic list of arguments to pass to the syscall.
///
/// # Example
///
/// ```rust,ignore
/// syscall!("NtQueryInformationProcess", process_handle, process_info_class, process_info, process_info_length, return_length);
/// ```
#[macro_export]
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
macro_rules! syscall {
    ($function_name:expr, $($y:expr), +) => {{
        use $crate::*;

        // Retrieve the address of ntdll.dll
        let ntdll = get_ntdll_address();

        // Get the address of the specified function in ntdll.dll
        let addr = GetProcAddress(ntdll, $function_name, None);

        // Retrieve the SSN for the target function
        let ssn = match ssn($function_name, ntdll) {
            Some(v) => v,
            None => return Err(-1),
        };

        // Calculate the syscall address
        let syscall_addr = match get_syscall_address(addr) {
            Some(v) => v,
            None => return Err(-2),
        };

        // Count the number of arguments provided
        let cnt = 0u32 $(+ { let _ = &$y; 1u32 })+;
        
        // Perform the syscall using inline assembly
        Ok::<_, i32>(unsafe { asm::do_syscall(ssn, syscall_addr, cnt, $($y),+) })
    }};
}

/// Declares an external function from a dynamically linked library.
///
/// # Arguments
///
/// * `$library` - A string literal representing the name of the shared library (e.g., `"ntdll.dll"`).
/// * `$abi` - A string literal specifying the calling convention (e.g., `"system"` for Windows API calls).
/// * `$link_name` (optional) - A string literal specifying the actual name of the function in the library.
/// * `$function` - The function signature to declare.
///
/// # Example
///
/// ```rust,ignore
/// link!("ntdll.dll" "system" fn NtQueryInformationProcess(
///     process_handle: HANDLE,
///     process_info_class: u32,
///     process_info: *mut u8,
///     process_info_length: u32,
///     return_length: *mut u32
/// ) -> u32);
/// ```
#[macro_export]
macro_rules! link {
    ($library:literal $abi:literal $($link_name:literal)? fn $($function:tt)*) => (
        #[link(name = $library)]
        unsafe extern $abi {
            $(#[link_name=$link_name])?
            pub(crate) fn $($function)*;
        }
    )
}

/// Prints output to the Windows console using `ConsoleWriter`.
///
/// # Example
/// 
/// ```rust,ignore
/// println!("Hello, world!");
/// println!("Value: {}", 42);
/// ```
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        
        let mut console = $crate::ConsoleWriter;
        let _ = writeln!(console, $($arg)*);
    }};
}
