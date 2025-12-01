/// Macro to dynamically invoke a function from a specified module.
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
        // Get the address of the function in the specified module
        let address = $crate::module::get_proc_address($module, $function, None);
        if address.is_null() {
            None
        } else {
            // Transmute the function pointer to the desired type and invoke it with the provided arguments
            let func = unsafe { core::mem::transmute::<*mut core::ffi::c_void, $ty>(address) };
            Some(unsafe { func($($arg),*) })
        }
    }};
}

/// Macro to perform a system call (syscall) by dynamically resolving its function name.
///
/// # Example
///
/// ```
/// let mut addr = null_mut::<c_void>();
/// let mut size = (1 << 12) as usize;
/// let status = syscall!("NtAllocateVirtualMemory", -1isize as HANDLE, &mut addr, 0, &mut size, 0x3000, 0x04)
///    .ok_or("syscall resolution failed")?;
///
/// if !NT_SUCCESS(status) {
///     eprintln!("[-] NtAllocateVirtualMemory Failed With Status: {}", status);
/// }
/// ```
#[macro_export]
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
macro_rules! syscall {
    ($function_name:expr, $($y:expr), +) => {{
        // Retrieve the address of ntdll.dll
        let ntdll = $crate::module::get_ntdll_address();

        // Get the address of the specified function in ntdll.dll
        let addr = $crate::module::get_proc_address(ntdll, $function_name, None);
        if addr.is_null() {
            None
        } else {
            // Retrieve the SSN for the target function
            match $crate::ssn($function_name, ntdll) {
                None => None,
                Some(ssn) => {
                    // Calculate the syscall address
                    match $crate::get_syscall_address(addr) {
                        None => None,
                        Some(syscall_addr) => {
                            // Count number of args
                            let cnt = 0u32 $(+ { let _ = &$y; 1u32 })+;
                            
                            // Execute syscall
                            Some(unsafe { $crate::asm::do_syscall(ssn, syscall_addr, cnt, $($y),+) })
                        }
                    }
                }
            }
        }
    }};
}

/// Prints output to the Windows console.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        
        let mut console = $crate::console::ConsoleWriter;
        let _ = writeln!(console, $($arg)*);
    }};
}