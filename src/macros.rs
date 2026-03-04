/// Dynamically invokes a function from a loaded module.
///
/// Resolves the function address at runtime and calls it with the provided
/// arguments. Returns `None` if the function cannot be resolved.
///
/// # Examples
///
/// ```no_run
/// use core::ffi::c_void;
/// use dinvk::{dinvoke, Module};
///
/// type LoadLibraryAFn = extern "system" fn(*const u8) -> *mut c_void;
///
/// // With Module
/// let kernel32 = Module::find("kernel32.dll").unwrap();
/// let handle = dinvoke!(kernel32, "LoadLibraryA", LoadLibraryAFn, b"ntdll.dll\0".as_ptr());
///
/// // With raw base address
/// let base = kernel32.base();
/// let handle = dinvoke!(base, "LoadLibraryA", LoadLibraryAFn, b"ntdll.dll\0".as_ptr());
/// ```
#[macro_export]
macro_rules! dinvoke {
    ($module:expr, $function:expr, $ty:ty, $($arg:expr),*) => {{
        let base: *mut core::ffi::c_void = $module.into();
        $crate::resolve::resolve_fn(base, $function)
            .map(|addr| {
                let func = unsafe { core::mem::transmute::<*mut core::ffi::c_void, $ty>(addr) };
                unsafe { func($($arg),*) }
            })
    }};
}

/// Executes a syscall by dynamically resolving the SSN and syscall address.
///
/// Resolves the System Service Number (SSN) and the `syscall` instruction
/// address at runtime, then executes the syscall directly. Returns `None`
/// if resolution fails.
///
/// # Examples
///
/// ```no_run
/// use core::{ptr::null_mut, ffi::c_void};
/// use dinvk::syscall;
///
/// let mut addr: *mut c_void = null_mut();
/// let mut size: usize = 0x1000;
///
/// let status = syscall!(
///     "NtAllocateVirtualMemory",
///     -1isize as *mut c_void,  // current process
///     &mut addr,
///     0usize,
///     &mut size,
///     0x3000u32,               // MEM_COMMIT | MEM_RESERVE
///     0x04u32                  // PAGE_READWRITE
/// );
///
/// match status {
///     Ok(0) => println!("allocated at {:?}", addr),
///     Ok(s) => println!("failed: {:#x}", s),
///     Err(e) => println!("syscall resolution failed: {}", e),
/// }
/// ```
#[macro_export]
macro_rules! syscall {
    ($function_name:expr, $($y:expr),+) => {{
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] 
        {
            $crate::resolve::resolve_syscall($function_name)
                .map(|(ssn, syscall_addr)| {
                    let argc = 0u32 $(+ { let _ = &$y; 1u32 })+;
                    unsafe { $crate::sys::asm::do_syscall(ssn, syscall_addr, argc, $($y),+) }
                })
        }

        #[cfg(target_arch = "aarch64")]
        {
            $crate::resolve::resolve_syscall($function_name)
                .map(|fn_ptr| {
                    let argc = 0u32 $(+ { let _ = &$y; 1u32 })+;
                    unsafe { $crate::sys::asm::do_syscall(fn_ptr, argc, $($y),+) }
                })
        }
    }};
}

/// Generates a wrapper function that dynamically links to a native API.
///
/// Creates a function that resolves and calls the target symbol at runtime.
/// The function type is inferred from the signature.
///
/// # Examples
///
/// ```ignore
/// use dinvk::{link, Module};
///
/// type HANDLE = *mut core::ffi::c_void;
/// type NTSTATUS = i32;
///
/// // With Module
/// let ntdll = Module::find("ntdll.dll").unwrap();
/// link!(ntdll, "NtClose", fn NtClose(handle: HANDLE) -> NTSTATUS);
///
/// // With expression that returns base
/// link!(Module::find("kernel32.dll").unwrap(), "VirtualAlloc",
///     fn VirtualAlloc(addr: *mut c_void, size: usize, typ: u32, prot: u32) -> *mut c_void);
/// ```
#[macro_export]
macro_rules! link {
    ($module:expr, $sym:expr, $vis:vis fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty) => {
        #[doc = concat!("Wrapper for `", stringify!($name), "`.")]
        ///
        /// # Safety
        ///
        /// This function is unsafe because it calls a dynamically resolved function pointer.
        /// The caller must ensure that the arguments are valid for the underlying Windows API.
        $vis unsafe fn $name($($arg: $ty),*) -> $crate::error::Result<$ret> {
            type FnType = unsafe extern "system" fn($($ty),*) -> $ret;
            $crate::dinvoke!($module, $sym, FnType, $($arg),*)
        }
    };

    ($module:expr, $sym:expr, $vis:vis fn $name:ident($($arg:ident: $ty:ty),* $(,)?)) => {
        #[doc = concat!("Wrapper for `", stringify!($name), "`.")]
        ///
        /// # Safety
        ///
        /// This function is unsafe because it calls a dynamically resolved function pointer.
        /// The caller must ensure that the arguments are valid for the underlying Windows API.
        $vis unsafe fn $name($($arg: $ty),*) -> $crate::error::Result<()> {
            type FnType = unsafe extern "system" fn($($ty),*);
            $crate::dinvoke!($module, $sym, FnType, $($arg),*)?;
            Ok(())
        }
    };
}