use obfstr::obfstr as s;
use core::{ffi::c_void, ptr::null_mut};
use crate::{
    data::*, dinvoke, get_ntdll_address, 
    GetModuleHandle, NtCurrentTeb,
};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::breakpoint::{
    is_breakpoint_enabled, 
    set_breakpoint, 
    WINAPI, CURRENT_API
};

/// Wrapper for the `LoadLibraryA` function from `KERNEL32.DLL`.
pub fn LoadLibraryA(module: &str) -> *mut c_void {
    let name = alloc::format!("{module}\0");
    let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
    dinvoke!(
        kernel32,
        s!("LoadLibraryA"),
        LoadLibraryA,
        name.as_ptr().cast()
    )
    .unwrap_or(null_mut())
}

/// Wrapper for the `NtAllocateVirtualMemory` function from `NTDLL.DLL`.
#[allow(unused_mut)]
pub fn NtAllocateVirtualMemory(
    mut process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    mut protect: u32,
) -> NTSTATUS {
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            // Handle debugging breakpoints, if enabled.
            if is_breakpoint_enabled() {
                unsafe {
                    CURRENT_API = Some(WINAPI::NtAllocateVirtualMemory {
                        ProcessHandle: process_handle,
                        Protect: protect,
                    });
                }
                
                // Argument tampering before syscall execution.
                // Modifies the memory protection to PAGE_READONLY.
                protect = 0x02;
        
                // Replaces the process handle with an arbitrary value.
                process_handle = -23isize as HANDLE; 
                
                // Locate and set a breakpoint on the NtAllocateVirtualMemory syscall.
                let addr = crate::GetProcAddress(get_ntdll_address(), s!("NtAllocateVirtualMemory"), None);
                if let Some(syscall_addr) = crate::get_syscall_address(addr) {
                    set_breakpoint(syscall_addr);
                }
            }
        }
    }

    dinvoke!(
        get_ntdll_address(),
        s!("NtAllocateVirtualMemory"),
        NtAllocateVirtualMemory,
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type, 
        protect
    )
    .unwrap_or(STATUS_UNSUCCESSFUL)
}

/// Wrapper for the `NtProtectVirtualMemory` function from `NTDLL.DLL`.
#[allow(unused_mut)]
pub fn NtProtectVirtualMemory(
    mut process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    mut new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            // Handle debugging breakpoints, if enabled.
            if is_breakpoint_enabled() {
                unsafe {
                    CURRENT_API = Some(WINAPI::NtProtectVirtualMemory {
                        ProcessHandle: process_handle,
                        NewProtect: new_protect,
                    });
                }
                
                // Modifies the memory protection to PAGE_READONLY.
                new_protect = 0x02;

                // Replaces the process handle with an arbitrary value.
                process_handle = -23isize as HANDLE; 

                // Locate and set a breakpoint on the NtProtectVirtualMemory syscall.
                let addr = crate::GetProcAddress(get_ntdll_address(), s!("NtProtectVirtualMemory"), None);
                if let Some(syscall_addr) = crate::get_syscall_address(addr) {
                    set_breakpoint(syscall_addr);
                }
            }
        }
    }

    dinvoke!(
        get_ntdll_address(),
        s!("NtProtectVirtualMemory"),
        NtProtectVirtualMemory,
        process_handle,
        base_address,
        region_size,
        new_protect, 
        old_protect
    )
    .unwrap_or(STATUS_UNSUCCESSFUL)
}

/// Wrapper for the `NtCreateThreadEx` function from `NTDLL.DLL`.
#[allow(unused_mut)]
pub fn NtCreateThreadEx(
    mut thread_handle: *mut HANDLE,
    mut desired_access: u32,
    mut object_attributes: *mut OBJECT_ATTRIBUTES,
    mut process_handle: HANDLE,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut PS_ATTRIBUTE_LIST
) -> NTSTATUS {
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            // Handle debugging breakpoints, if enabled.
            if is_breakpoint_enabled() {
                unsafe {
                    CURRENT_API = Some(WINAPI::NtCreateThreadEx {
                        ProcessHandle: process_handle,
                        ThreadHandle: thread_handle,
                        DesiredAccess: desired_access,
                        ObjectAttributes: object_attributes
                    });
                }
                
                // Replacing process handle and thread handle with arbitrary values.
                process_handle = -12isize as HANDLE;
                thread_handle = -43isize as *mut HANDLE;

                // Modifying desired access permissions.
                desired_access = 0x80;

                // Modifying object attributes before the syscall.
                object_attributes = alloc::boxed::Box::leak(alloc::boxed::Box::new(OBJECT_ATTRIBUTES::default()));

                // Locate and set a breakpoint on the NtCreateThreadEx syscall.
                let addr = crate::GetProcAddress(get_ntdll_address(), s!("NtCreateThreadEx"), None);
                if let Some(addr) = crate::get_syscall_address(addr) {
                    set_breakpoint(addr);
                }
            }
        }
    }

    dinvoke!(
        get_ntdll_address(),
        s!("NtCreateThreadEx"),
        NtCreateThreadEx,
        thread_handle,
        desired_access,
        object_attributes,
        process_handle,
        start_routine,
        argument,
        create_flags,
        zero_bits,
        stack_size,
        maximum_stack_size,
        attribute_list
    )
    .unwrap_or(STATUS_UNSUCCESSFUL)
}

/// Wrapper for the `NtWriteVirtualMemory` function from `NTDLL.DLL`.
#[allow(unused_mut)]
pub fn NtWriteVirtualMemory(
    mut process_handle: HANDLE,
    base_address: *mut c_void,
    mut buffer: *mut c_void,
    mut number_of_bytes_to_write: usize,
    number_of_bytes_written: *mut usize,
) -> NTSTATUS {
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            // Handle debugging breakpoints, if enabled.
            if is_breakpoint_enabled() {
                unsafe {
                    CURRENT_API = Some(WINAPI::NtWriteVirtualMemory {
                        ProcessHandle: process_handle,
                        Buffer: buffer,
                        NumberOfBytesToWrite: number_of_bytes_written
                    });
                }

                // Replacing process handle with an arbitrary value.
                process_handle = -90isize as HANDLE;

                // Modifying buffer and size before syscall execution.
                let temp = [0u8; 10];
                buffer = temp.as_ptr().cast_mut().cast();
                number_of_bytes_to_write = temp.len();

                // Locate and set a breakpoint on the NtWriteVirtualMemory syscall.
                let addr = crate::GetProcAddress(get_ntdll_address(), s!("NtWriteVirtualMemory"), None);
                if let Some(addr) = crate::get_syscall_address(addr) {
                    set_breakpoint(addr);
                }
            }
        }
    }
    
    dinvoke!(
        get_ntdll_address(),
        s!("NtWriteVirtualMemory"),
        NtWriteVirtualMemory,
        process_handle,
        base_address,
        buffer,
        number_of_bytes_to_write,
        number_of_bytes_written
    )
    .unwrap_or(STATUS_UNSUCCESSFUL)
}

/// Wrapper for the `HeapAlloc` function from `KERNEL32.DLL`.
pub fn HeapAlloc(
    hheap: HANDLE, 
    dwflags: HEAP_FLAGS, 
    dwbytes: usize
) -> *mut c_void {
    let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
    dinvoke!(
        kernel32,
        s!("HeapAlloc"),
        HeapAlloc,
        hheap,
        dwflags,
        dwbytes
    )
    .unwrap_or(null_mut())
}

/// Wrapper for the `HeapFree` function from `KERNEL32.DLL`.
pub fn HeapFree(
    hheap: HANDLE,
    dwflags: HEAP_FLAGS,
    lpmem: *const c_void,
) -> *mut c_void {
    let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
    dinvoke!(
        kernel32,
        s!("HeapFree"),
        HeapFree,
        hheap,
        dwflags,
        lpmem
    )
    .unwrap_or(null_mut())
}

/// Wrapper for the `HeapCreate` function from `KERNEL32.DLL`.
pub fn HeapCreate(
    floptions: HEAP_FLAGS,
    dwinitialsize: usize,
    dwmaximumsize: usize,
) -> *mut c_void {
    let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
    dinvoke!(
        kernel32,
        s!("HeapCreate"),
        HeapCreate,
        floptions,
        dwinitialsize,
        dwmaximumsize
    )
    .unwrap_or(null_mut())
}

/// Wrapper for the `AddVectoredExceptionHandler` function from `KERNEL32.DLL`.
pub fn AddVectoredExceptionHandler(
    first: u32,
    handler: PVECTORED_EXCEPTION_HANDLER,
) -> *mut c_void {
    let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
    dinvoke!(
        kernel32,
        s!("AddVectoredExceptionHandler"),
        AddVectoredExceptionHandler,
        first,
        handler
    )
    .unwrap_or(null_mut())
}

/// Wrapper for the `RemoveVectoredExceptionHandler` function from `KERNEL32.DLL`.
pub fn RemoveVectoredExceptionHandler(
    handle: *mut c_void,
) -> u32 {
    let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
    dinvoke!(
        kernel32,
        s!("RemoveVectoredExceptionHandler"),
        RemoveVectoredExceptionHandler,
        handle
    )
    .unwrap_or(0)
}

/// Wrapper for the `NtGetThreadContext` function from `NTDLL.DLL`.
pub fn NtGetThreadContext(
    hthread: HANDLE,
    lpcontext: *mut CONTEXT,
) -> i32 {
    dinvoke!(
        get_ntdll_address(),
        s!("NtGetThreadContext"),
        NtGetThreadContext,
        hthread,
        lpcontext
    )
    .unwrap_or(0)
}

/// Wrapper for the `NtSetThreadContext` function from `NTDLL.DLL`.
pub fn NtSetThreadContext(
    hthread: HANDLE,
    lpcontext: *const CONTEXT,
) -> i32 {
    dinvoke!(
        get_ntdll_address(),
        s!("NtSetThreadContext"),
        NtSetThreadContext,
        hthread,
        lpcontext
    )
    .unwrap_or(0)
}

/// Wrapper for the `GetStdHandle` function from `KERNEL32.DLL`.
pub fn GetStdHandle(nStdHandle: u32) -> HANDLE {
    let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
    dinvoke!(
        kernel32,
        s!("GetStdHandle"),
        GetStdHandle,
        nStdHandle
    )
    .unwrap_or(null_mut())
}

/// Returns a pseudo-handle to the current process ((HANDLE)-1).
#[inline(always)]
pub fn NtCurrentProcess() -> HANDLE {
    -1isize as HANDLE
}

/// Returns a pseudo-handle to the current thread ((HANDLE)-2).
#[inline(always)]
pub fn NtCurrentThread() -> HANDLE {
    -2isize as HANDLE
}

/// Returns the default heap handle for the current process from the PEB.
#[inline(always)]
pub fn GetProcessHeap() -> HANDLE {
    let peb = crate::NtCurrentPeb();
    (unsafe { *peb }).ProcessHeap
}

/// Returns the process ID of the calling process from the TEB.
#[inline(always)]
pub fn GetCurrentProcessId() -> u32 {
    let teb = NtCurrentTeb();
    (unsafe { *teb }).Reserved1[8] as u32
}

/// Returns the thread ID of the calling thread from the TEB.
#[inline(always)]
pub fn GetCurrentThreadId() -> u32 {
    let teb = NtCurrentTeb();
    (unsafe { *teb }).Reserved1[9] as u32
}
