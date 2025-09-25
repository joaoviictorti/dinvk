use std::{ffi::c_void, ptr::null_mut};
use dinvk::{
    data::{HANDLE, NTSTATUS},
    NT_SUCCESS, syscall, Dll
};

fn main() -> Result<(), NTSTATUS> {
    // Alternatively, you can use Dll::Vertdll or Dll::Iumdll on x86_64
    Dll::use_dll(Dll::Iumdll);

    // Memory allocation using a syscall
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    let status = syscall!("NtAllocateVirtualMemory", -1isize as HANDLE, &mut addr, 0, &mut size, 0x3000, 0x04)?;
    if !NT_SUCCESS(status) {
        eprintln!("[-] NtAllocateVirtualMemory Failed With Status: {}", status);
        return Err(status);
    }

    println!("{:?}", addr);

    Ok(())
}