use dinvk::breakpoint::{
    set_use_breakpoint, 
    veh_handler
};
use dinvk::winapis::{
    NT_SUCCESS, NtCurrentProcess,
    AddVectoredExceptionHandler, 
    NtAllocateVirtualMemory, 
    RemoveVectoredExceptionHandler,
};

fn main() {
    // Enabling breakpoint hardware
    set_use_breakpoint(true);
    let handle = AddVectoredExceptionHandler(1, Some(veh_handler));

    // Allocating memory and using breakpoint hardware
    let mut addr = std::ptr::null_mut();
    let mut size = 1 << 12;
    let status = NtAllocateVirtualMemory(NtCurrentProcess(), &mut addr, 0, &mut size, 0x3000, 0x04);
    if !NT_SUCCESS(status) {
        eprintln!("[-] NtAllocateVirtualMemory Failed With Status: {}", status);
        return;
    }

    // Disabling breakpoint hardware
    set_use_breakpoint(false);
    RemoveVectoredExceptionHandler(handle);
}