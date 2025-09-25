use dinvk::{GetModuleHandle, GetProcAddress, LoadLibraryA};

#[test]
fn test_modules() {
    println!("Module: {:?}", GetModuleHandle("kernel32.dll", None));
    println!("Module: {:?}", GetModuleHandle("kernel32.DLL", None));
    println!("Module: {:?}", GetModuleHandle("kernel32", None));
    println!("Module: {:?}", GetModuleHandle("KERNEL32.dll", None));
    println!("Module: {:?}", GetModuleHandle("KERNEL32", None));
}

#[test]
fn test_function() {
    let module = GetModuleHandle("KERNEL32.dll", None);
    println!("Function: {:x?}", GetProcAddress(module, "VirtualAlloc", None));
}

#[test]
fn test_forwarded() {
    let kernel32 = GetModuleHandle("KERNEL32.dll", None);
    println!("SetIoRingCompletionEvent: {:x?}", GetProcAddress(kernel32, "SetIoRingCompletionEvent", None));
    println!("SetProtectedPolicy: {:x?}", GetProcAddress(kernel32, "SetProtectedPolicy", None));
    println!("SetProcessDefaultCpuSetMasks: {:x?}", GetProcAddress(kernel32, "SetProcessDefaultCpuSetMasks", None));
    println!("SetDefaultDllDirectories: {:x?}", GetProcAddress(kernel32, "SetDefaultDllDirectories", None));
    println!("SetProcessDefaultCpuSets: {:x?}", GetProcAddress(kernel32, "SetProcessDefaultCpuSets", None));
    println!("InitializeProcThreadAttributeList : {:x?}", GetProcAddress(kernel32, "InitializeProcThreadAttributeList", None));

    let advapi32 = LoadLibraryA("advapi32.dll");
    println!("SystemFunction028: {:x?}", GetProcAddress(advapi32, "SystemFunction028", None));
    println!("PerfIncrementULongCounterValue: {:x?}", GetProcAddress(advapi32, "PerfIncrementULongCounterValue", None));
    println!("PerfSetCounterRefValue: {:x?}", GetProcAddress(advapi32, "PerfSetCounterRefValue", None));
    println!("I_QueryTagInformation: {:x?}", GetProcAddress(advapi32, "I_QueryTagInformation", None));
    println!("TraceQueryInformation: {:x?}", GetProcAddress(advapi32, "TraceQueryInformation", None));
    println!("TraceMessage: {:x?}", GetProcAddress(advapi32, "TraceMessage", None));
}