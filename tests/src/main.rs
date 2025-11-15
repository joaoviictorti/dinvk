use dinvk::module::{get_module_address, get_proc_address};
use dinvk::winapis::LoadLibraryA;

#[test]
fn test_modules() {
    println!("Module: {:?}", get_module_address("kernel32.dll", None));
    println!("Module: {:?}", get_module_address("kernel32.DLL", None));
    println!("Module: {:?}", get_module_address("kernel32", None));
    println!("Module: {:?}", get_module_address("KERNEL32.dll", None));
    println!("Module: {:?}", get_module_address("KERNEL32", None));
}

#[test]
fn test_function() {
    let module = get_module_address("KERNEL32.dll", None);
    println!("Function: {:x?}", get_proc_address(module, "VirtualAlloc", None));
}

#[test]
fn test_forwarded() {
    let kernel32 = get_module_address("KERNEL32.dll", None);
    println!("SetIoRingCompletionEvent: {:x?}", get_proc_address(kernel32, "SetIoRingCompletionEvent", None));
    println!("SetProtectedPolicy: {:x?}", get_proc_address(kernel32, "SetProtectedPolicy", None));
    println!("SetProcessDefaultCpuSetMasks: {:x?}", get_proc_address(kernel32, "SetProcessDefaultCpuSetMasks", None));
    println!("SetDefaultDllDirectories: {:x?}", get_proc_address(kernel32, "SetDefaultDllDirectories", None));
    println!("SetProcessDefaultCpuSets: {:x?}", get_proc_address(kernel32, "SetProcessDefaultCpuSets", None));
    println!("InitializeProcThreadAttributeList : {:x?}", get_proc_address(kernel32, "InitializeProcThreadAttributeList", None));

    let advapi32 = LoadLibraryA("advapi32.dll");
    println!("SystemFunction028: {:x?}", get_proc_address(advapi32, "SystemFunction028", None));
    println!("PerfIncrementULongCounterValue: {:x?}", get_proc_address(advapi32, "PerfIncrementULongCounterValue", None));
    println!("PerfSetCounterRefValue: {:x?}", get_proc_address(advapi32, "PerfSetCounterRefValue", None));
    println!("I_QueryTagInformation: {:x?}", get_proc_address(advapi32, "I_QueryTagInformation", None));
    println!("TraceQueryInformation: {:x?}", get_proc_address(advapi32, "TraceQueryInformation", None));
    println!("TraceMessage: {:x?}", get_proc_address(advapi32, "TraceMessage", None));
}