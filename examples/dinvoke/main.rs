use dinvk::module::get_module_address;
use dinvk::winapis::GetProcessHeap;
use dinvk::{data::HeapAllocFn, dinvoke};

const HEAP_ZERO_MEMORY: u32 = 8u32;

fn main() {
    let kernel32 = get_module_address("KERNEL32.DLL", None);
    let addr = dinvoke!(
        kernel32,
        "HeapAlloc",
        HeapAllocFn,
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        0x200
    );
    
    println!("[+] Address: {:?}", addr);
}