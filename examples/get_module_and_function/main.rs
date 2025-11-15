#![allow(unused)]

use dinvk::module::{get_module_address, get_proc_address};
use dinvk::hash::jenkins;

fn main() {
    // Retrieving module address via string and hash
    let kernel32 = get_module_address("KERNEL32.DLL", None);
    let kernel32 = get_module_address(3425263715u32, Some(jenkins));

    // Retrieving exported API address via string, ordinal and hash
    let addr = get_proc_address(kernel32, "LoadLibraryA", None);
    let addr = get_proc_address(kernel32, 3962820501u32, Some(jenkins));
    let addr = get_proc_address(kernel32, 997, None);

    println!("[+] LoadLibraryA: {:?}", addr);
    println!("[+] KERNEL32: {:?}", kernel32);
}