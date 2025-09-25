#![allow(unused)]

use dinvk::{hash::jenkins, GetModuleHandle, GetProcAddress};

fn main() {
    // Retrieving module address via string and hash
    let kernel32 = GetModuleHandle("KERNEL32.DLL", None);
    let kernel32 = GetModuleHandle(3425263715u32, Some(jenkins));

    // Retrieving exported API address via string, ordinal and hash
    let addr = GetProcAddress(kernel32, "LoadLibraryA", None);
    let addr = GetProcAddress(kernel32, 3962820501u32, Some(jenkins));
    let addr = GetProcAddress(kernel32, 997, None);

    println!("[+] LoadLibraryA: {:?}", addr);
    println!("[+] KERNEL32: {:?}", kernel32);
}