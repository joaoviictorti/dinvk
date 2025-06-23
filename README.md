# dinvk 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![crate](https://img.shields.io/crates/v/dinvk.svg)
![docs](https://docs.rs/dinvk/badge.svg)
![Forks](https://img.shields.io/github/forks/joaoviictorti/dinvk)
![Stars](https://img.shields.io/github/stars/joaoviictorti/dinvk)
![License](https://img.shields.io/github/license/joaoviictorti/dinvk)

Dynamically invoke arbitrary code with Rust tricks, `#[no_std]` support, and compatibility for `x64`, `x86`, `ARM64` and `WoW64` (DInvoke)

This tool is a Rust version of [DInvoke](https://github.com/TheWover/DInvoke), originally written in C#, with additional features added.

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
    - [Dynamically Invoke Arbitrary Code](#dynamically-invoke-arbitrary-code)
    - [Retrieving Module Addresses and Exported APIs](#retrieving-module-addresses-and-exported-apis)
    - [Indirect syscall](#indirect-syscall)
    - [Redirecting Syscall Invocation to Different DLLs](#redirecting-syscall-invocation-to-different-dlls)
    - [Different Hash Methods for API Hashing](#different-hash-methods-for-api-hashing)
    - [Library Proxy Loading](#library-proxy-loading)
    - [Tampered Syscalls Via Hardware BreakPoints](#tampered-syscalls-via-hardware-breakpoints)
    - [Support for #\[no\_std\] Environments](#support-for-no_std-environments)
- [Contributing to dinvk](#contributing-to-dinvk)
- [References](#references)
- [License](#license)

## Features

- ✅ Dynamically invoke arbitrary code (*x64*, *x86*, *Wow64*, *ARM64*)
- ✅ Indirect Syscall (*x64*, *x86*, *Wow64*)
- ✅ Redirecting Syscall Invocation to Different DLLs
- ✅ Tampered Syscalls Via Hardware BreakPoints (*x64*, *x86*, *Wow64*)
- ✅ PE headers parsing
- ✅ Library Proxy Loading
- ✅ Support `#[no_std]` projects
- ✅ Retrieve exported API addresses via string, ordinal, and hashing
- ✅ Retrieve module addresses via string and hashing
- ✅ Supports multiple 32-bit hash algorithms for API Hashing using `GetModuleHandle` and `GetProcAddress`: Jenkins3, Jenkins One-at-a-Time, DJB2, Murmur3, FNV-1a, SDBM, Lose, PJW, JS, and AP

## Installation

Add `dinvk` to your project by updating your `Cargo.toml`:
```bash
cargo add dinvk
```

## Usage

`dinvk` provides several features for invoking code dynamically, performing indirect syscalls and manipulating exported modules and APIs. Below are detailed examples of how to use each feature.

### Dynamically Invoke Arbitrary Code

Allows resolving and calling a function dynamically at runtime, avoiding static linking.

* This example demonstrates the dynamic invocation of arbitrary code using `dinvoke!`, resolving function addresses at runtime without direct linking. In this case, `HeapAlloc` is dynamically called to allocate memory.
* Using this macro is beneficial if you want to avoid having APIs directly listed in the `Import Address Table (IAT)` of your PE file.

```rs
#![allow(unused)]

use dinvk::{
    data::HeapAlloc, 
    dinvoke, GetModuleHandle
    GetProcessHeap
};

const HEAP_ZERO_MEMORY: u32 = 8u32;

fn main() {
    let kernel32 = GetModuleHandle("KERNEL32.DLL", None);
    let addr = dinvoke!(
        kernel32,
        "HeapAlloc",
        HeapAlloc,
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        0x200
    );
    
    println!("[+] Address: {:?}", addr);
}
```

### Retrieving Module Addresses and Exported APIs

Retrieves the base address of a module and resolves exported APIs using different methods: by string, ordinal, or hash.

* In this example, the address of the `KERNEL32` module is retrieved using both a string and a hash (Jenkins hash).
* Then, the `LoadLibrary` function address is resolved using the same methods, with an additional example using an ordinal number.

```rs
use dinvk::{hash::jenkins, GetModuleHandle, GetProcAddress};

fn main() {
    // Retrieving module address via string and hash
    let kernel32 = GetModuleHandle("KERNEL32.DLL", None);
    let kernel32 = GetModuleHandle(3425263715u32, Some(jenkins));

    // Retrieving exported API address via string, ordinal and hash
    let addr = GetProcAddress(kernel32, "LoadLibraryA", None);
    let addr = GetProcAddress(kernel32, 3962820501u32, Some(jenkins));
    let addr = GetProcAddress(kernel32, 997, None);
}
```

### Indirect syscall

Executes syscalls indirectly, bypassing user-mode API hooks and security monitoring tools.

* Currently supporting x64, x86 and WoW64.
* It uses techniques such as Hells Gate, Halos Gate, and Tartarus Gate to dynamically locate the System Service Number (SSN) and invoke the syscall indirectly.

```rs
use std::{ffi::c_void, ptr::null_mut};
use dinvk::{
    data::{HANDLE, NTSTATUS, NT_SUCCESS}, 
    syscall, NtCurrentProcess
};

fn main() -> Result<(), NTSTATUS> {
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;

    let status = syscall!(
        "NtAllocateVirtualMemory",
        NtCurrentProcess(),
        &mut addr,
        0,
        &mut size,
        0x3000,
        0x40
    ).ok_or(-1)?;

    if !NT_SUCCESS(status) {
        eprintln!("[-] NtAllocateVirtualMemory Failed With Status: {:?}", status);
        return Err(status)
    }

    Ok(())
}
```

## Redirecting Syscall Invocation to Different DLLs

By default, syscalls in Windows are invoked via `ntdll.dll`. However, on x86_64 architectures, other DLLs such as `win32u.dll`, `vertdll.dll` and `iumdll.dll` also contain syscall instructions, allowing you to avoid indirect calls via `ntdll.dll`. On x86, only `win32u.dll` has these instructions.

The code below demonstrates how to invoke `NtAllocateVirtualMemory` using different DLLs to execute the syscall:

```rs
use std::{ffi::c_void, ptr::null_mut};
use dinvk::{
    data::{HANDLE, NTSTATUS, NT_SUCCESS}, 
    syscall, Dll, NtCurrentProcess
};

fn main() -> Result<(), NTSTATUS> {
    // Alternatively, you can use Dll::Vertdll or Dll::Iumdll on x86_64
    Dll::use_dll(Dll::Win32u);

    // Memory allocation using a syscall
    let mut addr = null_mut::<c_void>();
    let mut size = (1 << 12) as usize;
    let status = syscall!("NtAllocateVirtualMemory", NtCurrentProcess(), &mut addr, 0, &mut size, 0x3000, 0x04).ok_or(-1)?;
    if !NT_SUCCESS(status) {
        eprintln!("[-] NtAllocateVirtualMemory Failed With Status: {}", status);
        return Err(status);
    }

    Ok(())
}
```

This method can be useful to avoid indirect invocations in `ntdll.dll`, diversifying the points of origin of the syscalls in the process.

### Different Hash Methods for API Hashing

Supports various hashing algorithms for API resolution, improving stealth and flexibility.

* Currently, the library only supports 32-bit hashes for API lookup.

```rs
use dinvk::hash::*;

fn main() {
    println!("{}", jenkins("dinvk"));
    println!("{}", jenkins3("dinvk"));
    println!("{}", ap("dinvk"));
    println!("{}", js("dinvk"));
    println!("{}", murmur3("dinvk"));
    println!("{}", fnv1a("dinvk"));
    println!("{}", djb2("dinvk"));
    println!("{}", crc32ba("dinvk"));
    println!("{}", loselose("dinvk"));
    println!("{}", pjw("dinvk"));
    println!("{}", sdbm("dinvk"));
}
```

### Library Proxy Loading

Allows DLLs to be loaded indirectly using an API call as an intermediary to clean the call stack and act as a proxy.

```rs
use dinvk::LdrProxy;

fn main() {
    // RtlQueueWorkItem
    LdrProxy::new("xpsservices.dll").work();

    // RtlCreateTimer
    LdrProxy::new("xpsservices.dll").timer();

    // RtlRegisterWait
    LdrProxy::new("xpsservices.dll").register_wait();
}
```

### Tampered Syscalls Via Hardware BreakPoints

Utilizes hardware breakpoints to manipulate syscall parameters before execution, bypassing security hooks.

* The library includes several API wrappers that leverage DInvoke and support hardware breakpoints to spoof syscall arguments dynamically.
* These breakpoints modify syscall parameters after security monitoring tools inspect them but before the syscall executes, effectively bypassing detection.
* Currently supporting x64, x86 and WoW64.
* You can find the full list of wrapped functions in the [wrappers](/src/wrappers.rs) module.

```rs
use dinvk::{
    breakpoint::{set_use_breakpoint, veh_handler},
    data::{HANDLE, NT_SUCCESS},
    AddVectoredExceptionHandler, 
    NtAllocateVirtualMemory, NtCurrentProcess,
    RemoveVectoredExceptionHandler,
};

fn main() {
    // Enabling breakpoint hardware
    set_use_breakpoint(true);
    let handle = AddVectoredExceptionHandler(0, Some(veh_handler));

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
```

### Support for #[no_std] Environments

Enables `#[no_std]` compatibility for environments without the Rust standard library.

* To enable `#[no_std]` support, define the required features in your `Cargo.toml`.

```toml
[dependencies]
dinvk = { version = "<version>", features = ["alloc", "dinvk_panic"] }
```

* Running in `#[no_std]` Mode.

```rs
#![no_std]
#![no_main]

use dinvk::allocator::WinHeap;
use dinvk::{
    get_ntdll_address, println, 
    GetProcAddress
};

#[unsafe(no_mangle)]
fn main() -> u8 {
    let addr = GetProcAddress(get_ntdll_address(), "NtOpenProcess", None);
    println!("[+] NtOpenProcess: {:?}", addr);

    0
}

#[global_allocator]
static ALLOCATOR: WinHeap = WinHeap;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    dinvk::panic::dinvk_handler(info)
}
```

## Contributing to dinvk

To contribute to **dinvk**, follow these steps:

1. Fork this repository.
2. Create a branch: `git checkout -b <branch_name>`.
3. Make your changes and commit them: `git commit -m '<commit_message>'`.
4. Push your changes to your branch: `git push origin <branch_name>`.
5. Create a pull request.

Alternatively, consult the [GitHub documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests) on how to create a pull request.

## References

- [DInvoke](https://github.com/TheWover/DInvoke)

## License

This project is licensed under the MIT License. See the [LICENSE](/LICENSE) file for details.