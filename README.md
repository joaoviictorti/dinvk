# dinvk

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]

A Rust library for dynamic code invocation on Windows. It resolves modules and exports at runtime by walking the PEB, eliminating the need for static linking or direct Win32 API calls.

## Getting Started

Add it as a library to your project:

```bash
cargo add dinvk
```

## Example

### Dynamic Invocation

Invoke functions at runtime without static imports using the `dinvoke!` macro:

```rust
use std::ffi::c_void;
use dinvk::{dinvoke, Module};

type LoadLibraryAFn = extern "system" fn(*const u8) -> *mut c_void;

let kernel32 = Module::find("kernel32.dll").unwrap();
let handle = dinvoke!(
    kernel32,
    "LoadLibraryA",
    LoadLibraryAFn,
    b"ntdll.dll\0".as_ptr()
);
```

### Indirect Syscalls

Execute syscalls indirectly with SSN resolution via Hell's Gate, Halo's Gate, and Tartarus Gate techniques:

```rust
use std::ffi::c_void; 
use std::ptr::null_mut;
use dinvk::syscall;

let mut addr = null_mut::<c_void>();
let mut size = 4096usize;
let status = syscall!(
    "NtAllocateVirtualMemory",
    -1isize as *mut c_void,
    &mut addr,
    0,
    &mut size,
    0x3000,
    0x04
);
```

For more information, including a more detailed overview of dinvk, [visit the documentation](https://docs.rs/dinvk).

## License

dinvk is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/joaoviictorti/dinvk/tree/main/LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/joaoviictorti/dinvk/tree/main/LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in dinvk
by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any

additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/dinvk?logo=rust
[crate-link]: https://crates.io/crates/dinvk
[docs-image]: https://docs.rs/dinvk/badge.svg
[docs-link]: https://docs.rs/dinvk/
[build-image]: https://github.com/joaoviictorti/dinvk/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/joaoviictorti/dinvk/actions/workflows/ci.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
