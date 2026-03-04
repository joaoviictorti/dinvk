//! # dinvk
//!
//! A Rust library for dynamic code invocation on Windows. It resolves modules and exports at runtime 
//! by walking the PEB, eliminating the need for static linking or direct Win32 API calls. 
//! Built with `#[no_std]` support and compatible with `x64`, `x86`, `ARM64`, and `WoW64` architectures.
//!
//! ## Usage
//!
//! ### Module and Export Resolution
//!
//! Locate loaded modules and resolve their exports by name, hash, or ordinal:
//!
//! ```no_run
//! use dinvk::Module;
//!
//! // By name
//! let kernel32 = Module::find("kernel32.dll").unwrap();
//! let load_library = kernel32.proc("LoadLibraryA").unwrap();
//!
//! let ntdll = Module::find("ntdll.dll").unwrap();
//! let nt_alloc = ntdll.proc("NtAllocateVirtualMemory").unwrap();
//!
//! // By hash
//! use dinvk::hash::jenkins;
//! let func = Module::find_by_hash(0xDEADBEEF, jenkins)
//!     .and_then(|m| m.proc_by_hash(0xCAFEBABE, jenkins));
//! ```
//!
//! ### Dynamic Invocation
//!
//! Invoke functions at runtime without static imports using the `dinvoke!` macro:
//!
//! ```no_run
//! use std::ffi::c_void;
//! use dinvk::{dinvoke, Module};
//!
//! type LoadLibraryAFn = extern "system" fn(*const u8) -> *mut c_void;
//!
//! let kernel32 = Module::find("kernel32.dll").unwrap();
//! let handle = dinvoke!(
//!     kernel32,
//!     "LoadLibraryA",
//!     LoadLibraryAFn,
//!     b"ntdll.dll\0".as_ptr()
//! );
//! ```
//!
//! ### Indirect Syscalls
//!
//! Execute syscalls indirectly with SSN resolution via Hell's Gate, Halo's Gate, and Tartarus Gate techniques:
//!
//! ```no_run
//! use std::{ffi::c_void, ptr::null_mut};
//! use dinvk::syscall;
//!
//! let mut addr = null_mut::<c_void>();
//! let mut size = 4096usize;
//!
//! let status = syscall!(
//!     "NtAllocateVirtualMemory",
//!     -1isize as *mut c_void,
//!     &mut addr,
//!     0,
//!     &mut size,
//!     0x3000,
//!     0x04
//! );
//!
//! match status {
//!     Ok(0) => println!("allocated at {:?}", addr),
//!     Ok(s) => eprintln!("NtAllocateVirtualMemory failed: {s:#X}"),
//!     Err(e) => eprintln!("syscall resolution failed: {e}"),
//! }
//! ```

#![no_std]
#![doc(
    html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png",
    html_favicon_url = "https://www.rust-lang.org/favicon.ico",
    html_root_url = "https://docs.rs/dinvk/latest"
)]

extern crate alloc;

pub mod error;
pub mod hash;
pub mod env;
pub mod sys;

mod pe;
mod module;
mod macros;

#[cfg(feature = "alloc")]
pub mod alloc;
#[doc(hidden)]
pub mod resolve;

pub use module::Module;
pub use pe::PeImage;
