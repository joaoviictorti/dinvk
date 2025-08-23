//! # dinvk 🦀
//!
//! Dynamically invoke arbitrary code in Rust with full support for `#[no_std]` and multiple architectures:
//! **x64**, **x86**, **WoW64**, **ARM64**.
//!
//! This crate is a Rust reimplementation of [DInvoke](https://github.com/TheWover/DInvoke) with extra features.
//!
//! ## Features
//! - Dynamic API resolution (`dinvoke!`).
//! - Indirect syscalls (Hells Gate / Halos Gate / Tartarus Gate).
//! - Syscall redirection to other DLLs (e.g. `win32u.dll`, `vertdll.dll`).
//! - PE parsing, proxy DLL loading.
//! - Multiple hashing algorithms for API resolution.
//! - `#[no_std]` compatibility.
//!
//! ## Examples
//!
//! ### 1. Dynamically Invoke Arbitrary Code
//! ```no_run
//! use dinvk::{
//!     data::HeapAllocFn,
//!     dinvoke, GetModuleHandle,
//!     GetProcessHeap
//! };
//!
//! const HEAP_ZERO_MEMORY: u32 = 8;
//!
//! fn main() {
//!     let kernel32 = GetModuleHandle("KERNEL32.DLL", None);
//!     let addr = dinvoke!(
//!         kernel32,
//!         "HeapAlloc",
//!         HeapAllocFn,
//!         GetProcessHeap(),
//!         HEAP_ZERO_MEMORY,
//!         0x200
//!     );
//!
//!     println!("[+] Address: {:?}", addr);
//! }
//! ```
//!
//! ### 2. Indirect Syscall
//! ```no_run
//! use std::{ffi::c_void, ptr::null_mut};
//! use dinvk::{
//!     data::{NTSTATUS, NT_SUCCESS},
//!     syscall, NtCurrentProcess
//! };
//!
//! fn main() -> Result<(), NTSTATUS> {
//!     let mut addr = null_mut::<c_void>();
//!     let mut size = 0x1000;
//!
//!     let status = syscall!(
//!         "NtAllocateVirtualMemory",
//!         NtCurrentProcess(),
//!         &mut addr,
//!         0,
//!         &mut size,
//!         0x3000,
//!         0x40
//!     ).ok_or(-1)?;
//!
//!     if !NT_SUCCESS(status) {
//!         eprintln!("[-] NtAllocateVirtualMemory failed: {status:?}");
//!         return Err(status);
//!     }
//!
//!     println!("[+] Allocated at: {:?}", addr);
//!     Ok(())
//! }
//! ```
//!
//! ### 3. Hashing APIs
//! ```no_run
//! use dinvk::hash::*;
//!
//! fn main() {
//!     println!("jenkins: {}", jenkins("dinvk"));
//!     println!("djb2:    {}", djb2("dinvk"));
//!     println!("fnv1a:   {}", fnv1a("dinvk"));
//! }
//! ```
//!
//! ### 4. Proxy DLL Loading
//! ```no_run
//! use dinvk::LdrProxy;
//!
//! fn main() {
//!     // Use RtlQueueWorkItem to indirectly load DLL
//!     LdrProxy::new("xpsservices.dll").work();
//!
//!     // Or RtlCreateTimer
//!     LdrProxy::new("xpsservices.dll").timer();
//!
//!     // Or RtlRegisterWait
//!     LdrProxy::new("xpsservices.dll").register_wait();
//! }
//! ```
//! 
//! # More Information
//!
//! For updates, usage guides, and examples, visit the [repository].
//!
//! [repository]: https://github.com/joaoviictorti/uwd

#![no_std]
#![allow(non_snake_case, non_camel_case_types)]
#![allow(
    clippy::too_many_arguments,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::missing_transmute_annotations,
    clippy::missing_safety_doc,
    clippy::macro_metavars_in_unsafe
)]

extern crate alloc;

/// Structures and types used across the library.
pub mod data;

/// Runtime hash functions.
pub mod hash;

/// PE Parsing
pub mod parse;

/// Hardware breakpoint management utilities (only for x86/x86_64 targets).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod breakpoint;

/// Custom panic handler support (requires `dinvk_panic` feature).
#[cfg(feature = "dinvk_panic")]
pub mod panic;

/// Heap allocator using Windows native APIs (requires `alloc` feature).
#[cfg(feature = "alloc")]
pub mod allocator;

mod functions;
mod macros;
mod module;
mod syscall;
mod utils;

pub use syscall::*;
pub use functions::*;
pub use module::*;
pub use module::ldr::*;
pub use utils::*;