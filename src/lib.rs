#![no_std]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case, non_camel_case_types)]
#![allow(
    clippy::too_many_arguments,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::missing_transmute_annotations,
    clippy::missing_safety_doc,
    clippy::macro_metavars_in_unsafe,
    clippy::collapsible_if
)]

extern crate alloc;

/// Structures and types used across the library.
pub mod data;

/// Runtime hash functions.
pub mod hash;

/// PE Parsing
pub mod pe;

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
mod util;
mod console;

pub use syscall::*;
pub use functions::*;
pub use module::*;
pub use util::{shuffle};
pub use console::ConsoleWriter;