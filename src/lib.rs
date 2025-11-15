#![no_std]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case, non_camel_case_types)]
#![allow(
    clippy::too_many_arguments,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::missing_safety_doc,
    clippy::macro_metavars_in_unsafe,
)]

extern crate alloc;

pub mod data;
pub mod hash;
pub mod pe;
pub mod winapis;
pub mod console;
pub mod module;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod breakpoint;

#[cfg(feature = "panic")]
pub mod panic;

#[cfg(feature = "alloc")]
pub mod allocator;

mod macros;
mod syscall;
pub use syscall::*;