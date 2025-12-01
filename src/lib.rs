#![no_std]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case, non_camel_case_types)]
#![allow(clippy::too_many_arguments, clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::macro_metavars_in_unsafe)]

extern crate alloc;

pub mod types;
pub mod hash;
pub mod helper;
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