// Copyright (c) 2025 joaoviictorti
// Licensed under the MIT License. See LICENSE file in the project root for details.

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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod breakpoint;

#[cfg(feature = "panic")]
pub mod panic;

#[cfg(feature = "alloc")]
pub mod allocator;

mod functions;
mod macros;
mod module;
mod syscall;
mod console;

pub use syscall::*;
pub use functions::*;
pub use module::*;
pub use console::*;