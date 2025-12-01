#[cfg(target_arch = "x86")]
mod x86;
#[cfg(target_arch = "x86")]
pub use x86::*;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[doc(hidden)]
pub mod asm;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const RANGE: usize = 255;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const DOWN: usize = 32;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const UP: isize = -32;
