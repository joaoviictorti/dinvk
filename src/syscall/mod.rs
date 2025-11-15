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

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod dll;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub use dll::*;

#[doc(hidden)]
pub mod asm;

/// The maximum range of bytes to search when resolving syscall instructions.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const RANGE: usize = 255;

/// The step size used to scan memory in a downward direction.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const DOWN: usize = 32;

/// The step size used to scan memory in an upward direction.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const UP: isize = -32;
