//! Process and thread environment block access.

use phnt::ffi::{PEB, TEB};

/// Retrieves a pointer to the PEB of the current process.
#[inline(always)]
pub fn nt_current_peb() -> *const PEB {
    #[cfg(target_arch = "x86_64")]
    return __readgsqword(0x60) as *const PEB;

    #[cfg(target_arch = "x86")]
    return __readfsdword(0x30) as *const PEB;

    #[cfg(target_arch = "aarch64")]
    return unsafe { *(__readx18(0x60) as *const *const PEB) };
}

/// Retrieves a pointer to the TEB of the current thread.
#[inline(always)]
pub fn nt_current_teb() -> *const TEB {
    #[cfg(target_arch = "x86_64")]
    return __readgsqword(0x30) as *const TEB;

    #[cfg(target_arch = "x86")]
    return __readfsdword(0x18) as *const TEB;

    #[cfg(target_arch = "aarch64")]
    return unsafe { *(__readx18(0x30) as *const *const TEB) };
}

/// Reads a u64 from the GS segment at the specified offset.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[{:e}]",
            lateout(reg) out,
            in(reg) offset,
            options(nostack, pure, readonly),
        );
    }
    out
}

/// Reads a u32 from the FS segment at the specified offset.
#[inline(always)]
#[cfg(target_arch = "x86")]
pub fn __readfsdword(offset: u32) -> u32 {
    let out: u32;
    unsafe {
        core::arch::asm!(
            "mov {:e}, fs:[{:e}]",
            lateout(reg) out,
            in(reg) offset,
            options(nostack, pure, readonly),
        );
    }
    out
}

/// Reads a u64 from the x18 register at the specified offset.
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub fn __readx18(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, x18",
            lateout(reg) out,
            options(nostack, pure, readonly),
        );
    }
    out + offset
}
