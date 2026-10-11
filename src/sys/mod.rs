//! Provides SSN (System Service Number) resolution and syscall address
//! extraction for indirect syscall execution. 

use core::ffi::c_void;
use core::ptr::read;

use pelite::pe::{Pe, PeView};

use crate::hash::jenkins3;
use crate::module::Module;

#[doc(hidden)]
pub mod asm;

/// Maximum neighbor search range for hooked syscalls.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const RANGE: usize = 255;

/// Syscall stub size for downward neighbor search.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const DOWN: usize = 32;

/// Syscall stub size for upward neighbor search (negative offset).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const UP: isize = -32;

/// Resolves the SSN for a function by name from a module's export table.
///
/// Supports clean stubs (Hell's Gate), hooked stubs (Halos Gate), and
/// stubs hooked after `MOV R10, RCX` (Tartarus Gate).
///
/// # Examples
///
/// ```no_run
/// # use dinvk::Module;
/// # use dinvk::sys::find_ssn;
///
/// let ntdll = Module::find("ntdll.dll").unwrap();
/// if let Some(ssn) = unsafe { find_ssn("NtAllocateVirtualMemory", &ntdll) } {
///     println!("SSN: {}", ssn);
/// }
/// ```
///
/// # Safety
///
/// `module` must be a valid, loaded copy of `ntdll.dll` whose syscall export
/// stubs and their neighboring stubs are readable.
pub unsafe fn find_ssn(function_name: &str, module: &Module) -> Option<u16> {
    let base_address = module.base();
    let pe = unsafe { PeView::module(base_address.cast()) };
    let exports = pe.exports().ok()?;
    let by = exports.by().ok()?;
    let base = base_address as usize;
    let hash = jenkins3(function_name);

    for (name, export) in by.iter_names() {
        let Ok(name) = name else {
            continue;
        };
        let Ok(name) = name.to_str() else {
            continue;
        };

        if jenkins3(name) == hash {
            let rva = export.ok()?.symbol()?;
            let address = (base + rva as usize) as *const u8;
            return extract_ssn(address);
        }
    }

    None
}

/// Extracts the SSN from an x64 syscall stub.
///
/// Supports Hell's Gate (clean stub), Halos Gate (hooked at start),
/// and Tartarus Gate (hooked after MOV R10, RCX).
#[cfg(target_arch = "x86_64")]
fn extract_ssn(address: *const u8) -> Option<u16> {
    unsafe {
        // Hell's Gate: MOV R10, RCX; MOV EAX, <ssn>.
        if read(address) == 0x4C
            && read(address.add(1)) == 0x8B
            && read(address.add(2)) == 0xD1
            && read(address.add(3)) == 0xB8
            && read(address.add(6)) == 0x00
            && read(address.add(7)) == 0x00
        {
            let high = u16::from(read(address.add(5)));
            let low = u16::from(read(address.add(4)));
            return Some((high << 8) | low);
        }

        // Halos Gate: hooked at start (JMP).
        if read(address) == 0xE9
            && let Some(ssn) = search_neighbors_x64(address)
        {
            return Some(ssn);
        }

        // Tartarus Gate: hooked after MOV R10, RCX.
        if read(address.add(3)) == 0xE9
            && let Some(ssn) = search_neighbors_x64(address)
        {
            return Some(ssn);
        }
    }

    None
}

/// Searches neighboring syscall stubs to infer the SSN (x64).
#[cfg(target_arch = "x86_64")]
fn search_neighbors_x64(address: *const u8) -> Option<u16> {
    unsafe {
        for idx in 1..RANGE {
            let idx_u16 = u16::try_from(idx).ok()?;
            let up = isize::try_from(idx).ok()? * UP;

            // Check neighboring syscall DOWN.
            if read(address.add(idx * DOWN)) == 0x4C
                && read(address.add(1 + idx * DOWN)) == 0x8B
                && read(address.add(2 + idx * DOWN)) == 0xD1
                && read(address.add(3 + idx * DOWN)) == 0xB8
                && read(address.add(6 + idx * DOWN)) == 0x00
                && read(address.add(7 + idx * DOWN)) == 0x00
            {
                let high = u16::from(read(address.add(5 + idx * DOWN)));
                let low = u16::from(read(address.add(4 + idx * DOWN)));
                return Some((high << 8) | low.wrapping_sub(idx_u16));
            }

            // Check neighboring syscall UP.
            if read(address.offset(up)) == 0x4C
                && read(address.offset(1 + up)) == 0x8B
                && read(address.offset(2 + up)) == 0xD1
                && read(address.offset(3 + up)) == 0xB8
                && read(address.offset(6 + up)) == 0x00
                && read(address.offset(7 + up)) == 0x00
            {
                let high = u16::from(read(address.offset(5 + up)));
                let low = u16::from(read(address.offset(4 + up)));
                return Some((high << 8) | low.wrapping_add(idx_u16));
            }
        }
    }

    None
}

/// Finds the syscall instruction address within an x64 stub.
///
/// Scans the stub for the `syscall; ret` instruction sequence and returns
/// its address for use with indirect syscall techniques.
///
/// # Examples
///
/// ```no_run
/// # use dinvk::Module;
/// # use dinvk::sys::get_syscall_address;
///
/// let ntdll = Module::find("ntdll.dll").unwrap();
/// let addr = ntdll.proc("NtClose").unwrap();
/// if let Some(syscall_addr) = unsafe { get_syscall_address(addr) } {
///     println!("syscall instruction at: {:#x}", syscall_addr);
/// }
/// ```
///
/// # Safety
///
/// `address` must point to a readable syscall stub with at least 257 bytes
/// available from its start.
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_syscall_address(address: *mut c_void) -> Option<usize> {
    unsafe {
        let address = address.cast::<u8>();

        // syscall; ret => 0x0F 0x05 0xC3.
        (1..255).find_map(|i| {
            if read(address.add(i)) == 0x0F
                && read(address.add(i + 1)) == 0x05
                && read(address.add(i + 2)) == 0xC3
            {
                Some(address.add(i) as usize)
            } else {
                None
            }
        })
    }
}

/// Extracts the SSN from an x86 syscall stub.
///
/// Supports Hell's Gate (clean stub), Halos Gate (hooked at start),
/// and Tartarus Gate (hooked after MOV EAX).
#[cfg(target_arch = "x86")]
fn extract_ssn(address: *const u8) -> Option<u16> {
    unsafe {
        // Hell's Gate: MOV EAX, <ssn>.
        if read(address) == 0xB8
            && read(address.add(3)) == 0x00
            && read(address.add(4)) == 0x00
        {
            let high = u16::from(read(address.add(2)));
            let low = u16::from(read(address.add(1)));
            return Some((high << 8) | low);
        }

        // Halos Gate: hooked at start (JMP).
        if read(address) == 0xE9 {
            if let Some(ssn) = search_neighbors_x86(address) {
                return Some(ssn);
            }
        }

        // Tartarus Gate: hooked after MOV EAX.
        if read(address.add(3)) == 0xE9 {
            if let Some(ssn) = search_neighbors_x86(address) {
                return Some(ssn);
            }
        }
    }

    None
}

/// Searches neighboring syscall stubs to infer the SSN (x86).
#[cfg(target_arch = "x86")]
fn search_neighbors_x86(address: *const u8) -> Option<u16> {
    unsafe {
        for idx in 1..RANGE {
            let idx_u16 = u16::try_from(idx).ok()?;
            let up = isize::try_from(idx).ok()? * UP;

            // Check neighboring syscall DOWN.
            if read(address.add(idx * DOWN)) == 0xB8
                && read(address.add(3 + idx * DOWN)) == 0x00
                && read(address.add(4 + idx * DOWN)) == 0x00
            {
                let high = u16::from(read(address.add(2 + idx * DOWN)));
                let low = u16::from(read(address.add(1 + idx * DOWN)));
                return Some((high << 8) | low.wrapping_sub(idx_u16 * 2));
            }

            // Check neighboring syscall UP.
            if read(address.offset(up)) == 0xB8
                && read(address.offset(3 + up)) == 0x00
                && read(address.offset(4 + up)) == 0x00
            {
                let high = u16::from(read(address.offset(2 + up)));
                let low = u16::from(read(address.offset(1 + up)));
                return Some((high << 8) | low.wrapping_add(idx_u16 * 2));
            }
        }
    }

    None
}

/// Finds the syscall instruction address within an x86 stub.
///
/// Handles both native x86 (sysenter) and WOW64 (call edx).
///
/// # Examples
///
/// ```no_run
/// # use dinvk::Module;
/// # use dinvk::sys::get_syscall_address;
///
/// let ntdll = Module::find("ntdll.dll").unwrap();
/// let addr = ntdll.proc("NtClose").unwrap();
/// if let Some(syscall_addr) = unsafe { get_syscall_address(addr) } {
///     println!("syscall instruction at: {:#x}", syscall_addr);
/// }
/// ```
///
/// # Safety
///
/// `address` must point to a readable syscall stub with at least 259 bytes
/// available from its start.
#[cfg(target_arch = "x86")]
pub unsafe fn get_syscall_address(address: *mut c_void) -> Option<usize> {
    unsafe {
        let address = address.cast::<u8>();

        // WOW64: call edx => 0xFF 0xD2.
        if is_wow64() {
            return (1..255).find_map(|i| {
                if read(address.add(i)) == 0xFF && read(address.add(i + 1)) == 0xD2 {
                    Some(address.add(i) as usize)
                } else {
                    None
                }
            });
        }

        // Native x86: mov edx, esp; sysenter; ret.
        (1..255).find_map(|i| {
            if read(address.add(i)) == 0x8B
                && read(address.add(i + 1)) == 0xD4
                && read(address.add(i + 2)) == 0x0F
                && read(address.add(i + 3)) == 0x34
                && read(address.add(i + 4)) == 0xC3
            {
                Some(address.add(i + 2) as usize)
            } else {
                None
            }
        })
    }
}

/// Checks if running under WOW64 emulation.
#[cfg(target_arch = "x86")]
#[inline]
fn is_wow64() -> bool {
    let addr = crate::env::__readfsdword(0xC0);
    addr != 0
}

/// Extracts the SSN from an ARM64 syscall stub.
#[cfg(target_arch = "aarch64")]
fn extract_ssn(address: *const u8) -> Option<u16> {
    unsafe {
        // SVC #<imm16>.
        if read(address.add(3)) == 0xD4 && (read(address.add(2)) & 0xFC) == 0x00 {
            let opcode = u32::from(read(address.add(3))) << 24
                | u32::from(read(address.add(2))) << 16
                | u32::from(read(address.add(1))) << 8
                | u32::from(read(address));

            let ssn = (opcode >> 5) & 0xFFFF;
            return Some(ssn as u16);
        }
    }

    None
}

/// Returns the syscall address for ARM64.
///
/// ARM64 uses the `SVC` instruction directly in the stub, so no indirect
/// pattern is needed. Returns the stub address itself.
#[cfg(target_arch = "aarch64")]
pub fn get_syscall_address(address: *mut c_void) -> Option<u64> {
    Some(address as u64)
}
