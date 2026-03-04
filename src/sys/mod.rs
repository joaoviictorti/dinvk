//! Provides SSN (System Service Number) resolution and syscall address
//! extraction for indirect syscall execution. 

use core::ffi::{c_void, CStr};
use core::ptr::read;

use crate::hash::jenkins3;
use crate::pe::PeImage;

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
/// use dinvk::Module;
/// use dinvk::sys::find_ssn;
///
/// let ntdll = Module::find("ntdll.dll").unwrap();
/// if let Some(ssn) = find_ssn("NtAllocateVirtualMemory", ntdll.base()) {
///     println!("SSN: {}", ssn);
/// }
/// ```
pub fn find_ssn(function_name: &str, module: *mut c_void) -> Option<u16> {
    let pe = PeImage::parse(module);
    let exp = pe.exports().data()?;
    let base = module as usize;
    let hash = jenkins3(function_name);

    for i in 0..exp.names.len() {
        let name = unsafe {
            CStr::from_ptr((base + exp.names[i] as usize) as *const i8)
                .to_str()
                .unwrap_or("")
        };

        if jenkins3(name) == hash {
            let ordinal = exp.ordinals[i] as usize;
            let address = (base + exp.addresses[ordinal] as usize) as *const u8;
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
            let high = read(address.add(5)) as u16;
            let low = read(address.add(4)) as u16;
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
            // Check neighboring syscall DOWN.
            if read(address.add(idx * DOWN)) == 0x4C
                && read(address.add(1 + idx * DOWN)) == 0x8B
                && read(address.add(2 + idx * DOWN)) == 0xD1
                && read(address.add(3 + idx * DOWN)) == 0xB8
                && read(address.add(6 + idx * DOWN)) == 0x00
                && read(address.add(7 + idx * DOWN)) == 0x00
            {
                let high = read(address.add(5 + idx * DOWN)) as u16;
                let low = read(address.add(4 + idx * DOWN)) as u16;
                return Some((high << 8) | low.wrapping_sub(idx as u16));
            }

            // Check neighboring syscall UP.
            if read(address.offset(idx as isize * UP)) == 0x4C
                && read(address.offset(1 + idx as isize * UP)) == 0x8B
                && read(address.offset(2 + idx as isize * UP)) == 0xD1
                && read(address.offset(3 + idx as isize * UP)) == 0xB8
                && read(address.offset(6 + idx as isize * UP)) == 0x00
                && read(address.offset(7 + idx as isize * UP)) == 0x00
            {
                let high = read(address.offset(5 + idx as isize * UP)) as u16;
                let low = read(address.offset(4 + idx as isize * UP)) as u16;
                return Some((high << 8) | low.wrapping_add(idx as u16));
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
/// use dinvk::Module;
/// use dinvk::sys::get_syscall_address;
///
/// let ntdll = Module::find("ntdll.dll").unwrap();
/// let addr = ntdll.proc("NtClose").unwrap();
/// if let Some(syscall_addr) = get_syscall_address(addr) {
///     println!("syscall instruction at: {:#x}", syscall_addr);
/// }
/// ```
#[cfg(target_arch = "x86_64")]
pub fn get_syscall_address(address: *mut c_void) -> Option<usize> {
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
            let high = read(address.add(2)) as u16;
            let low = read(address.add(1)) as u16;
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
            // Check neighboring syscall DOWN.
            if read(address.add(idx * DOWN)) == 0xB8
                && read(address.add(3 + idx * DOWN)) == 0x00
                && read(address.add(4 + idx * DOWN)) == 0x00
            {
                let high = read(address.add(2 + idx * DOWN)) as u16;
                let low = read(address.add(1 + idx * DOWN)) as u16;
                return Some((high << 8) | low.wrapping_sub((idx * 2) as u16));
            }

            // Check neighboring syscall UP.
            if read(address.offset(idx as isize * UP)) == 0xB8
                && read(address.offset(3 + idx as isize * UP)) == 0x00
                && read(address.offset(4 + idx as isize * UP)) == 0x00
            {
                let high = read(address.offset(2 + idx as isize * UP)) as u16;
                let low = read(address.offset(1 + idx as isize * UP)) as u16;
                return Some((high << 8) | low.wrapping_add((idx * 2) as u16));
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
/// use dinvk::Module;
/// use dinvk::sys::get_syscall_address;
///
/// let ntdll = Module::find("ntdll.dll").unwrap();
/// let addr = ntdll.proc("NtClose").unwrap();
/// if let Some(syscall_addr) = get_syscall_address(addr) {
///     println!("syscall instruction at: {:#x}", syscall_addr);
/// }
/// ```
#[cfg(target_arch = "x86")]
pub fn get_syscall_address(address: *mut c_void) -> Option<usize> {
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
#[inline(always)]
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
            let opcode = (read(address.add(3)) as u32) << 24
                | (read(address.add(2)) as u32) << 16
                | (read(address.add(1)) as u32) << 8
                | (read(address) as u32);

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
