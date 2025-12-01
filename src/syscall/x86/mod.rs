use core::{
    ffi::{c_void, CStr}, 
    ptr::read, 
    slice::from_raw_parts,
};

use crate::{
    helper::PE,
    hash::jenkins3, 
    syscall::{DOWN, RANGE, UP}
};

/// Resolves the System Service Number (SSN) for a given function name within a module.
pub fn ssn(function_name: &str, module: *mut c_void) -> Option<u16> {
    unsafe {
        // Recovering the export directory and hashing the module 
        let export_dir = PE::parse(module)
            .exports()
            .directory()?;
        
        let hash = jenkins3(function_name);
        let module = module as usize;

        // Retrieving information from module names
        let names = from_raw_parts((
            module + (*export_dir).AddressOfNames as usize) as *const u32, 
            (*export_dir).NumberOfNames as usize
        );

        // Retrieving information from functions
        let functions = from_raw_parts(
            (module + (*export_dir).AddressOfFunctions as usize) as *const u32, 
            (*export_dir).NumberOfFunctions as usize
        );

        // Retrieving information from ordinals
        let ordinals = from_raw_parts(
            (module + (*export_dir).AddressOfNameOrdinals as usize) as *const u16, 
            (*export_dir).NumberOfNames as usize
        );
        
        for i in 0..(*export_dir).NumberOfNames as isize {
            let ordinal = ordinals[i as usize] as usize;
            let address = (module + functions[ordinal] as usize) as *const u8;
            let name = CStr::from_ptr((module + names[i as usize] as usize) as *const i8)
                .to_str()
                .unwrap_or("");

            // Comparation by Hash (Default `Jenkins3`)
            if jenkins3(&name) == hash {
                // Hells Gate (x86)
                // MOV EAX, <ssn>  => 0xB8 XX XX 00 00
                if read(address) == 0xB8
                    && read(address.add(3)) == 0x00
                    && read(address.add(4)) == 0x00
                {
                    let high = read(address.add(2)) as u16;
                    let low  = read(address.add(1)) as u16;
                    let ssn = (high << 8) | low;
                    return Some(ssn);
                }

                // Halos Gate (x86 and Wow64)
                if read(address) == 0xE9 {
                    for idx in 1..RANGE {
                        // check neighboring syscall down
                        if read(address.add(idx * DOWN)) == 0xB8
                            && read(address.add(3 + idx * DOWN)) == 0x00
                            && read(address.add(4 + idx * DOWN)) == 0x00
                            {
                                let high = read(address.add(2 + idx * DOWN)) as u16;
                                let low = read(address.add(1 + idx * DOWN)) as u16;
                                let ssn = (high << 8) | (low - (idx * 2) as u16);
                                return Some(ssn);
                            }
    
                        // check neighboring syscall up
                        if read(address.offset(idx as isize * UP)) == 0xB8
                            && read(address.offset(3 + idx as isize * UP)) == 0x00
                            && read(address.offset(4 + idx as isize * UP)) == 0x00
                            {
                                let high = read(address.offset(2 + idx as isize * UP)) as u16;
                                let low = read(address.offset(1 + idx as isize * UP)) as u16;
                                let ssn = (high << 8) | (low + (idx * 2) as u16);
                                return Some(ssn);
                            }
                    }
                }

                // Tartarus Gate (x86 and Wow64)
                if read(address.add(3)) == 0xE9 {
                    for idx in 1..RANGE {
                        // check neighboring syscall down
                        if read(address.add(idx * DOWN)) == 0xB8
                            && read(address.add(3 + idx * DOWN)) == 0x00
                            && read(address.add(4 + idx * DOWN)) == 0x00
                            {
                                let high = read(address.add(2 + idx * DOWN)) as u16;
                                let low = read(address.add(1 + idx * DOWN)) as u16;
                                let ssn = (high << 8) | (low - (idx * 2)  as u16);
                                return Some(ssn);
                            }
    
                        // check neighboring syscall up
                        if read(address.offset(idx as isize * UP)) == 0xB8
                            && read(address.offset(3 + idx as isize * UP)) == 0x00
                            && read(address.offset(4 + idx as isize * UP)) == 0x00
                            {
                                let high = read(address.offset(2 + idx as isize * UP)) as u16;
                                let low = read(address.offset(1 + idx as isize * UP)) as u16;
                                let ssn = (high << 8) | (low + (idx * 2) as u16);
                                return Some(ssn);
                            }
                    }
                }
            }
        }
    }

    None
}

/// Retrieves the syscall address from a given function address.
pub fn get_syscall_address(address: *mut c_void) -> Option<u32> {
    unsafe {
        // Is Process wow64?
        let address = address.cast::<u8>();
        if is_wow64() {
            return (1..255).find_map(|i| {
                if read(address.add(i)) == 0xFF 
                    && read(address.add(i + 1)) == 0xD2 
                {
                    Some(address.add(i) as u32)
                } else {
                    None
                }
            });
        }

        // If it's not a wow64 process, it's a native x86 process
        (1..255).find_map(|i| {
            if read(address.add(i)) == 0x8B
                && read(address.add(i + 1)) == 0xD4
                && read(address.add(i + 2)) == 0x0F
                && read(address.add(i + 3)) == 0x34
                && read(address.add(i + 4)) == 0xC3
            {
                Some(address.add(i + 2) as u32)
            } else {
                None
            }
        })
    }
}

/// Checks if the process is running under WOW64 (Windows 32-bit on a 64-bit OS).
///
/// In Windows, the `FS` segment contains the Thread Environment Block (TEB),
/// and offset `0xC0` holds a pointer to the WOW64 structure.  
/// If this value is `0`, the process is running in **pure x86 mode**.  
/// If it is non-zero, the process is running under **WOW64**.
/// 
/// # Reference
/// 
/// https://github.com/AlexPetrusca/assembly-virus/blob/17dbe88e066c4ae680136d10cd3110820169a0e9/docs/TEB.txt#L23
#[inline(always)]
pub(crate) fn is_wow64() -> bool {
    let addr = unsafe { super::__readfsdword(0xC0) };
    addr != 0
}