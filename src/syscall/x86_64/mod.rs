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
        let names = from_raw_parts(
            (module + (*export_dir).AddressOfNames as usize) as *const u32, 
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
    
            // Comparation by Hash (Default `jenkins3`)
            if jenkins3(name) == hash {
                // Hells Gate
                // MOV R10, RCX
                // MOV RCX, <ssn>
                if read(address) == 0x4C
                    && read(address.add(1)) == 0x8B
                    && read(address.add(2)) == 0xD1
                    && read(address.add(3)) == 0xB8
                    && read(address.add(6)) == 0x00
                    && read(address.add(7)) == 0x00 
                {
                    let high = read(address.add(5)) as u16;
                    let low = read(address.add(4)) as u16;
                    let ssn = (high << 8) | low;
                    return Some(ssn);
                }
    
                // Halos Gate
                if read(address) == 0xE9 {
                    for idx in 1..RANGE {
                        // check neighboring syscall down
                        if read(address.add(idx * DOWN)) == 0x4C
                            && read(address.add(1 + idx * DOWN)) == 0x8B
                            && read(address.add(2 + idx * DOWN)) == 0xD1
                            && read(address.add(3 + idx * DOWN)) == 0xB8
                            && read(address.add(6 + idx * DOWN)) == 0x00
                            && read(address.add(7 + idx * DOWN)) == 0x00 
                            {
                                let high = read(address.add(5 + idx * DOWN)) as u16;
                                let low = read(address.add(4 + idx * DOWN)) as u16;
                                let ssn = (high << 8) | (low - idx as u16);
                                return Some(ssn);
                            }
    
                        // check neighboring syscall up
                        if read(address.offset(idx as isize * UP)) == 0x4c
                            && read(address.offset(1 + idx as isize * UP)) == 0x8B
                            && read(address.offset(2 + idx as isize * UP)) == 0xD1
                            && read(address.offset(3 + idx as isize * UP)) == 0xB8
                            && read(address.offset(6 + idx as isize * UP)) == 0x00
                            && read(address.offset(7 + idx as isize * UP)) == 0x00 
                            {
                                let high = read(address.offset(5 + idx as isize * UP)) as u16;
                                let low = read(address.offset(4 + idx as isize * UP)) as u16;
                                let ssn = (high << 8) | (low + idx as u16);
                                return Some(ssn);
                            }
                    }
                }
    
                // Tartarus Gate
                if read(address.add(3)) == 0xE9 {
                    for idx in 1..RANGE {
                        // check neighboring syscall down
                        if read(address.add(idx * DOWN)) == 0x4C
                            && read(address.add(1 + idx * DOWN)) == 0x8B
                            && read(address.add(2 + idx * DOWN)) == 0xD1
                            && read(address.add(3 + idx * DOWN)) == 0xB8
                            && read(address.add(6 + idx * DOWN)) == 0x00
                            && read(address.add(7 + idx * DOWN)) == 0x00 
                            {
                                let high = read(address.add(5 + idx * DOWN)) as u16;
                                let low = read(address.add(4 + idx * DOWN)) as u16;
                                let ssn = (high << 8) | (low - idx as u16);
                                return Some(ssn);
                            }
                            
                        // check neighboring syscall up
                        if read(address.offset(idx as isize * UP)) == 0x4c
                            && read(address.offset(1 + idx as isize * UP)) == 0x8B
                            && read(address.offset(2 + idx as isize * UP)) == 0xD1
                            && read(address.offset(3 + idx as isize * UP)) == 0xB8
                            && read(address.offset(6 + idx as isize * UP)) == 0x00
                            && read(address.offset(7 + idx as isize * UP)) == 0x00 
                            {
                                let high = read(address.offset(5 + idx as isize * UP)) as u16;
                                let low = read(address.offset(4 + idx as isize * UP)) as u16;
                                let ssn = (high << 8) | (low + idx as u16);
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
pub fn get_syscall_address(address: *mut c_void) -> Option<u64> {
    unsafe {
        let address = address.cast::<u8>();
        (1..255).find_map(|i| {
            if read(address.add(i)) == 0x0F
                && read(address.add(i + 1)) == 0x05
                && read(address.add(i + 2)) == 0xC3
            {
                Some(address.add(i) as u64)
            } else {
                None
            }
        })
    }
}
