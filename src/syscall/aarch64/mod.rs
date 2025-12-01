use core::{
    ffi::{c_void, CStr}, 
    ptr::read, 
    slice::from_raw_parts,
};
use crate::{
    hash::jenkins3, 
    helper::PE,
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
    
            // Comparation by Hash (Default `jenkins3`)
            if jenkins3(&name) == hash {
                // svc, #`<ssn>`
                if read(address.add(3)) == 0xD4
                    && (read(address.add(2)) & 0xFC) == 0x00
                {
                    let opcode = (read(address.add(3)) as u32) << 24
                        | (read(address.add(2)) as u32) << 16
                        | (read(address.add(1)) as u32) << 8
                        | (read(address) as u32);
            
                    // Take the bits [5:20]
                    let ssn = (opcode >> 5) & 0xFFFF;
                    return Some(ssn as u16);
                }
            }
        }
    }

    None
}
