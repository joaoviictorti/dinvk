use alloc::{
    format, vec::Vec, vec,
    string::{String, ToString}, 
};
use core::{
    ffi::{c_void, CStr}, 
    ptr::null_mut, 
    slice::from_raw_parts
};

use obfstr::obfstr as s;
use super::{data::*, pe::PE};
use super::hash::{crc32ba, murmur3};
use super::{
    LoadLibraryA,
    NtCurrentPeb
};

/// Stores the NTDLL address
static NTDLL: spin::Once<u64> = spin::Once::new();

/// Retrieves the base address of the `ntdll.dll` module.
#[inline(always)]
pub fn get_ntdll_address() -> *mut c_void {
    *NTDLL.call_once(|| GetModuleHandle(
        2788516083u32, 
        Some(murmur3)) as u64
    ) as *mut c_void
}

/// Resolves the base address of a module loaded in memory by name or hash.
///
/// # Arguments
///
/// * `module` - Can be a DLL name (as `&str`) or a hash (`u32`).
/// * `hash` - Optional hash function. Used for hash matching.
///
/// # Returns
///
/// * Returns the module's base address.
///
/// # Examples
///
/// ```
/// let base = GetModuleHandle("ntdll.dll", None);
/// let base = GetModuleHandle(2788516083u32, Some(murmur3));
/// ```
pub fn GetModuleHandle<T>(
    module: T,
    hash: Option<fn(&str) -> u32>
) -> HMODULE
where 
    T: ToString
{
    unsafe {
        let hash = hash.unwrap_or(crc32ba);
        let peb = NtCurrentPeb();
        let ldr_data = (*peb).Ldr;
        let mut list_node = (*ldr_data).InMemoryOrderModuleList.Flink;
        let mut data_table_entry = (*ldr_data).InMemoryOrderModuleList.Flink 
            as *const LDR_DATA_TABLE_ENTRY;

        if module.to_string().is_empty() {
            return (*peb).ImageBaseAddress;
        }

        // Save a reference to the head nod for the list
        let head_node = list_node;
        let mut addr = null_mut();
        while !(*data_table_entry).FullDllName.Buffer.is_null() {
            if (*data_table_entry).FullDllName.Length != 0 {
                // Converts the buffer from UTF-16 to a `String`
                let buffer = from_raw_parts(
                    (*data_table_entry).FullDllName.Buffer,
                    ((*data_table_entry).FullDllName.Length / 2) as usize
                );
            
                // Try interpreting `module` as a numeric hash (u32)
                let mut dll_file_name = String::from_utf16_lossy(buffer).to_uppercase();
                if let Ok(dll_hash) = module.to_string().parse::<u32>() {
                    if dll_hash == hash(&dll_file_name) {
                        addr = (*data_table_entry).Reserved2[0];
                        break;
                    }
                } else {
                    // If it is not an `u32`, it is treated as a string
                    let module = canonicalize_module(&module.to_string());
                    dll_file_name = canonicalize_module(&dll_file_name);
                    if dll_file_name == module {
                        addr = (*data_table_entry).Reserved2[0];
                        break;
                    }
                }
            }

            // Moves to the next node in the list of modules
            list_node = (*list_node).Flink;

            // Break out of loop if all of the nodes have been checked
            if list_node == head_node {
                break
            }

            data_table_entry = list_node as *const LDR_DATA_TABLE_ENTRY
        }
        
        addr
    }
}

/// Retrieves the address of an exported function from a loaded module.
///
/// # Arguments
///
/// * `h_module` - Handle to the loaded module (base address)
/// * `function` - Name, hash, or ordinal as input
/// * `hash` - Optional hash function. Used for hash matching.
///
/// # Returns
///
/// * Pointer to the resolved function
///
/// # Examples
///
/// ### Name
/// ```rust,ignore
/// GetProcAddress(base, "NtProtectVirtualMemory", None);
/// ```
///
/// ### Hash
/// ```rust,ignore
/// GetProcAddress(base, 2193297120u32, Some(murmur3));
/// ```
///
/// ### Ordinal
/// ```rust,ignore
/// GetProcAddress(base, 473u32, None);
/// ```
pub fn GetProcAddress<T>(
    h_module: HMODULE,
    function: T,
    hash: Option<fn(&str) -> u32>
) -> *mut c_void
where 
    T: ToString,
{
    if h_module.is_null() {
        return null_mut();
    }

    unsafe {
        // Converts the module handle to a base address
        let h_module = h_module as usize;

        // Initializes the PE parser from the base address
        let pe = PE::parse(h_module as *mut c_void);

        // Retrieves the NT header and export directory; returns null if either is missing
        let Some((nt_header, export_dir)) = pe.nt_header().zip(pe.exports().directory()) else {
            return null_mut();
        };

        // Retrieves the size of the export table
        let export_size = (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size as usize;

        // Retrieving information from module names
        let names = from_raw_parts(
            (h_module + (*export_dir).AddressOfNames as usize) as *const u32, 
            (*export_dir).NumberOfNames as usize
        );

        // Retrieving information from functions
        let functions = from_raw_parts(
            (h_module + (*export_dir).AddressOfFunctions as usize) as *const u32, 
            (*export_dir).NumberOfFunctions as usize
        );

        // Retrieving information from ordinals
        let ordinals = from_raw_parts(
            (h_module + (*export_dir).AddressOfNameOrdinals as usize) as *const u16, 
            (*export_dir).NumberOfNames as usize
        );

        // Convert Api name to String
        let api_name = function.to_string();

        // Import By Ordinal
        if let Ok(ordinal) = api_name.parse::<u32>() && ordinal <= 0xFFFF {
            let ordinal = ordinal & 0xFFFF;
            if ordinal < (*export_dir).Base || (ordinal >= (*export_dir).Base + (*export_dir).NumberOfFunctions) {
                return null_mut();
            }

            return (h_module + functions[ordinal as usize - (*export_dir).Base as usize] as usize) as *mut c_void;
        }

        // Extract DLL name from export directory for forwarder resolution
        let dll_name = {
            let ptr = (h_module + (*export_dir).Name as usize) as *const i8;
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        };

        // Import By Name or Hash
        let hash = hash.unwrap_or(crc32ba);
        for i in 0..(*export_dir).NumberOfNames as usize {
            let name = CStr::from_ptr((h_module + names[i] as usize) as *const i8)
                .to_str()
                .unwrap_or("");

            let ordinal = ordinals[i] as usize;
            let address = (h_module + functions[ordinal] as usize) as *mut c_void;
            if let Ok(api_hash) = api_name.parse::<u32>() {
                // Comparison by hash
                if hash(name) == api_hash {
                    return get_forwarded_address(&dll_name, address, export_dir, export_size, hash);
                }
            } else {
                // Comparison by String
                if name == api_name {
                    return get_forwarded_address(&dll_name, address, export_dir, export_size, hash);
                }
            }
        }
    }

    null_mut()
}

/// Resolves forwarded exports to the actual implementation address.
///
/// # Arguments
/// 
/// * `module` - Name of the current module performing the resolution
/// * `address` - Address returned from the export table
/// * `export_dir` - Pointer to the module's IMAGE_EXPORT_DIRECTORY
/// * `export_size` - Size of the export directory
/// * `hash` - Function to hash names (used for recursive resolution)
///
/// # Returns
/// 
/// * Resolved address or original address if not a forwarder.
fn get_forwarded_address(
    module: &str,
    address: *mut c_void,
    export_dir: *const IMAGE_EXPORT_DIRECTORY,
    export_size: usize,
    hash: fn(&str) -> u32,
) -> *mut c_void {
    // Detect if the address is a forwarder RVA
    if (address as usize) >= export_dir as usize &&
       (address as usize) < (export_dir as usize + export_size)
    {
        let cstr = unsafe { CStr::from_ptr(address as *const i8) };
        let forwarder = cstr.to_str().unwrap_or_default();
        let (module_name, function_name) = forwarder.split_once('.')
            .unwrap_or(("", ""));

        // If forwarder is of type api-ms-* or ext-ms-*
        let module_resolved = if module_name.starts_with(s!("api-ms")) || module_name.starts_with(s!("ext-ms")) {
            let base_contract = module_name.rsplit_once('-').map(|(b, _)| b).unwrap_or(module_name);
            resolve_api_set_map(module, base_contract)
        } else {
            Some(vec![format!("{}.dll", module_name)])
        };

        // Try resolving the symbol from all resolved modules
        if let Some(modules) = module_resolved {
            for module in modules {
                let mut addr = GetModuleHandle(module.as_str(), None);
                if addr.is_null() {
                    addr = LoadLibraryA(module.as_str());
                }

                if !addr.is_null() {
                    let resolved = GetProcAddress(addr, hash(function_name), Some(hash));
                    if !resolved.is_null() {
                        return resolved;
                    }
                }
            }
        }
    }

    address
}

/// Resolves ApiSet contracts to the actual implementing DLLs.
///
/// This parses the ApiSetMap from the PEB and returns all possible DLLs,
/// excluding the current module itself if `ValueCount > 1`.
///
/// # Arguments
/// 
/// * `host_name` - Name of the module currently resolving (to avoid loops)
/// * `contract_name` - Base contract name (e.g., `api-ms-win-core-processthreads`)
///
/// # Returns
/// 
/// * A list of DLL names that implement the contract, or `None` if not found.
fn resolve_api_set_map(
    host_name: &str,
    contract_name: &str
) -> Option<Vec<String>> {
    unsafe {
        let peb = NtCurrentPeb();
        let map = (*peb).ApiSetMap;
        
        // Base pointer for the namespace entry array
        let ns_entry = ((*map).EntryOffset as usize + map as usize) as *const API_SET_NAMESPACE_ENTRY;
        let ns_entries = from_raw_parts(ns_entry, (*map).Count as usize);

        for entry in ns_entries {
            let name = String::from_utf16_lossy(from_raw_parts(
                (map as usize + entry.NameOffset as usize) as *const u16,
                entry.NameLength as usize / 2,
            ));

            if name.starts_with(contract_name) {
                let values = from_raw_parts(
                    (map as usize + entry.ValueOffset as usize) as *const API_SET_VALUE_ENTRY, 
                    entry.ValueCount as usize
                );

                // Only one value: direct forward
                if values.len() == 1 {
                    let val = &values[0];
                    let dll = String::from_utf16_lossy(from_raw_parts(
                        (map as usize + val.ValueOffset as usize) as *const u16,
                        val.ValueLength as usize / 2,
                    ));

                    return Some(vec![dll]);
                }
                
                // Multiple values: skip the host DLL to avoid self-resolving
                let mut result = Vec::new();
                for val in values {
                    let name = String::from_utf16_lossy(from_raw_parts(
                        (map as usize + val.ValueOffset as usize) as *const u16,
                        val.ValueLength as usize / 2,
                    ));

                    if !name.eq_ignore_ascii_case(host_name) {
                        let dll = String::from_utf16_lossy(from_raw_parts(
                            (map as usize + val.ValueOffset as usize) as *const u16,
                            val.ValueLength as usize / 2,
                        ));
   
                        result.push(dll);
                    }
                }
                
                if !result.is_empty() {
                    return Some(result);
                }
            }
        }
    }

    None
}

/// Returns the module name in uppercase without path or ".DLL" suffix.
fn canonicalize_module(name: &str) -> String {
    let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let upper = file.to_ascii_uppercase();
    upper.trim_end_matches(".DLL").to_string()
}