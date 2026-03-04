use core::ptr::null_mut;
use core::slice::from_raw_parts;
use core::ffi::{c_void, CStr};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::{String, ToString};

use windows_sys::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;
use phnt::ffi::{
    API_SET_NAMESPACE_ENTRY, API_SET_VALUE_ENTRY,
    LDR_DATA_TABLE_ENTRY, LIST_ENTRY
};

use crate::link;
use crate::pe::PeImage;
use crate::env::nt_current_peb;

/// A handle to a loaded Windows module.
///
/// Wraps a module base address and provides methods for resolving exports.
/// Created via [`Module::find`] or [`Module::from_ptr`].
///
/// # Examples
///
/// ```no_run
/// use dinvk::Module;
///
/// let kernel32 = Module::find("kernel32.dll").unwrap();
/// let virtual_alloc = kernel32.proc("VirtualAlloc").unwrap();
/// ```
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Module(*mut c_void);

impl Module {
    /// Finds a loaded module by name.
    pub fn find(name: &str) -> Option<Self> {
        let base = find_module_by_name(name);
        if base.is_null() {
            None
        } else {
            Some(Self(base))
        }
    }

    /// Finds a loaded module by hash.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dinvk::Module;
    /// # use dinvk::hash::murmur3;
    ///
    /// // NTDLL.DLL hash
    /// let ntdll = Module::find_by_hash(2788516083, murmur3);
    /// ```
    pub fn find_by_hash(hash: u32, hash_fn: fn(&str) -> u32) -> Option<Self> {
        let base = find_module_by_hash(hash, hash_fn);
        if base.is_null() {
            None
        } else {
            Some(Self(base))
        }
    }

    /// Creates a Module from an existing base address.
    ///
    /// Use this when you already have a module handle from another source,
    /// like `GetModuleHandle` or a previous lookup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dinvk::Module;
    ///
    /// let base = 0x7fff00000000 as *mut _;
    /// let module = Module::from_ptr(base);
    /// ```
    pub fn from_ptr(base: *mut c_void) -> Option<Self> {
        if base.is_null() {
            None
        } else {
            Some(Self(base))
        }
    }

    /// Returns the current process executable.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dinvk::Module;
    ///
    /// let exe = Module::current().unwrap();
    /// println!("Base: {:?}", exe.base());
    /// ```
    pub fn current() -> Option<Self> {
        let peb = nt_current_peb();
        let base = unsafe { (*peb).ImageBaseAddress };
        Self::from_ptr(base)
    }

    /// Returns the module base address.
    pub fn base(&self) -> *mut c_void {
        self.0
    }
    
    /// Resolves an export by name.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dinvk::Module;
    ///
    /// let func = Module::find("kernel32.dll")
    ///     .and_then(|m| m.proc("VirtualAlloc"));
    /// ```
    pub fn proc(&self, name: &str) -> Option<*mut c_void> {
        let addr = self.resolve_export(ExportLookup::Name(name));
        if addr.is_null() {
            None
        } else {
            Some(addr)
        }
    }

    /// Resolves an export by hash.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dinvk::Module;
    /// # use dinvk::hash::jenkins;
    ///
    /// let func = Module::find("kernel32.dll")
    ///     .and_then(|m| m.proc_by_hash(0xDEADBEEF, jenkins));
    /// ```
    pub fn proc_by_hash(&self, hash: u32, hash_fn: fn(&str) -> u32) -> Option<*mut c_void> {
        let addr = self.resolve_export(ExportLookup::Hash(hash, hash_fn));
        if addr.is_null() {
            None
        } else {
            Some(addr)
        }
    }

    /// Resolves an export by ordinal.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dinvk::Module;
    ///
    /// let func = Module::find("kernel32.dll")
    ///     .and_then(|m| m.proc_by_ordinal(997));
    /// ```
    pub fn proc_by_ordinal(&self, ordinal: u16) -> Option<*mut c_void> {
        let addr = self.resolve_export(ExportLookup::Ordinal(ordinal));
        if addr.is_null() { 
            None 
        } else { 
            Some(addr) 
        }
    }

    /// Internal export resolution handling all lookup types.
    fn resolve_export(&self, lookup: ExportLookup) -> *mut c_void {
        let pe = PeImage::parse(self.0);
        let base = self.0 as usize;

        // Get export data from PE
        let Some(exp) = pe.exports().data() else {
            return null_mut();
        };

        // Handle ordinal lookup
        if let ExportLookup::Ordinal(ordinal) = lookup {
            let ordinal = ordinal as u32;
            if ordinal < exp.base_ordinal || ordinal >= exp.base_ordinal + exp.num_functions {
                return null_mut();
            }
            let idx = (ordinal - exp.base_ordinal) as usize;
            return (base + exp.addresses[idx] as usize) as *mut c_void;
        }

        // Search by name or hash
        for i in 0..exp.names.len() {
            let name = unsafe {
                CStr::from_ptr((base + exp.names[i] as usize) as *const i8)
                    .to_str()
                    .unwrap_or("")
            };

            let matched = match lookup {
                ExportLookup::Name(target) => name == target,
                ExportLookup::Hash(target, hash_fn) => hash_fn(name) == target,
                ExportLookup::Ordinal(_) => unreachable!(),
            };

            if matched {
                let ordinal = exp.ordinals[i] as usize;
                let address = (base + exp.addresses[ordinal] as usize) as *mut c_void;
                return self.resolve_forward(exp.dll_name, address, exp.directory, exp.size);
            }
        }

        null_mut()
    }

    /// Handles forwarded exports.
    ///
    /// Forwarded exports point to implementations in other DLLs. The forwarder
    /// string format is "MODULE.FunctionName". ApiSet contracts (api-ms-*, ext-ms-*)
    /// are resolved through the PEB ApiSetMap.
    fn resolve_forward(
        &self,
        host_module: &str,
        address: *mut c_void,
        export_dir: *const IMAGE_EXPORT_DIRECTORY,
        export_size: usize,
    ) -> *mut c_void {
        // Check if address is within the export directory (indicates forwarder)
        let addr = address as usize;
        let dir_start = export_dir as usize;
        let dir_end = dir_start + export_size;
        if addr < dir_start || addr >= dir_end {
            return address;
        }

        let forwarder = unsafe {
            CStr::from_ptr(address as *const i8)
                .to_str()
                .unwrap_or_default()
        };

        let Some((module_name, function_name)) = forwarder.split_once('.') else {
            return address;
        };

        // Resolve ApiSet contracts
        let target_modules = if module_name.starts_with("api-ms") || module_name.starts_with("ext-ms") {
            let contract = module_name.rsplit_once('-').map(|(b, _)| b).unwrap_or(module_name);
            resolve_api_set(host_module, contract)
        } else {
            Some(vec![format!("{}.dll", module_name)])
        };

        // Try each resolved module
        let Some(modules) = target_modules else {
            return address;
        };

        for module in modules {
            let target = Module::find(&module)
                .or_else(|| {
                    let cstr = format!("{module}\0");
                    let ptr = unsafe { load_library_a(cstr.as_ptr()).ok()? };
                    Module::from_ptr(ptr)
                });

            if let Some(m) = target {
                if let Some(resolved) = m.proc(function_name) {
                    return resolved;
                }
            }
        }

        address
    }
}

impl core::fmt::Debug for Module {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Module")
            .field("base", &self.0)
            .finish()
    }
}

impl From<Module> for *mut c_void {
    fn from(m: Module) -> Self {
        m.0
    }
}

impl From<&Module> for *mut c_void {
    fn from(m: &Module) -> Self {
        m.0
    }
}

/// Export lookup type for internal dispatch.
enum ExportLookup<'a> {
    Name(&'a str),
    Hash(u32, fn(&str) -> u32),
    Ordinal(u16),
}

/// Finds a module by name walking the PEB loader list.
fn find_module_by_name(name: &str) -> *mut c_void {
    let peb = nt_current_peb();
    if name.is_empty() {
        return unsafe { (*peb).ImageBaseAddress };
    }

    let target = canonicalize_name(name);
    unsafe {
        let ldr = (*peb).Ldr;
        let head = &(*ldr).InMemoryOrderModuleList as *const LIST_ENTRY;
        let mut current = (*head).Flink as *const LIST_ENTRY;

        while current != head {
            let entry = (current as *const u8)
                .sub(core::mem::offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks))
                as *const LDR_DATA_TABLE_ENTRY;

            if !(*entry).BaseDllName.is_empty() {
                let dll_name = (*entry).BaseDllName.to_string();
                if canonicalize_name(&dll_name) == target {
                    return (*entry).DllBase;
                }
            }

            current = (*current).Flink;
        }
    }

    null_mut()
}

/// Finds a module by hash walking the PEB loader list.
fn find_module_by_hash(hash: u32, hash_fn: fn(&str) -> u32) -> *mut c_void {
    unsafe {
        let peb = nt_current_peb();
        let ldr = (*peb).Ldr;
        let head = &(*ldr).InMemoryOrderModuleList as *const LIST_ENTRY;
        let mut current = (*head).Flink as *const LIST_ENTRY;

        while current != head {
            let entry = (current as *const u8)
                .sub(core::mem::offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks))
                as *const LDR_DATA_TABLE_ENTRY;

            if !(*entry).BaseDllName.is_empty() {
                let dll_name = (*entry).BaseDllName.to_string().to_uppercase();
                if hash_fn(&dll_name) == hash {
                    return (*entry).DllBase;
                }
            }

            current = (*current).Flink;
        }
    }

    null_mut()
}

/// Resolves an ApiSet contract to implementing DLLs.
fn resolve_api_set(host: &str, contract: &str) -> Option<Vec<String>> {
    unsafe {
        let peb = nt_current_peb();
        let map = (*peb).ApiSetMap;

        let entries = from_raw_parts(
            (map as usize + (*map).EntryOffset as usize) as *const API_SET_NAMESPACE_ENTRY,
            (*map).Count as usize,
        );

        for entry in entries {
            let name = String::from_utf16_lossy(from_raw_parts(
                (map as usize + entry.NameOffset as usize) as *const u16,
                entry.NameLength as usize / 2,
            ));

            if !name.starts_with(contract) {
                continue;
            }

            let values = from_raw_parts(
                (map as usize + entry.ValueOffset as usize) as *const API_SET_VALUE_ENTRY,
                entry.ValueCount as usize,
            );

            // Single value: direct mapping
            if values.len() == 1 {
                let dll = String::from_utf16_lossy(from_raw_parts(
                    (map as usize + values[0].ValueOffset as usize) as *const u16,
                    values[0].ValueLength as usize / 2,
                ));
                return Some(vec![dll]);
            }

            // Multiple values: exclude host to avoid circular resolution
            let mut result = Vec::new();
            for val in values {
                let dll = String::from_utf16_lossy(from_raw_parts(
                    (map as usize + val.ValueOffset as usize) as *const u16,
                    val.ValueLength as usize / 2,
                ));

                if !dll.eq_ignore_ascii_case(host) {
                    result.push(dll);
                }
            }

            if !result.is_empty() {
                return Some(result);
            }
        }
    }

    None
}

/// Normalizes a module name for comparison.
fn canonicalize_name(name: &str) -> String {
    name.rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_uppercase()
        .trim_end_matches(".DLL")
        .to_string()
}

link!(
    find_module_by_name("KERNEL32.DLL"),
    "LoadLibraryA",
    fn load_library_a(name: *const u8) -> *mut c_void
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_case_insensitive() {
        assert!(Module::find("kernel32.dll").is_some());
        assert!(Module::find("KERNEL32.DLL").is_some());
        assert!(Module::find("Kernel32").is_some());
        assert!(Module::find("KERNEL32").is_some());
    }

    #[test]
    fn resolve_proc_by_name() {
        let func = Module::find("kernel32.dll")
            .and_then(|m| m.proc("VirtualAlloc"));
        assert!(func.is_some());
    }

    #[test]
    fn resolve_forwarded_export() {
        // These are forwarded in kernel32
        let k32 = Module::find("kernel32.dll").unwrap();
        assert!(k32.proc("SetIoRingCompletionEvent").is_some());
        assert!(k32.proc("SetProtectedPolicy").is_some());
    }
}
