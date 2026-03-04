use core::ffi::{c_void, CStr};
use core::slice::from_raw_parts;

use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, 
    IMAGE_NT_SIGNATURE,
};

#[cfg(target_pointer_width = "64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
#[cfg(target_pointer_width = "32")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;

/// PE image parsed from memory.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PeImage(*mut c_void);

impl PeImage {
    /// Parses a PE from a module base address.
    pub fn parse(base: *mut c_void) -> Self {
        Self(base)
    }

    /// Returns the NT headers if the signature is valid.
    pub fn nt_header(&self) -> Option<*const IMAGE_NT_HEADERS> {
        unsafe {
            let dos = self.0 as *const IMAGE_DOS_HEADER;
            let nt = (self.0 as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

            if (*nt).Signature == IMAGE_NT_SIGNATURE {
                Some(nt)
            } else {
                None
            }
        }
    }

    /// Returns an export table accessor.
    pub fn exports(&self) -> Exports<'_> {
        Exports { pe: self }
    }
}

/// Export table accessor.
#[derive(Debug)]
pub struct Exports<'a> {
    pe: &'a PeImage,
}

impl<'a> Exports<'a> {
    /// Returns the export directory pointer.
    pub fn directory(&self) -> Option<*const IMAGE_EXPORT_DIRECTORY> {
        unsafe {
            let nt = self.pe.nt_header()?;
            let dir = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
            if dir.VirtualAddress == 0 {
                return None;
            }

            Some((self.pe.0 as usize + dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY)
        }
    }

    /// Returns all export data in a single struct.
    pub fn data(&self) -> Option<ExportData<'a>> {
        let base = self.pe.0 as usize;
        let nt = self.pe.nt_header()?;
        let dir = self.directory()?;

        unsafe {
            let size = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
                .Size as usize;

            Some(ExportData {
                names: from_raw_parts(
                    (base + (*dir).AddressOfNames as usize) as *const u32,
                    (*dir).NumberOfNames as usize,
                ),
                addresses: from_raw_parts(
                    (base + (*dir).AddressOfFunctions as usize) as *const u32,
                    (*dir).NumberOfFunctions as usize,
                ),
                ordinals: from_raw_parts(
                    (base + (*dir).AddressOfNameOrdinals as usize) as *const u16,
                    (*dir).NumberOfNames as usize,
                ),
                size,
                directory: dir,
                dll_name: CStr::from_ptr((base + (*dir).Name as usize) as *const i8)
                    .to_str()
                    .unwrap_or(""),
                base_ordinal: (*dir).Base,
                num_functions: (*dir).NumberOfFunctions,
            })
        }
    }
}

/// Export table data extracted from PE.
pub struct ExportData<'a> {
    /// RVAs to export name strings.
    pub names: &'a [u32],
    /// RVAs to export addresses.
    pub addresses: &'a [u32],
    /// Ordinal values for each named export.
    pub ordinals: &'a [u16],
    /// Size of the export directory.
    pub size: usize,
    /// Pointer to export directory.
    pub directory: *const IMAGE_EXPORT_DIRECTORY,
    /// DLL name from export directory.
    pub dll_name: &'a str,
    /// Base ordinal value.
    pub base_ordinal: u32,
    /// Total number of exported functions.
    pub num_functions: u32,
}
