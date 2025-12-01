//! Internal helper module 

use alloc::collections::BTreeMap;
use core::{ffi::{c_void, CStr}, slice::from_raw_parts};

use crate::types::*;

/// Maps exported function addresses to their respective names.
pub type Functions<'a> = BTreeMap<usize, &'a str>;

/// Portable Executable (PE) abstraction over a module's in-memory image.
#[derive(Debug)]
pub struct PE {
    /// Base address of the loaded module.
    pub base: *mut c_void,
}

impl PE {
    /// Creates a new `PE` instance from a module base.
    #[inline]
    pub fn parse(base: *mut c_void) -> Self {
        Self { base }
    }

    /// Returns the DOS header of the module.
    #[inline]
    pub fn dos_header(&self) -> *const IMAGE_DOS_HEADER {
        self.base as *const IMAGE_DOS_HEADER
    }

    /// Returns a pointer to the `IMAGE_NT_HEADERS`, if valid.
    #[inline]
    pub fn nt_header(&self) -> Option<*const IMAGE_NT_HEADERS> {
        unsafe {
            let dos = self.base as *const IMAGE_DOS_HEADER;
            let nt = (self.base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

            if (*nt).Signature == IMAGE_NT_SIGNATURE {
                Some(nt)
            } else {
                None
            }
        }
    }

    /// Returns all section headers in the PE.
    pub fn sections(&self) -> Option<&[IMAGE_SECTION_HEADER]> {
        unsafe {
            let nt = self.nt_header()?;
            let first_section = (nt as *const u8)
                .add(size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
            Some(from_raw_parts(first_section, (*nt).FileHeader.NumberOfSections as usize))
        }
    }

    /// Finds the name of the section containing a specific RVA.
    pub fn section_name_by_rva(&self, rva: u32) -> Option<&str> {
        self.sections()?.iter().find_map(|sec| {
            let start = sec.VirtualAddress;
            let end = start + unsafe { sec.Misc.VirtualSize };
            if rva >= start && rva < end {
                let name = unsafe { core::str::from_utf8_unchecked(&sec.Name[..]) };
                Some(name.trim_end_matches('\0'))
            } else {
                None
            }
        })
    }

    /// Finds a section by its name.
    pub fn section_by_name(&self, name: &str) -> Option<&IMAGE_SECTION_HEADER> {
        self.sections()?.iter().find(|sec| {
            let raw_name = unsafe { core::str::from_utf8_unchecked(&sec.Name) };
            raw_name.trim_end_matches('\0') == name
        })
    }

    /// Exports helper
    #[inline]
    pub fn exports(&self) -> Exports<'_> {
        Exports { pe: self }
    }
}

/// Provides access to the export table of a PE image.
#[derive(Debug)]
pub struct Exports<'a> {
    /// Reference to the parsed PE image.
    pub pe: &'a PE,
}

impl<'a> Exports<'a> {
    /// Returns a pointer to the `IMAGE_EXPORT_DIRECTORY`, if present.
    pub fn directory(&self) -> Option<*const IMAGE_EXPORT_DIRECTORY> {
        unsafe {
            let nt = self.pe.nt_header()?;
            let dir = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

            if dir.VirtualAddress == 0 {
                return None;
            }

            Some((self.pe.base as usize + dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY)
        }
    }

    /// Returns a map of exported function addresses and their names.
    pub fn functions(&self) -> Option<Functions<'a>> {
        unsafe {
            let base = self.pe.base as usize;
            let dir = self.directory()?;

            let names = from_raw_parts(
                (base + (*dir).AddressOfNames as usize) as *const u32,
                (*dir).NumberOfNames as usize,
            );

            let funcs = from_raw_parts(
                (base + (*dir).AddressOfFunctions as usize) as *const u32,
                (*dir).NumberOfFunctions as usize,
            );

            let ords = from_raw_parts(
                (base + (*dir).AddressOfNameOrdinals as usize) as *const u16,
                (*dir).NumberOfNames as usize,
            );

            let mut map = BTreeMap::new();
            for i in 0..(*dir).NumberOfNames as usize {
                let ordinal = ords[i] as usize;
                let addr = base + funcs[ordinal] as usize;
                let name_ptr = (base + names[i] as usize) as *const i8;

                let name = CStr::from_ptr(name_ptr).to_str().unwrap_or("");
                map.insert(addr, name);
            }

            Some(map)
        }
    }
}
