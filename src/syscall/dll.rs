// Copyright (c) 2025 joaoviictorti
// Licensed under the MIT License. See LICENSE file in the project root for details.

use core::{sync::atomic::{AtomicUsize, Ordering}};

/// The global variable that stores the currently selected DLL for system calls.
static DEFAULT_DLL: AtomicUsize = AtomicUsize::new(Dll::Ntdll as usize);

/// Represents different dynamic link libraries (DLLs) that contain system call functions.
#[derive(Clone, Copy, PartialEq)]
pub enum Dll {
    /// `iumdll.dll`
    #[cfg(target_arch = "x86_64")]
    Iumdll,

    /// `vertdll.dll`
    #[cfg(target_arch = "x86_64")]
    Vertdll,

    /// `win32u.dll`
    Win32u,

    /// `ntdll.dll`
    Ntdll,
}

impl Dll {
    /// Sets the default DLL to be used for system calls.
    ///
    /// # Arguments
    ///
    /// * `dll` - The [`Dll`] variant to use as the new default.
    pub fn use_dll(dll: Dll) {
        DEFAULT_DLL.store(dll as usize, Ordering::Relaxed);
    }

    /// Retrieves the currently selected DLL for system calls.
    pub fn current() -> Dll {
        match DEFAULT_DLL.load(Ordering::Relaxed) {
            #[cfg(target_arch = "x86_64")]
            x if x == Dll::Iumdll as usize => Dll::Iumdll,
            #[cfg(target_arch = "x86_64")]
            x if x == Dll::Vertdll as usize => Dll::Vertdll,
            x if x == Dll::Win32u as usize => Dll::Win32u,
            _ => Dll::Ntdll,
        }
    }

    /// Returns the DLL name.
    pub fn name(&self) -> &'static str {
        match self {
            Dll::Ntdll => "ntdll.dll",
            Dll::Win32u => "win32u.dll",
            #[cfg(target_arch = "x86_64")]
            Dll::Iumdll => "iumdll.dll",
            #[cfg(target_arch = "x86_64")]
            Dll::Vertdll => "vertdll.dll",
        }
    }

    /// Returns the function name associated with the selected DLL.
    pub fn function_hash(&self) -> u32 {
        match self {
            Dll::Ntdll => 0,
            Dll::Win32u => 2_604_093_150,
            #[cfg(target_arch = "x86_64")]
            Dll::Iumdll => 75_139_374,
            #[cfg(target_arch = "x86_64")]
            Dll::Vertdll => 2_237_456_582,
        }
    }
}
