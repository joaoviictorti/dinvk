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
    /// XOR key used for static string obfuscation.
    const XOR_KEY: u8 = 0x55;

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

    /// Returns the function name associated with the selected DLL, if applicable.
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

    /// Returns a precomputed hash of the DLL name itself.
    pub fn hash(&self) -> u32 {
        match self {
            Dll::Ntdll => 4_168_839_019,
            Dll::Win32u => 1_292_941_823,
            #[cfg(target_arch = "x86_64")]
            Dll::Iumdll => 1_162_714_123,
            #[cfg(target_arch = "x86_64")]
            Dll::Vertdll => 218_821_999,
        }
    }

    /// Returns the DLL name as a null-terminated string (decoded from XOR obfuscation).
    pub fn name(&self) -> &'static str {
        match self {
            Dll::Ntdll => decode(&[
                b'n' ^ Self::XOR_KEY,
                b't' ^ Self::XOR_KEY,
                b'd' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'.' ^ Self::XOR_KEY,
                b'd' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
            ]),
            Dll::Win32u => decode(&[
                b'w' ^ Self::XOR_KEY,
                b'i' ^ Self::XOR_KEY,
                b'n' ^ Self::XOR_KEY,
                b'3' ^ Self::XOR_KEY,
                b'2' ^ Self::XOR_KEY,
                b'u' ^ Self::XOR_KEY,
                b'.' ^ Self::XOR_KEY,
                b'd' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
            ]),
            #[cfg(target_arch = "x86_64")]
            Dll::Iumdll => decode(&[
                b'i' ^ Self::XOR_KEY,
                b'u' ^ Self::XOR_KEY,
                b'm' ^ Self::XOR_KEY,
                b'd' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'.' ^ Self::XOR_KEY,
                b'd' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
            ]),
            #[cfg(target_arch = "x86_64")]
            Dll::Vertdll => decode(&[
                b'v' ^ Self::XOR_KEY,
                b'e' ^ Self::XOR_KEY,
                b'r' ^ Self::XOR_KEY,
                b't' ^ Self::XOR_KEY,
                b'd' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'.' ^ Self::XOR_KEY,
                b'd' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
                b'l' ^ Self::XOR_KEY,
            ]),
        }
    }
}

/// Decodes a DLL name from a XOR-obfuscated byte array.
///
/// This is used to avoid embedding literal DLL names in the binary.
fn decode(input: &[u8]) -> &'static str {
    const MAX: usize = 12;
    static mut DECODED: [u8; MAX] = [0; MAX];
    let len = input.len();

    for i in 0..len {
        unsafe { DECODED[i] = input[i] ^ Dll::XOR_KEY };
    }

    unsafe { core::str::from_utf8_unchecked(&DECODED[..len]) }
}