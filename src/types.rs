//! Structures and types used across the library.

use core::ffi::c_void;
use core::ptr::null_mut;
use bitflags::bitflags;

pub const IMAGE_NT_SIGNATURE: u32 = 17744u32;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: IMAGE_DIRECTORY_ENTRY = 0u16;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const EXCEPTION_SINGLE_STEP: i32 = 0x80000004_u32 as _;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const CONTEXT_DEBUG_REGISTERS_AMD64: u32 = 1048592u32;
pub const CONTEXT_DEBUG_REGISTERS_X86: u32 = 65552u32;
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;
pub const SYNCHRONIZE: u32 = 0x00100000;
pub const EVENT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3;
pub const WT_EXECUTEONLYONCE: u32 = 0x00000008;
pub const WT_EXECUTEINWAITTHREAD: u32 = 0x00000004;
pub const WT_EXECUTEINTIMERTHREAD: u32 = 0x00000020;
pub const STATUS_UNSUCCESSFUL: i32 = 0xC0000001_u32 as _;

pub type GDI_HANDLE_BUFFER = [u32; 34];
pub type WORKERCALLBACKFUNC = unsafe extern "system" fn(param: *mut c_void);
pub type IMAGE_FILE_MACHINE = u16;
pub type IMAGE_FILE_CHARACTERISTICS = u16;
pub type IMAGE_OPTIONAL_HEADER_MAGIC = u16;
pub type IMAGE_SUBSYSTEM = u16;
pub type IMAGE_DLL_CHARACTERISTICS = u16;
pub type IMAGE_DIRECTORY_ENTRY = u16;
pub type NTSTATUS = i32;
pub type HANDLE = *mut c_void;
pub type HEAP_FLAGS = u32;
pub type WAITORTIMERCALLBACKFUNC = unsafe extern "system" fn(*mut c_void, u8);
pub type HMODULE = *mut c_void;
pub type PVECTORED_EXCEPTION_HANDLER = Option<unsafe extern "system" fn(exceptioninfo: *mut EXCEPTION_POINTERS) -> i32>;
pub type PPS_POST_PROCESS_INIT_ROUTINE = unsafe extern "system" fn();
pub type LoadLibraryAFn = unsafe extern "system" fn(fnlpLibFileName: *const u8) -> *mut c_void;
pub type RemoveVectoredExceptionHandlerFn = unsafe extern "system" fn(handle: *mut c_void) -> u32;
pub type NtGetThreadContextFn = unsafe extern "system" fn(hthread: HANDLE, lpcontext: *mut CONTEXT) -> i32;
pub type NtSetThreadContextFn = unsafe extern "system" fn(hthread: HANDLE, lpcontext: *const CONTEXT) -> i32;
pub type RtlCaptureContextFn = unsafe extern "system" fn(contextrecord: *mut CONTEXT);
pub type RtlCreateTimerQueueFn = unsafe extern "system" fn(TimerQueueHandle: *mut HANDLE) -> NTSTATUS;
pub type HeapAllocFn = unsafe extern "system" fn(hheap: HANDLE, dwflags: HEAP_FLAGS, dwbytes: usize) -> *mut c_void;
pub type HeapFreeFn = unsafe extern "system" fn(hheap: HANDLE, dwflags: HEAP_FLAGS, lpmem: *const c_void) -> *mut c_void;
pub type HeapCreateFn = unsafe extern "system" fn(floptions: HEAP_FLAGS, dwinitialsize: usize, dwmaximumsize: usize) -> *mut c_void;
pub type AddVectoredExceptionHandlerFn = unsafe extern "system" fn(first: u32, handler: PVECTORED_EXCEPTION_HANDLER) -> *mut c_void;
pub type OutputDebugStringAFn = unsafe extern "system" fn(lpOutputString: *const u8);
pub type GetStdHandleFn = unsafe extern "system" fn(nStdHandle: u32) -> HANDLE;
pub type RtlAllocateHeapFn = unsafe extern "system" fn(heap: HANDLE, flags: u32, size: usize) -> *mut c_void;
pub type RtlFreeHeapFn = unsafe extern "system" fn(heap: HANDLE, flags: u32, ptr: *mut c_void) -> i8;
pub type RtlDestroyHeapFn = unsafe extern "system" fn(heap: *mut c_void) -> i8;
pub type RtlCreateHeapFn = unsafe extern "system" fn(
    flags: u32, 
    base: *mut c_void, 
    reserve: usize, 
    commit: usize, 
    lock: *mut c_void, 
    param: *mut c_void
) -> HANDLE;

pub type WriteConsoleAFn = unsafe extern "system" fn(
    hConsoleOutput: HANDLE, 
    lpBuffer: *const u8, 
    nNumberOfCharsToWrite: u32, 
    lpNumberOfCharsWritten: *mut u32, 
    lpReserved: *mut c_void
);

pub type NtCreateEventFn = unsafe extern "system" fn(
    EventHandle: *mut HANDLE,
    DesiredAccess: u32, 
    ObjectAttribute: *mut OBJECT_ATTRIBUTES, 
    EventType: EVENT_TYPE, 
    InitialState: u8
) -> NTSTATUS;

pub type RtlRegisterWaitFn = unsafe extern "system" fn(
    WaitHandle: *mut HANDLE,
    Handle: HANDLE,
    Function: *mut c_void,
    Context: *mut c_void,
    Milliseconds: u32,
    Flags: u32
) -> NTSTATUS;

pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> NTSTATUS;

pub type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> NTSTATUS;

pub type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut c_void,
    Buffer: *mut c_void,
    NumberOfBytesToWrite: usize,
    NumberOfBytesWritten: *mut usize,
) -> NTSTATUS;

pub type NtCreateThreadExFn = unsafe extern "system" fn(
    ThreadHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ProcessHandle: HANDLE,
    StartRoutine: *mut c_void,
    Argument: *mut c_void,
    CreateFlags: u32,
    ZeroBits: usize,
    StackSize: usize,
    MaximumStackSize: usize,
    AttributeList: *mut PS_ATTRIBUTE_LIST
) -> NTSTATUS;

pub type RtlQueueWorkItemFn = unsafe extern "system" fn(
    Function: WORKERCALLBACKFUNC,
    Context: *mut c_void,
    Flags: u32
) -> NTSTATUS;

pub type RtlCreateTimerFn = unsafe extern "system" fn(
    TimerQueueHandle: HANDLE,
    Handle: *mut HANDLE,
    Function: WAITORTIMERCALLBACKFUNC,
    Context: *mut c_void,
    DueTime: u32,
    Period: u32,
    Flags: u32
) -> NTSTATUS;

#[repr(C)]
pub enum EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
}


#[repr(C)]
#[derive(Clone, Copy)]
pub struct API_SET_HASH_ENTRY {
	Hash: u32,
	Index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct API_SET_NAMESPACE_ENTRY {
	pub Flags: u32,
	pub NameOffset: u32,
	pub NameLength: u32,
	pub HashedLength: u32,
	pub ValueOffset: u32,
	pub ValueCount: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct API_SET_VALUE_ENTRY {
	pub Flags: u32,
	pub NameOffset: u32,
	pub NameLength: u32,
	pub ValueOffset: u32,
	pub ValueLength: u32
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub struct IMAGE_NT_HEADERS {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(target_arch = "x86")]
pub struct IMAGE_NT_HEADERS {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

/// CONTEXT structure representing ARM64
#[repr(C)]
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub struct CONTEXT {
    pub ContextFlags: u32,
    pub Cpsr: u32,
    pub Anonymous: CONTEXT_0,
    pub Sp: u64,
    pub Pc: u64,
    pub V: [ARM64_NT_NEON128; 32],
    pub Fpcr: u32,
    pub Fpsr: u32,
    pub Bcr: [u32; 8],
    pub Bvr: [u64; 8],
    pub Wcr: [u32; 2],
    pub Wvr: [u64; 2],
}

#[repr(C)]
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub union CONTEXT_0 {
    pub Anonymous: CONTEXT_0_0,
    pub X: [u64; 31],
}

#[repr(C)]
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub struct CONTEXT_0_0 {
    pub X0: u64,
    pub X1: u64,
    pub X2: u64,
    pub X3: u64,
    pub X4: u64,
    pub X5: u64,
    pub X6: u64,
    pub X7: u64,
    pub X8: u64,
    pub X9: u64,
    pub X10: u64,
    pub X11: u64,
    pub X12: u64,
    pub X13: u64,
    pub X14: u64,
    pub X15: u64,
    pub X16: u64,
    pub X17: u64,
    pub X18: u64,
    pub X19: u64,
    pub X20: u64,
    pub X21: u64,
    pub X22: u64,
    pub X23: u64,
    pub X24: u64,
    pub X25: u64,
    pub X26: u64,
    pub X27: u64,
    pub X28: u64,
    pub Fp: u64,
    pub Lr: u64,
}

#[repr(C)]
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub union ARM64_NT_NEON128 {
    pub Anonymous: ARM64_NT_NEON128_0,
    pub D: [f64; 2],
    pub S: [f32; 4],
    pub H: [u16; 8],
    pub B: [u8; 16],
}

#[repr(C)]
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ARM64_NT_NEON128_0 {
    pub Low: u64,
    pub High: i64,
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy)]
#[cfg(target_arch = "x86_64")]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: CONTEXT_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

/// CONTEXT structure representing x86
#[derive(Debug)]
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct CONTEXT {
    pub ContextFlags: u32,
    pub Dr0: u32,
    pub Dr1: u32,
    pub Dr2: u32,
    pub Dr3: u32,
    pub Dr6: u32,
    pub Dr7: u32,
    pub ControlWord: u32,
    pub StatusWord: u32,
    pub TagWord: u32,
    pub ErrorOffset: u32,
    pub ErrorSelector: u32,
    pub DataOffset: u32,
    pub DataSelector: u32,
    pub RegisterArea: [u8; 80],
    pub Spare0: u32,
    pub SegGs: u32,
    pub SegFs: u32,
    pub SegEs: u32,
    pub SegDs: u32,
    pub Edi: u32,
    pub Esi: u32,
    pub Ebx: u32,
    pub Edx: u32,
    pub Ecx: u32,
    pub Eax: u32,
    pub Ebp: u32,
    pub Eip: u32,
    pub SegCs: u32,
    pub EFlags: u32,
    pub Esp: u32,
    pub SegSs: u32,
    pub ExtendedRegisters: [u8; 512]
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(target_arch = "x86_64")]
pub union CONTEXT_0 {
    pub FltSave: XSAVE_FORMAT,
    pub Anonymous: CONTEXT_0_0,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(target_arch = "x86_64")]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(target_arch = "x86_64")]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(target_arch = "x86_64")]
pub struct CONTEXT_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

impl Default for CONTEXT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl Default for CONTEXT_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(target_arch = "x86_64")]
impl Default for XSAVE_FORMAT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(target_arch = "x86_64")]
impl Default for M128A {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl Default for CONTEXT_0_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut CONTEXT,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: NTSTATUS,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: *mut c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

impl Default for OBJECT_ATTRIBUTES {
    fn default() -> Self {
        Self { 
            Length: Default::default(), 
            RootDirectory: null_mut(), 
            ObjectName: null_mut(), 
            Attributes: Default::default(), 
            SecurityDescriptor: null_mut(), 
            SecurityQualityOfService: null_mut() 
        }
    }
}

#[repr(C)]
pub struct PS_ATTRIBUTE_LIST {
    pub TotalLength: usize,
    pub Attributes: [PS_ATTRIBUTE; 1],
}

#[repr(C)]
pub struct PS_ATTRIBUTE {
    pub Attribute: usize,
    pub Size: usize,
    pub u: PS_ATTRIBUTE_0,
    pub ReturnLength: *mut usize,
}

#[repr(C)]
pub union PS_ATTRIBUTE_0 {
    pub Value: usize,
    pub ValuePtr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *const u16,
}


#[repr(C)]
pub struct API_SET_NAMESPACE {
    pub Version: u32,
    pub Size: u32,
    pub Flags: u32,
    pub Count: u32,
    pub EntryOffset: u32,
    pub HashOffset: u32,
    pub HashFactor: u32
}

#[repr(C)]
pub struct RTL_BITMAP {
    SizeOfBitMap: u32,
    Buffer: *mut u32
}

#[repr(C)]
pub enum NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
}

#[repr(C)]
pub struct SILO_USER_SHARED_DATA {
    ServiceSessionId: u32,
    ActiveConsoleId: u32,
    ConsoleSessionForegroundProcessId: i64,
    NtProductType: NT_PRODUCT_TYPE,
    SuiteMask: u32,
    SharedUserSessionId: u32,
    IsMultiSessionSku: u8,
    IsStateSeparationEnabled: u8,
    NtSystemRoot: [u16; 260],
    UserModeGlobalLogger: [u16; 16],
    TimeZoneId: u32,
    TimeZoneBiasStamp: i32,
    TimeZoneBiasEffectiveStart: LARGE_INTEGER,
    TimeZoneBiasEffectiveEnd: LARGE_INTEGER
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TEB {
    pub Reserved1: [*mut c_void; 12],
    pub ProcessEnvironmentBlock: *mut PEB,
    pub Reserved2: [*mut c_void; 399],
    pub Reserved3: [u8; 1952],
    pub TlsSlots: [*mut c_void; 64],
    pub Reserved4: [u8; 8],
    pub Reserved5: [*mut c_void; 26],
    pub ReservedForOle: *mut c_void,
    pub Reserved6: [*mut c_void; 4],
    pub TlsExpansionSlots: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub Anonymous1: PEB_0,
    pub Mutant: HANDLE,
    pub ImageBaseAddress: *mut c_void,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: *mut c_void,
    pub ProcessHeap: *mut c_void,
    pub FastPebLock: *mut RTL_CRITICAL_SECTION,
    pub AtlThunkSListPtr: *mut SLIST_HEADER,
    pub IFEOKey: *mut c_void,
    pub Anonymous2: PEB_1,
    pub Anonymous3: PEB_2,
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: *mut API_SET_NAMESPACE,
    pub TlsExpansionCounter: u32,
    pub TlsBitmap: *mut RTL_BITMAP,
    pub TlsBitmapBits: [u32; 2],
    pub ReadOnlySharedMemoryBase: *mut c_void,
    pub SharedData: *mut SILO_USER_SHARED_DATA,
    pub ReadOnlyStaticServerData: *mut c_void,
    pub AnsiCodePageData: *mut c_void,
    pub OemCodePageData: *mut c_void,
    pub UnicodeCaseTableData: *mut c_void,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub CriticalSectionTimeout: LARGE_INTEGER,
    pub HeapSegmentReserve: usize,
    pub HeapSegmentCommit: usize,
    pub HeapDeCommitTotalFreeThreshold: usize,
    pub HeapDeCommitFreeBlockThreshold: usize,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: *mut c_void,
    pub GdiSharedHandleTable: *mut c_void,
    pub ProcessStarterHelper: *mut c_void,
    pub GdiDCAttributeList: u32,
    pub LoaderLock: *mut RTL_CRITICAL_SECTION,
    pub OSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u16,
    pub OSCSDVersion: u16,
    pub OSPlatformId: u32,
    pub ImageSubsystem: u32,
    pub ImageSubsystemMajorVersion: u32,
    pub ImageSubsystemMinorVersion: u32,
    pub ActiveProcessAffinityMask: usize,
    pub GdiHandleBuffer: GDI_HANDLE_BUFFER,
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub TlsExpansionBitmap: *mut RTL_BITMAP,
    pub TlsExpansionBitmapBits: [u32; 32],
    pub SessionId: u32,
    pub AppCompatFlags: ULARGE_INTEGER,
    pub AppCompatFlagsUser: ULARGE_INTEGER,
    pub pShimData: *mut c_void,
    pub AppCompatInfo: *mut c_void,
    pub CSDVersion: UNICODE_STRING,
    pub ActivationContextData: *mut ACTIVATION_CONTEXT_DATA,
    pub ProcessAssemblyStorageMap: *mut ASSEMBLY_STORAGE_MAP,
    pub SystemDefaultActivationContextData: *mut ACTIVATION_CONTEXT_DATA,
    pub SystemAssemblyStorageMap: *mut ASSEMBLY_STORAGE_MAP,
    pub MinimumStackCommit: usize,
    pub SparePointers: *mut c_void,
    pub PatchLoaderData: *mut c_void,
    pub ChpeV2ProcessInfo: *mut c_void,
    pub Anonymous4: PEB_3,
    pub SpareUlongs: [u32; 2],
    pub ActiveCodePage: u16,
    pub OemCodePage: u16,
    pub UseCaseMapping: u16,
    pub UnusedNlsField: u16,
    pub WerRegistrationData: *mut WER_PEB_HEADER_BLOCK,
    pub WerShipAssertPtr: *mut c_void,
    pub Anonymous5: PEB_4,
    pub pImageHeaderHash: *mut c_void,
    pub Anonymous6: PEB_5,
    pub CsrServerReadOnlySharedMemoryBase: u64,
    pub TppWorkerpListLock: *mut RTL_CRITICAL_SECTION,
    pub TppWorkerpList: LIST_ENTRY,
    pub WaitOnAddressHashTable: [*mut c_void; 128],
    pub TelemetryCoverageHeader: *mut TELEMETRY_COVERAGE_HEADER,
    pub CloudFileFlags: u32,
    pub CloudFileDiagFlags: u32,
    pub PlaceholderCompatibilityMode: i8,
    pub PlaceholderCompatibilityModeReserved: [i8; 7],
    pub LeapSecondData: *mut c_void, // PLEAP_SECOND_DATA
    pub Anonymous7: PEB_6,
    pub NtGlobalFlag2: u32,
    pub ExtendedFeatureDisableMask: u64,
}

#[repr(C)]
pub struct WER_RECOVERY_INFO {
    pub Length: u32,
    pub Callback: *mut c_void,
    pub Parameter: *mut c_void,
    pub Started: HANDLE,
    pub Finished: HANDLE,
    pub InProgress: HANDLE,
    pub LastError: i32,
    pub Successful: i32,
    pub PingInterval: u32,
    pub Flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WER_FILE {
    pub Flags: u16,
    pub Path: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WER_MEMORY {
    pub Address: *mut c_void,
    pub Size: u32,
}

#[repr(C)]
pub union WER_GATHER_VALUE {
    pub File: WER_FILE,
    pub Memory: WER_MEMORY,
}

#[repr(C)]
pub struct WER_GATHER {
    pub Next: *mut WER_GATHER,
    pub Flags: u16,
    pub v: WER_GATHER_VALUE,
}

#[repr(C)]
pub struct WER_METADATA {
    pub Next: *mut WER_METADATA,
    pub Key: [u16; 64],
    pub Value: [u16; 128],
}

#[repr(C)]
pub struct WER_RUNTIME_DLL {
    pub Next: *mut WER_RUNTIME_DLL,
    pub Length: u32,
    pub Context: *mut c_void,
    pub CallbackDllPath: [u16; 260],
}

#[repr(C)]
pub struct WER_DUMP_COLLECTION {
    pub Next: *mut WER_DUMP_COLLECTION,
    pub ProcessId: u32,
    pub ThreadId: u32,
}

#[repr(C)]
pub struct WER_HEAP_MAIN_HEADER {
    pub Signature: [u16; 16],
    pub Links: LIST_ENTRY,
    pub Mutex: HANDLE,
    pub FreeHeap: *mut c_void,
    pub FreeCount: u32,
}

#[repr(C)]
pub struct WER_PEB_HEADER_BLOCK {
    pub Length: i32,
    pub Signature: [u16; 16],
    pub AppDataRelativePath: [u16; 64],
    pub RestartCommandLine: [u16; 1024],
    pub RecoveryInfo: WER_RECOVERY_INFO,
    pub Gather: *mut WER_GATHER,
    pub MetaData: *mut WER_METADATA,
    pub RuntimeDll: *mut WER_RUNTIME_DLL,
    pub DumpCollection: *mut WER_DUMP_COLLECTION,
    pub GatherCount: i32,
    pub MetaDataCount: i32,
    pub DumpCount: i32,
    pub Flags: i32,
    pub MainHeader: WER_HEAP_MAIN_HEADER,
    pub Reserved: *mut c_void,
}

#[repr(C)]
pub struct ASSEMBLY_STORAGE_MAP_ENTRY {
    Flags: u32,
    DosPath: UNICODE_STRING,
    Handle: HANDLE
}

#[repr(C)]
pub struct ASSEMBLY_STORAGE_MAP {
    pub Flags: u32,
    pub AssemblyCount: u32,
    pub AssemblyArray: *mut ASSEMBLY_STORAGE_MAP_ENTRY
}

#[repr(C)]
pub struct ACTIVATION_CONTEXT_DATA {
    pub Magic: u32,
    pub HeaderSize: u32,
    pub FormatVersion: u32,
    pub TotalSize: u32,
    pub DefaultTocOffset: u32,
    pub ExtendedTocOffset: u32,
    pub AssemblyRosterOffset: u32,
    pub Flags: u32
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: *mut c_void,
    pub ShutdownInProgress: u8,
    pub ShutdownThreadId: HANDLE,
}

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: HANDLE,
}

#[repr(C)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: u16,
    pub Length: u16,
    pub TimeStamp: u32,
    pub DosPath: STRING
}

#[repr(C)]
pub struct STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut i8,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: HANDLE,
    pub ConsoleFlags: u32,
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: *mut c_void,
    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,
    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; 32],
    pub EnvironmentSize: usize,
    pub EnvironmentVersion: usize,
    pub PackageDependencyData: *mut c_void,
    pub ProcessGroupId: u32,
    pub LoaderThreads: u32,
    pub RedirectionDllName: UNICODE_STRING, // REDSTONE4
    pub HeapPartitionName: UNICODE_STRING, // 19H1
    pub DefaultThreadpoolCpuSetMasks: *mut u64,
    pub DefaultThreadpoolCpuSetMaskCount: u32,
    pub DefaultThreadpoolThreadMaximum: u32,
    pub HeapMemoryTypeMask: u32, // WIN11
}

#[repr(C)]
pub struct RTL_CRITICAL_SECTION {
    pub DebugInfo: *mut RTL_CRITICAL_SECTION,
    pub LockCount: i32,
    pub RecursionCount: i32,
    pub OwningThread: HANDLE,
    pub LockSemaphore: HANDLE,
    pub SpinCount: usize
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DUMMYSTRUCTNAME {
    pub Aligment: u64,
    pub Region: u64
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union LARGE_INTEGER {
    pub Anonymous: LARGE_INTEGER_0,
    pub u: LARGE_INTEGER_1,
    pub QuadPart: i64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LARGE_INTEGER_0 {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LARGE_INTEGER_1 {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ULARGE_INTEGER {
    pub Anonymous: ULARGE_INTEGER_0,
    pub u: ULARGE_INTEGER_1,
    pub QuadPart: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ULARGE_INTEGER_0 {
    pub LowPart: u32,
    pub HighPart: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ULARGE_INTEGER_1 {
    pub LowPart: u32,
    pub HighPart: u32,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct BitField: u8 {
        const ImageUsesLargePages          = 1 << 0;
        const IsProtectedProcess           = 1 << 1;
        const IsImageDynamicallyRelocated  = 1 << 2;
        const SkipPatchingUser32Forwarders = 1 << 3;
        const IsPackagedProcess            = 1 << 4;
        const IsAppContainer               = 1 << 5;
        const IsProtectedProcessLight      = 1 << 6;
        const IsLongPathAwareProcess       = 1 << 7;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct CrossProcessFlags: u32 {
        const ProcessInJob               = 1 << 0;
        const ProcessInitializing        = 1 << 1;
        const ProcessUsingVEH            = 1 << 2;
        const ProcessUsingVCH            = 1 << 3;
        const ProcessUsingFTH            = 1 << 4;
        const ProcessPreviouslyThrottled = 1 << 5;
        const ProcessCurrentlyThrottled  = 1 << 6;
        const ProcessImagesHotPatched    = 1 << 7;
        const ReservedBits0              = 0xFFFFFF00;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct AppModelFeatureState: u32 {
        const ForegroundBoostProcesses     = 1 << 0;
        const AppModelFeatureStateReserved = 0xFFFFFFFE; 
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct TracingFlags: u32 {
        const HeapTracingEnabled      = 1 << 0;
        const CritSecTracingEnabled   = 1 << 1;
        const LibLoaderTracingEnabled = 1 << 2;
        const SpareTracingBits        = 0xFFFF_FFF8;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct LeapSecondFlags: u128 {
        const Depth     = 0xFFFF;
        const Sequence  = 0xFFFFFFFFFFFF << 16;
        const Reserved  = 0xF << 64;
        const NextEntry = 0xFFFFFFFFFFFFFFF << 68;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct TELEMETRY_COVERAGE_HEADER_0: u16 {
        const TRACING_ENABLED = 1 << 0; 
        const RESERVED1       = 0xFFFE;
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_0 {
    pub BitField: u8,
    pub Anonymous: BitField
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_1 {
    pub CrossProcessFlags: u32,
    pub Anonymous: CrossProcessFlags,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_2 {
    pub KernelCallbackTable: *mut c_void,
    pub UserSharedInfoPtr: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_3 {
    pub AppModelFeatureState: u32,
    pub Anonymous: AppModelFeatureState,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PEB_4 {
    pub pContextData: *mut c_void,
    pub EcCodeBitMap: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_5 {
    pub TracingFlags: u32,
    pub Anonymous: TracingFlags,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PEB_6 {
    pub LeapSecondFlags: u32,
    pub Anonymous: LeapSecondFlags,
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub union SLIST_HEADER {
    pub alignment: u64,
    pub region: u64,
    // Padding
    pub _padding: [u8; 16],
}

#[repr(C)]
pub struct TELEMETRY_COVERAGE_HEADER {
    pub MajorVersion: u8,
    pub MinorVersion: u8,
    pub Anonymous: TELEMETRY_COVERAGE_HEADER_0,
    pub HashTableEntries: u32,
    pub HashIndexMask: u32,
    pub TableUpdateVersion: u32,
    pub TableSizeInBytes: u32,
    pub LastResetTick: u32,
    pub ResetRound: u32,
    pub Reserved2: u32,
    pub RecordedCount: u32,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [*mut c_void; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [*mut c_void; 2],
    pub DllBase: *mut c_void,
    pub Reserved3: [*mut c_void; 2],
    pub FullDllName: UNICODE_STRING,
    pub Reserved4: [u8; 8],
    pub Reserved5: [*mut c_void; 3],
    pub Anonymous: LDR_DATA_TABLE_ENTRY_0,
    pub TimeDateStamp: u32,
}

#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_0 {
    pub CheckSum: u32,
    pub Reserved6: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct IMAGE_RUNTIME_FUNCTION {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub UnwindData: u32
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}