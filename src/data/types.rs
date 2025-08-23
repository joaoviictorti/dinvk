use core::ffi::c_void;
use super::{
    CONTEXT, EVENT_TYPE, EXCEPTION_POINTERS, 
    OBJECT_ATTRIBUTES, PS_ATTRIBUTE_LIST
};

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

