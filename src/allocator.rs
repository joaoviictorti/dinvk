//! Heap allocator using Windows native APIs.

use core::{
    ptr::null_mut, ffi::c_void,
    alloc::{GlobalAlloc, Layout},
};

use crate::{types::*, winapis::GetProcessHeap};

/// A thread-safe wrapper for managing a Windows Heap.
pub struct WinHeap;

impl WinHeap {
    /// Returns the handle to the default process heap.
    #[inline]
    fn get(&self) -> HANDLE {
        GetProcessHeap()
    }
}

unsafe impl GlobalAlloc for WinHeap {
    /// Allocates memory using the custom heap.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = self.get();
        let size = layout.size();
        if size == 0 {
            return null_mut();
        }

        unsafe {
            RtlAllocateHeap(
                heap,
                0,
                size
            ) as *mut u8
        }
    }

    /// Deallocates memory using the custom heap.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
    
        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        unsafe { RtlFreeHeap(self.get(), 0, ptr.cast()); }
    }
}

windows_targets::link!("ntdll" "system" fn RtlFreeHeap(heap: HANDLE, flags: u32, ptr: *mut c_void) -> i8);
windows_targets::link!("ntdll" "system" fn RtlAllocateHeap(heap: HANDLE, flags: u32, size: usize) -> *mut c_void);