//! Heap allocator using Windows native APIs.

use core::{
    ptr::null_mut, ffi::c_void,
    alloc::{GlobalAlloc, Layout},
};

use super::{data::*, GetProcessHeap};

/// A thread-safe wrapper for managing a Windows Heap.
pub struct WinHeap;

impl WinHeap {
    /// Returns the handle to the default process heap.
    #[inline(always)]
    fn heap(&self) -> HANDLE {
        GetProcessHeap()
    }
}

unsafe impl GlobalAlloc for WinHeap {
    /// Allocates memory using the custom heap.
    ///
    /// # Arguments
    ///
    /// * `layout` - The memory layout to allocate.
    ///
    /// # Returns
    ///
    /// A pointer to the allocated memory
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = self.heap();
        let size = layout.size();
        if size == 0 {
            return null_mut();
        }

        // Another thread initialized the heap, free our local one
        unsafe {
            RtlAllocateHeap(
                heap,
                0,
                size
            ) as *mut u8
        }
    }

    /// Deallocates memory using the custom heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to deallocate.
    /// * `layout` - The memory layout.
    /// 
    /// # Notes
    /// 
    /// If `ptr` is null, this function does nothing.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
    
        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        unsafe { RtlFreeHeap(self.heap(), 0, ptr.cast()); }
    }
}

windows_targets::link!("ntdll" "system" fn RtlFreeHeap(heap: HANDLE, flags: u32, ptr: *mut c_void) -> i8);
windows_targets::link!("ntdll" "system" fn RtlAllocateHeap(heap: HANDLE, flags: u32, size: usize) -> *mut c_void);