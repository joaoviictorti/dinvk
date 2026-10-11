//! Heap allocator using Windows native APIs.

use core::ptr::null_mut;
use alloc::alloc::{GlobalAlloc, Layout};

use phnt::ffi::{HANDLE, RtlAllocateHeap, RtlFreeHeap};

use crate::env::nt_current_peb;

/// Global allocator backed by the Windows process heap.
///
/// Uses `RtlAllocateHeap` for allocation and `RtlFreeHeap` for deallocation.
/// Memory is zeroed on deallocation for security.
///
/// # Examples
///
/// ```
/// # use dinvk::allocator::Heap;
/// 
/// #[global_allocator]
/// static ALLOCATOR: Heap = Heap::empty();
///
/// fn main() {
///     // Now `alloc::vec!`, `alloc::string::String`, etc. work normally
///     let v = vec![1, 2, 3];
/// }
/// ```
#[derive(Debug)]
pub struct Heap;

impl Heap {
    /// Creates an allocator backed by the current process heap.
    pub const fn empty() -> Self {
        Self
    }

    fn heap_handle(&self) -> HANDLE {
        let peb = nt_current_peb();
        unsafe { (&*peb).ProcessHeap }
    }
}

unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return null_mut();
        }

        const HEAP_ALIGNMENT: usize = if cfg!(target_pointer_width = "64") { 16 } else { 8 };

        if layout.align() > HEAP_ALIGNMENT {
            return null_mut();
        }

        let Ok(size) = layout.size().try_into() else {
            return null_mut();
        };

        unsafe { RtlAllocateHeap(self.heap_handle(), 0, size) }.cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
    
        // Zero memory before freeing for security.
        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        unsafe { RtlFreeHeap(self.heap_handle(), 0, ptr.cast()) };
    }
}
