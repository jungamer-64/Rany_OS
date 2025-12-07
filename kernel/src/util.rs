// ==============================================
// kernel/src/util.rs - Utility Functions for Struct <-> Byte Slice Conversion
// ==============================================
// Utility helpers used across kernel modules for safe-ish byte-slice <-> struct conversions.
// These functions centralize unsafe operations, reduce duplication, and perform boundary
// and alignment checks where possible.
#![allow(dead_code)]
use core::mem;

/// Try to read a value of type T from a byte slice at offset 'offset'.
/// Returns Some(T) on success, None on bounds/overflow errors.
pub fn read_struct<T: Copy>(data: &[u8], offset: usize) -> Option<T> {
    let size = mem::size_of::<T>();
    // Basic overflow check
    let end = offset.checked_add(size)?;
    if end > data.len() {
        return None;
    }

    let ptr = unsafe { data.as_ptr().add(offset) };
    let align = mem::align_of::<T>();

    if (ptr as usize) % align != 0 {
        // Unaligned - copy into a local buffer
        let mut buf = mem::MaybeUninit::<T>::uninit();
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr() as *mut u8, size);
            Some(buf.assume_init())
        }
    } else {
        // Aligned - direct read
        Some(unsafe { core::ptr::read(ptr as *const T) })
    }
}

/// Try to write a value of type T into a byte slice at offset 'offset'.
/// Returns Some(()) on success, None on bounds/overflow errors.
pub fn write_struct<T: Copy>(data: &mut [u8], offset: usize, value: T) -> Option<()> {
    let size = mem::size_of::<T>();
    let end = offset.checked_add(size)?;
    if end > data.len() {
        return None;
    }

    let ptr = unsafe { data.as_mut_ptr().add(offset) };
    let align = mem::align_of::<T>();

    if (ptr as usize) % align != 0 {
        // Unaligned - copy from value
        unsafe {
            core::ptr::copy_nonoverlapping(&value as *const T as *const u8, ptr, size);
        }
    } else {
        unsafe {
            (ptr as *mut T).write(value);
        }
    }

    Some(())
}

/// Try to return a subslice of `data` with bounds checking.
pub fn get_slice<'a>(data: &'a [u8], offset: usize, len: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    if end > data.len() { return None; }
    Some(&data[offset..end])
}

/// Try to return a mutable subslice of `data` with bounds checking.
pub fn get_slice_mut<'a>(data: &'a mut [u8], offset: usize, len: usize) -> Option<&'a mut [u8]> {
    let end = offset.checked_add(len)?;
    if end > data.len() { return None; }
    Some(&mut data[offset..end])
}

/// Attempt to obtain a &mut T pointing into the given mutable slice at offset.
/// Returns None if bounds or alignment don't match.
pub fn get_mut_ref<'a, T>(data: &'a mut [u8], offset: usize) -> Option<&'a mut T> {
    let size = mem::size_of::<T>();
    let end = offset.checked_add(size)?;
    if end > data.len() { return None; }
    let ptr = unsafe { data.as_mut_ptr().add(offset) };
    let align = mem::align_of::<T>();
    if (ptr as usize) % align != 0 { return None; }
    Some(unsafe { &mut *(ptr as *mut T) })
}

/// Obtain an immutable reference to a typed value inside a byte slice at offset.
/// Returns None if bounds or alignment don't match.
pub fn get_ref<'a, T>(data: &'a [u8], offset: usize) -> Option<&'a T> {
    let size = mem::size_of::<T>();
    let end = offset.checked_add(size)?;
    if end > data.len() { return None; }
    let ptr = unsafe { data.as_ptr().add(offset) };
    let align = mem::align_of::<T>();
    if (ptr as usize) % align != 0 { return None; }
    Some(unsafe { &*(ptr as *const T) })
}

/// Write a typed value directly to a virtual address. The address must be valid
/// and mapped for writing. This operation is unsafe and may cause undefined
/// behaviour if the provided address is invalid; the helper centralizes this
/// unsafe write point so it is easier to audit.
pub fn write_to_addr<T>(addr: usize, value: T) {
    let ptr = addr as *mut T;
    unsafe {
        core::ptr::write(ptr, value);
    }
}
