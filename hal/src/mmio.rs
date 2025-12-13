// hal/src/mmio.rs - Minimal wrappers for MMIO volatile reads/writes
#![allow(dead_code)]

use core::marker::Copy;

/// Read an 8-bit value from the MMIO address
#[inline]
pub fn mmio_read_u8(addr: usize) -> u8 {
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Read a 16-bit value from the MMIO address
#[inline]
pub fn mmio_read_u16(addr: usize) -> u16 {
    unsafe { core::ptr::read_volatile(addr as *const u16) }
}

/// Read a 32-bit value from the MMIO address
#[inline]
pub fn mmio_read_u32(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Read a 64-bit value from the MMIO address
#[inline]
pub fn mmio_read_u64(addr: usize) -> u64 {
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

/// Write an 8-bit value to the MMIO address
#[inline]
pub fn mmio_write_u8(addr: usize, val: u8) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u8, val);
    }
}

/// Write a 16-bit value to the MMIO address
#[inline]
pub fn mmio_write_u16(addr: usize, val: u16) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u16, val);
    }
}

/// Write a 32-bit value to the MMIO address
#[inline]
pub fn mmio_write_u32(addr: usize, val: u32) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u32, val);
    }
}

/// Write a 64-bit value to the MMIO address
#[inline]
pub fn mmio_write_u64(addr: usize, val: u64) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u64, val);
    }
}

/// Generic volatile read for Copy types. Useful for reading struct types or
/// custom-sized types from memory-mapped or volatile memory locations.
#[inline]
pub fn volatile_read<T: Copy>(addr: usize) -> T {
    // TODO: Consider adding optional runtime or compile-time checks to validate
    // that `addr` points to a valid mmio region for this device/driver. For now
    // the caller is expected to ensure the address is correct.
    unsafe { core::ptr::read_volatile(addr as *const T) }
}

/// Generic volatile write for Copy types.
#[inline]
pub fn volatile_write<T: Copy>(addr: usize, val: T) {
    // TODO: Consider adding optional address validation to MMIO writes.
    unsafe {
        core::ptr::write_volatile(addr as *mut T, val);
    }
}
