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

// ============================================================================
// MmioReg - Type-Safe MMIO Register Access
// ============================================================================

/// MMIO Register accessor for type-safe register operations.
///
/// Encapsulates unsafe volatile operations, allowing callers to perform
/// register access without explicit `unsafe` blocks.
///
/// # Type Parameter
/// - `T`: The register width type (u8, u16, u32, u64)
///
/// # Example
/// ```ignore
/// let sivr = MmioReg::<u32>::new(0xFEE00000, 0x0F0);
/// sivr.write(0xFF | (1 << 8));
/// let val = sivr.read();
/// ```
#[derive(Clone, Copy)]
pub struct MmioReg<T> {
    addr: usize,
    _marker: core::marker::PhantomData<T>,
}

impl<T> MmioReg<T> {
    /// Create a new MMIO register accessor.
    ///
    /// # Safety Considerations
    /// The caller must ensure that `base + offset` points to a valid
    /// memory-mapped I/O register for the lifetime of this accessor.
    #[inline]
    pub const fn new(base: usize, offset: usize) -> Self {
        Self {
            addr: base + offset,
            _marker: core::marker::PhantomData,
        }
    }

    /// Create a new MMIO register accessor from a direct address.
    #[inline]
    pub const fn from_addr(addr: usize) -> Self {
        Self {
            addr,
            _marker: core::marker::PhantomData,
        }
    }

    /// Get the raw address of this register.
    #[inline]
    pub const fn addr(&self) -> usize {
        self.addr
    }
}

impl MmioReg<u8> {
    /// Read from the register.
    #[inline]
    pub fn read(&self) -> u8 {
        unsafe { core::ptr::read_volatile(self.addr as *const u8) }
    }

    /// Write to the register.
    #[inline]
    pub fn write(&self, value: u8) {
        unsafe { core::ptr::write_volatile(self.addr as *mut u8, value) }
    }
}

impl MmioReg<u16> {
    /// Read from the register.
    #[inline]
    pub fn read(&self) -> u16 {
        unsafe { core::ptr::read_volatile(self.addr as *const u16) }
    }

    /// Write to the register.
    #[inline]
    pub fn write(&self, value: u16) {
        unsafe { core::ptr::write_volatile(self.addr as *mut u16, value) }
    }
}

impl MmioReg<u32> {
    /// Read from the register.
    #[inline]
    pub fn read(&self) -> u32 {
        unsafe { core::ptr::read_volatile(self.addr as *const u32) }
    }

    /// Write to the register.
    #[inline]
    pub fn write(&self, value: u32) {
        unsafe { core::ptr::write_volatile(self.addr as *mut u32, value) }
    }

    /// Modify the register using a closure.
    #[inline]
    pub fn modify<F: FnOnce(u32) -> u32>(&self, f: F) {
        let val = self.read();
        self.write(f(val));
    }
}

impl MmioReg<u64> {
    /// Read from the register.
    #[inline]
    pub fn read(&self) -> u64 {
        unsafe { core::ptr::read_volatile(self.addr as *const u64) }
    }

    /// Write to the register.
    #[inline]
    pub fn write(&self, value: u64) {
        unsafe { core::ptr::write_volatile(self.addr as *mut u64, value) }
    }

    /// Modify the register using a closure.
    #[inline]
    pub fn modify<F: FnOnce(u64) -> u64>(&self, f: F) {
        let val = self.read();
        self.write(f(val));
    }
}

// ============================================================================
// Non-Temporal (Streaming) Store Functions
// ============================================================================
//
// These functions bypass the CPU cache and write directly to memory using
// Write-Combining buffers. They are optimal for VRAM writes where the data
// will not be read back immediately.
//
// IMPORTANT: For maximum performance, the destination memory should be mapped
// with Write-Combining (WC) page attribute via PAT/MTRR.

/// Memory fence for streaming stores. Ensures all preceding streaming stores
/// are globally visible before any subsequent loads or stores.
#[inline]
pub fn sfence() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        core::arch::x86_64::_mm_sfence();
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        // On other architectures, use a compiler fence as fallback
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Write a 32-bit value using non-temporal store (bypasses cache).
/// The address must be 4-byte aligned.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub fn stream_write_u32(addr: usize, val: u32) {
    unsafe {
        core::arch::x86_64::_mm_stream_si32(addr as *mut i32, val as i32);
    }
}

/// Write a 64-bit value using non-temporal store (bypasses cache).
/// The address must be 8-byte aligned.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub fn stream_write_u64(addr: usize, val: u64) {
    unsafe {
        core::arch::x86_64::_mm_stream_si64(addr as *mut i64, val as i64);
    }
}

/// Write 128 bits (16 bytes) using SSE2 non-temporal store.
/// The address MUST be 16-byte aligned.
///
/// # Safety
/// - Caller must ensure the address is 16-byte aligned
/// - Caller must ensure SSE2 is available (standard on x86_64)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub unsafe fn stream_write_128(addr: usize, data: &[u8; 16]) {
    use core::arch::x86_64::*;
    let v = _mm_loadu_si128(data.as_ptr() as *const __m128i);
    _mm_stream_si128(addr as *mut __m128i, v);
}

/// Write 256 bits (32 bytes) using AVX non-temporal store.
/// The address MUST be 32-byte aligned.
///
/// # Safety
/// - Caller must ensure the address is 32-byte aligned
/// - Caller must ensure AVX is available
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx")]
#[inline]
pub unsafe fn stream_write_256(addr: usize, data: &[u8; 32]) {
    use core::arch::x86_64::*;
    let v = _mm256_loadu_si256(data.as_ptr() as *const __m256i);
    _mm256_stream_si256(addr as *mut __m256i, v);
}

/// Write a contiguous slice of bytes using streaming stores.
/// Handles alignment and falls back to volatile writes for unaligned portions.
///
/// # Safety
/// - Caller must ensure the destination address range is valid for writing
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub unsafe fn stream_write_bytes(mut addr: usize, data: &[u8]) {
    let mut i = 0usize;
    let len = data.len();

    // Handle leading unaligned bytes (write as u8 until 8-byte aligned)
    while i < len && (addr & 7) != 0 {
        core::ptr::write_volatile(addr as *mut u8, data[i]);
        addr += 1;
        i += 1;
    }

    // Bulk streaming writes using u64 (8 bytes at a time)
    while i + 8 <= len {
        let v = core::ptr::read_unaligned(data.as_ptr().add(i) as *const u64);
        stream_write_u64(addr, v);
        addr += 8;
        i += 8;
    }

    // Handle trailing bytes
    while i < len {
        core::ptr::write_volatile(addr as *mut u8, data[i]);
        addr += 1;
        i += 1;
    }
}

/// Fallback for non-x86 architectures: just use volatile writes
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn stream_write_bytes(mut addr: usize, data: &[u8]) {
    for &byte in data {
        core::ptr::write_volatile(addr as *mut u8, byte);
        addr += 1;
    }
}
