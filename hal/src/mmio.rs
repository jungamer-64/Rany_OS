// ============================================================================
// hal/src/mmio.rs - Minimal wrappers for MMIO volatile reads/writes
// ============================================================================
#![allow(dead_code)]

use core::marker::Copy;

/// Read an 8-bit value from the MMIO address
#[inline]
#[must_use]
pub fn mmio_read_u8(addr: usize) -> u8 {
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Read a 16-bit value from the MMIO address
#[inline]
#[must_use]
pub fn mmio_read_u16(addr: usize) -> u16 {
    unsafe { core::ptr::read_volatile(addr as *const u16) }
}

/// Read a 32-bit value from the MMIO address
#[inline]
#[must_use]
pub fn mmio_read_u32(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Read a 64-bit value from the MMIO address
#[inline]
#[must_use]
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
#[must_use]
pub fn volatile_read<T: Copy>(addr: usize) -> T {
    debug_check_mmio_access::<T>(addr);
    unsafe { core::ptr::read_volatile(addr as *const T) }
}

/// Generic volatile write for Copy types.
#[inline]
pub fn volatile_write<T: Copy>(addr: usize, val: T) {
    debug_check_mmio_access::<T>(addr);
    unsafe {
        core::ptr::write_volatile(addr as *mut T, val);
    }
}

#[inline]
fn debug_check_mmio_access<T>(addr: usize) {
    if cfg!(debug_assertions) {
        let align = core::mem::align_of::<T>();
        debug_assert!(addr != 0, "MMIO access with null address");
        debug_assert!(
            align == 0 || addr.is_multiple_of(align),
            "MMIO access is unaligned"
        );
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
    #[must_use]
    pub const fn new(base: usize, offset: usize) -> Self {
        Self {
            addr: base + offset,
            _marker: core::marker::PhantomData,
        }
    }

    /// Create a new MMIO register accessor from a direct address.
    #[inline]
    #[must_use]
    pub const fn from_addr(addr: usize) -> Self {
        Self {
            addr,
            _marker: core::marker::PhantomData,
        }
    }

    /// Get the raw address of this register.
    #[inline]
    #[must_use]
    pub const fn addr(&self) -> usize {
        self.addr
    }
}

impl MmioReg<u8> {
    /// Read from the register.
    #[inline]
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    // Only use SSE intrinsics when target has SSE enabled at compile time
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse"
    ))]
    unsafe {
        core::arch::x86_64::_mm_sfence();
    }
    // Fallback for soft-float targets or non-x86 architectures
    #[cfg(not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse"
    )))]
    {
        // Use a compiler fence as fallback
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Write a 32-bit value using non-temporal store (bypasses cache).
/// The address must be 4-byte aligned.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
#[inline]
#[allow(clippy::cast_possible_wrap)]
pub fn stream_write_u32(addr: usize, val: u32) {
    unsafe {
        core::arch::x86_64::_mm_stream_si32(addr as *mut i32, val as i32);
    }
}

/// Fallback for soft-float targets: use volatile write
#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
)))]
#[inline]
pub fn stream_write_u32(addr: usize, val: u32) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u32, val);
    }
}

/// Write a 64-bit value using non-temporal store (bypasses cache).
/// The address must be 8-byte aligned.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
#[inline]
#[allow(clippy::cast_possible_wrap)]
pub fn stream_write_u64(addr: usize, val: u64) {
    unsafe {
        core::arch::x86_64::_mm_stream_si64(addr as *mut i64, val as i64);
    }
}

/// Fallback for soft-float targets: use volatile write
#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
)))]
#[inline]
pub fn stream_write_u64(addr: usize, val: u64) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u64, val);
    }
}

/// Write 128 bits (16 bytes) using SSE2 non-temporal store.
/// The address MUST be 16-byte aligned.
///
/// # Safety
/// - Caller must ensure the address is 16-byte aligned
/// - Caller must ensure SSE2 is available (standard on `x86_64`)
///
/// NOTE: Disabled on no_std targets due to LLVM codegen bug.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"))]
#[target_feature(enable = "sse2")]
#[inline]
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn stream_write_128(addr: usize, data: &[u8; 16]) {
    use core::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_stream_si128};
    // SAFETY: Caller ensures SSE2 is available and address is 16-byte aligned
    unsafe {
        let v = _mm_loadu_si128(data.as_ptr().cast::<__m128i>());
        _mm_stream_si128(addr as *mut __m128i, v);
    }
}

/// Fallback for no_std targets - use two 64-bit stores
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(feature = "std")))]
#[inline]
pub unsafe fn stream_write_128(addr: usize, data: &[u8; 16]) {
    // Fall back to two 64-bit streaming stores
    unsafe {
        let v0 = core::ptr::read_unaligned(data.as_ptr().cast::<u64>());
        let v1 = core::ptr::read_unaligned(data.as_ptr().add(8).cast::<u64>());
        stream_write_u64(addr, v0);
        stream_write_u64(addr + 8, v1);
    }
}

/// Write 256 bits (32 bytes) using AVX non-temporal store.
/// The address MUST be 32-byte aligned.
///
/// # Safety
/// - Caller must ensure the address is 32-byte aligned
/// - Caller must ensure AVX is available
///
/// NOTE: Disabled on no_std targets due to LLVM codegen bug in nightly 2025-11-25 through 2025-12-17.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"))]
#[target_feature(enable = "avx")]
#[inline]
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn stream_write_256(addr: usize, data: &[u8; 32]) {
    use core::arch::x86_64::{__m256i, _mm256_loadu_si256, _mm256_stream_si256};
    // SAFETY: Caller ensures AVX is available and address is 32-byte aligned
    unsafe {
        let v = _mm256_loadu_si256(data.as_ptr().cast::<__m256i>());
        _mm256_stream_si256(addr as *mut __m256i, v);
    }
}

/// Fallback for no_std targets - use SSE2 16-byte stores
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(feature = "std")))]
#[inline]
pub unsafe fn stream_write_256(addr: usize, data: &[u8; 32]) {
    // Fall back to two 16-byte stores
    unsafe {
        stream_write_128(addr, &*(data.as_ptr().cast::<[u8; 16]>()));
        stream_write_128(addr + 16, &*(data.as_ptr().add(16).cast::<[u8; 16]>()));
    }
}

// ============================================================================
// SIMD Support Level
// ============================================================================

static SIMD_LEVEL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// SIMD support level
pub mod simd_level {
    pub const NONE: u8 = 0;
    pub const SSE2: u8 = 0; // Baseline for x86_64
    pub const AVX: u8 = 1;
    pub const SSSE3: u8 = 2;
    pub const AVX2: u8 = 3; // For future use
}

/// Set the supported SIMD level for optimized MMIO operations.
///
/// # Safety
/// Caller must ensure the CPU supports the specified level.
/// - level >= 1 requires AVX support
pub unsafe fn set_simd_level(level: u8) {
    SIMD_LEVEL.store(level, core::sync::atomic::Ordering::Relaxed);
}

/// Get the current SIMD support level.
#[inline]
#[must_use]
pub fn get_simd_level() -> u8 {
    SIMD_LEVEL.load(core::sync::atomic::Ordering::Relaxed)
}

/// Check if debug printing is allowed during benchmarks.
/// Use this instead of direct env var checks to allow use in `no_std` context.
/// Returns true if `std` feature is enabled AND `RANY_DEBUG_DRAW` == "1".
#[inline]
#[must_use]
pub fn bench_debug_print_allowed() -> bool {
    #[cfg(feature = "std")]
    {
        std::env::var("RANY_DEBUG_DRAW").ok().as_deref() == Some("1")
    }
    #[cfg(not(feature = "std"))]
    {
        false
    }
}

/// Fallback for non-x86 architectures: just use volatile writes
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub unsafe fn stream_write_bytes(mut addr: usize, data: &[u8]) {
    unsafe {
        for &byte in data {
            core::ptr::write_volatile(addr as *mut u8, byte);
            addr += 1;
        }
    }
}

/// AVX (256-bit) streaming write pass. Returns (updated addr, updated index).
///
/// # Safety
/// Caller must ensure the destination address range is valid for AVX writes.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
unsafe fn stream_write_avx_pass(mut addr: usize, data: &[u8], mut i: usize) -> (usize, usize) {
    let len = data.len();
    unsafe {
        // Align to 32 bytes
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i < len && (addr & 31) != 0 {
            core::ptr::write_volatile(addr as *mut u8, data[i]);
            addr += 1;
            i += 1;
        }

        // Loop unrolling: 4x 32-byte (128 bytes per iteration)
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i + 128 <= len {
            let ptr = data.as_ptr().add(i);
            stream_write_256(addr, &*(ptr.cast::<[u8; 32]>()));
            stream_write_256(addr + 32, &*(ptr.add(32).cast::<[u8; 32]>()));
            stream_write_256(addr + 64, &*(ptr.add(64).cast::<[u8; 32]>()));
            stream_write_256(addr + 96, &*(ptr.add(96).cast::<[u8; 32]>()));
            addr += 128;
            i += 128;
        }

        // Handle remaining 32-byte chunks
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i + 32 <= len {
            let chunk_ptr = data.as_ptr().add(i).cast::<[u8; 32]>();
            stream_write_256(addr, &*chunk_ptr);
            addr += 32;
            i += 32;
        }
    }
    (addr, i)
}

/// SSE2/trailing streaming write pass. Returns (updated addr, updated index).
///
/// # Safety
/// Caller must ensure the destination address range is valid for writing.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
unsafe fn stream_write_trailing(mut addr: usize, data: &[u8], mut i: usize) -> (usize, usize) {
    let len = data.len();
    unsafe {
        // Loop unrolling: 4x 16-byte (64 bytes per iteration)
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i + 64 <= len {
            let ptr = data.as_ptr().add(i);
            stream_write_128(addr, &*(ptr.cast::<[u8; 16]>()));
            stream_write_128(addr + 16, &*(ptr.add(16).cast::<[u8; 16]>()));
            stream_write_128(addr + 32, &*(ptr.add(32).cast::<[u8; 16]>()));
            stream_write_128(addr + 48, &*(ptr.add(48).cast::<[u8; 16]>()));
            addr += 64;
            i += 64;
        }

        // Handle remaining 16-byte chunks
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i + 16 <= len {
            let chunk_ptr = data.as_ptr().add(i).cast::<[u8; 16]>();
            stream_write_128(addr, &*chunk_ptr);
            addr += 16;
            i += 16;
        }

        // Handle remaining bytes via u64 streaming if possible
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i + 8 <= len {
            let v = core::ptr::read_unaligned(data.as_ptr().add(i).cast::<u64>());
            stream_write_u64(addr, v);
            addr += 8;
            i += 8;
        }

        // Handle trailing bytes
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i < len {
            core::ptr::write_volatile(addr as *mut u8, data[i]);
            addr += 1;
            i += 1;
        }
    }
    (addr, i)
}

/// Write a contiguous slice of bytes using streaming stores.
/// Handles alignment and falls back to volatile writes for unaligned portions.
///
/// Automatically uses AVX (256-bit) stores if `set_simd_level` was called with >= 1.
///
/// # Safety
/// - Caller must ensure the destination address range is valid for writing
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub unsafe fn stream_write_bytes(mut addr: usize, data: &[u8]) {
    let mut i = 0usize;
    let len = data.len();
    let level = SIMD_LEVEL.load(core::sync::atomic::Ordering::Relaxed);

    unsafe {
        if level >= simd_level::AVX {
            (addr, i) = stream_write_avx_pass(addr, data, i);
        } else {
            // SSE2 Path: Align to 16 bytes
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while i < len && (addr & 15) != 0 {
                core::ptr::write_volatile(addr as *mut u8, data[i]);
                addr += 1;
                i += 1;
            }
        }

        // SSE2 Fallback / Cleanup (also runs if AVX path didn't consume everything or wasn't taken)
        // If AVX path ran, we are 32-byte aligned, which is also 16-byte aligned.
        let _ = stream_write_trailing(addr, data, i);
    }
}
