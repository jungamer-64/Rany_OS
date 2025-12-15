//! MMIO Access Optimization
//!
//! Provides optimized writers for Memory Mapped I/O, handling alignment and
//! ensuring efficient bus transactions (e.g. using u64 pair writes).

use core::marker::PhantomData;
use hal::mmio;
#[cfg(all(feature = "std", feature = "bench"))]
use std::sync::atomic::{AtomicUsize, Ordering};

/// A safe wrapper for writing to an MMIO region.
/// Wraps a raw pointer and ensures bounds checking (if length is provided)
/// and proper alignment handling.
pub struct MmioWriter<'a> {
    base: usize,
    len: usize,
    _phantom: PhantomData<&'a mut [u8]>,
}

// Bench debug printing throttle. When `RANY_DEBUG_DRAW=1` this limits the
// number of per-write debug messages that are emitted so benchmarks don't
// get overwhelmed by millions of lines and appear to run forever.
#[cfg(all(feature = "std", feature = "bench"))]
static BENCH_DEBUG_PRINTS_LEFT: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(feature = "std", feature = "bench"))]
/// Returns true when a debug print is allowed. This respects the
/// `RANY_DEBUG_DRAW` env var and an optional `RANY_DEBUG_DRAW_LIMIT` which
/// sets how many individual per-write messages are allowed (defaults to 128).
pub(crate) fn bench_debug_print_allowed() -> bool {
    if std::env::var("RANY_DEBUG_DRAW").ok().as_deref() != Some("1") {
        return false;
    }

    // Initialize the counter on first use.
    let cur = BENCH_DEBUG_PRINTS_LEFT.load(Ordering::Relaxed);
    if cur == 0 {
        let limit = std::env::var("RANY_DEBUG_DRAW_LIMIT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(128usize);
        BENCH_DEBUG_PRINTS_LEFT.store(limit, Ordering::Relaxed);
    }

    // Try to decrement once; if zero then no prints allowed.
    loop {
        let old = BENCH_DEBUG_PRINTS_LEFT.load(Ordering::Acquire);
        if old == 0 {
            return false;
        }
        if BENCH_DEBUG_PRINTS_LEFT
            .compare_exchange(old, old - 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

#[cfg(not(all(feature = "std", feature = "bench")))]
/// Stub for non-bench builds: never allow per-write bench debug prints.
pub(crate) fn bench_debug_print_allowed() -> bool {
    false
}

impl<'a> MmioWriter<'a> {
    /// Create a new MmioWriter from a raw pointer and length.
    ///
    /// # Safety
    /// The caller must ensure that [base, base + len) is a valid MMIO region.
    #[inline]
    pub unsafe fn new(base: usize, len: usize) -> Self {
        Self {
            base,
            len,
            _phantom: PhantomData,
        }
    }

    /// Create a new MmioWriter from a mutable slice.
    #[inline]
    pub fn from_slice(slice: &mut [u8]) -> Self {
        unsafe { Self::new(slice.as_mut_ptr() as usize, slice.len()) }
    }

    /// Write a slice of bytes to the MMIO region efficiently.
    ///
    /// This will attempt to perform aligned 32-bit/64-bit writes when possible to
    /// reduce the number of volatile writes. It never performs unaligned
    /// u32 writes: any leading bytes to reach 4-byte alignment are emitted
    /// as u8 writes.
    #[inline]
    pub fn write_bytes(&mut self, offset: usize, data: &[u8]) {
        if offset + data.len() > self.len {
            // Panic or ignore? panic is safer for now.
            panic!("MmioWriter::write_bytes: out of bounds");
        }
        let mut ptr = self.base + offset;
        let mut i = 0usize;
        let len = data.len();

        // Align to 8-bytes boundary. If pointer is 4 mod 8 and at least
        // 4 bytes remain, write a single u32 to reach 8-byte alignment
        // (faster than 4 u8 volatile writes). Otherwise emit up to 7 u8
        // writes to reach the 8-byte boundary.
        let align8 = ptr & 7;
        if align8 != 0 {
            if align8 == 4 && i + 4 <= len {
                unsafe {
                    #[cfg(target_endian = "little")]
                    {
                        let v = core::ptr::read_unaligned(data.as_ptr().add(i) as *const u32);
                        mmio::mmio_write_u32(ptr, v);
                    }
                    #[cfg(not(target_endian = "little"))]
                    {
                        let v =
                            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                        mmio::mmio_write_u32(ptr, v);
                    }
                }
                ptr += 4;
                i += 4;
            } else {
                let to_align = core::cmp::min(8 - align8, len - i);
                for _ in 0..to_align {
                    unsafe { mmio::volatile_write::<u8>(ptr, data[i]) };
                    ptr += 1;
                    i += 1;
                }
            }
        }

        // Bulk write u64 when possible. Unroll 4 u64 writes per iteration.
        while i + 32 <= len {
            unsafe {
                #[cfg(target_endian = "little")]
                {
                    let v0 = core::ptr::read_unaligned(data.as_ptr().add(i) as *const u64);
                    let v1 = core::ptr::read_unaligned(data.as_ptr().add(i + 8) as *const u64);
                    let v2 = core::ptr::read_unaligned(data.as_ptr().add(i + 16) as *const u64);
                    let v3 = core::ptr::read_unaligned(data.as_ptr().add(i + 24) as *const u64);
                    mmio::mmio_write_u64(ptr, v0);
                    mmio::mmio_write_u64(ptr + 8, v1);
                    mmio::mmio_write_u64(ptr + 16, v2);
                    mmio::mmio_write_u64(ptr + 24, v3);
                }
                #[cfg(not(target_endian = "little"))]
                {
                    // Fallback for big endian if ever supported
                    // ... (omitted for brevity, existing code had it but little endian is dominant)
                    let v0 = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
                    let v1 = u64::from_le_bytes(data[i + 8..i + 16].try_into().unwrap());
                    let v2 = u64::from_le_bytes(data[i + 16..i + 24].try_into().unwrap());
                    let v3 = u64::from_le_bytes(data[i + 24..i + 32].try_into().unwrap());
                    mmio::mmio_write_u64(ptr, v0);
                    mmio::mmio_write_u64(ptr + 8, v1);
                    mmio::mmio_write_u64(ptr + 16, v2);
                    mmio::mmio_write_u64(ptr + 24, v3);
                }
            }
            ptr += 32;
            i += 32;
        }

        while i + 8 <= len {
            unsafe {
                let v = core::ptr::read_unaligned(data.as_ptr().add(i) as *const u64);
                mmio::mmio_write_u64(ptr, v);
            }
            ptr += 8;
            i += 8;
        }

        // Remaining u32-aligned writes; unroll 4 at a time
        while i + 16 <= len {
            unsafe {
                let v0 = core::ptr::read_unaligned(data.as_ptr().add(i) as *const u32);
                let v1 = core::ptr::read_unaligned(data.as_ptr().add(i + 4) as *const u32);
                let v2 = core::ptr::read_unaligned(data.as_ptr().add(i + 8) as *const u32);
                let v3 = core::ptr::read_unaligned(data.as_ptr().add(i + 12) as *const u32);
                mmio::mmio_write_u32(ptr, v0);
                mmio::mmio_write_u32(ptr + 4, v1);
                mmio::mmio_write_u32(ptr + 8, v2);
                mmio::mmio_write_u32(ptr + 12, v3);
            }
            ptr += 16;
            i += 16;
        }

        while i + 4 <= len {
            unsafe {
                let v = core::ptr::read_unaligned(data.as_ptr().add(i) as *const u32);
                mmio::mmio_write_u32(ptr, v);
            }
            ptr += 4;
            i += 4;
        }

        // Remaining tail bytes
        while i < len {
            unsafe { mmio::volatile_write::<u8>(ptr, data[i]) };
            ptr += 1;
            i += 1;
        }
    }

    /// Write a slice of u32 pixels to an MMIO destination, using u64 pair writes
    /// when possible for improved throughput.
    #[inline]
    pub fn write_u32_slice(&mut self, offset: usize, data: &[u32]) {
        let byte_len = data.len() * 4;
        if offset + byte_len > self.len {
            panic!("MmioWriter::write_u32_slice: out of bounds");
        }

        let mut ptr = self.base + offset;
        let mut i = 0usize;
        let len = data.len();

        // If ptr is 4 mod 8, write a single u32 to reach 8-byte alignment
        if (ptr & 7) == 4 && i < len {
            unsafe { mmio::mmio_write_u32(ptr, data[i]) };
            ptr += 4;
            i += 1;
        }

        // Write u64 pairs; unroll 4 pairs at a time for throughput.
        while i + 7 < len {
            let p0 = (data[i] as u64) | ((data[i + 1] as u64) << 32);
            let p1 = (data[i + 2] as u64) | ((data[i + 3] as u64) << 32);
            let p2 = (data[i + 4] as u64) | ((data[i + 5] as u64) << 32);
            let p3 = (data[i + 6] as u64) | ((data[i + 7] as u64) << 32);
            unsafe {
                mmio::mmio_write_u64(ptr, p0);
                mmio::mmio_write_u64(ptr + 8, p1);
                mmio::mmio_write_u64(ptr + 16, p2);
                mmio::mmio_write_u64(ptr + 24, p3);
            }
            ptr += 32;
            i += 8;
        }

        while i + 1 < len {
            let pair = (data[i] as u64) | ((data[i + 1] as u64) << 32);
            unsafe { mmio::mmio_write_u64(ptr, pair) };
            ptr += 8;
            i += 2;
        }

        if i < len {
            unsafe { mmio::mmio_write_u32(ptr, data[i]) };
        }
    }

    /// Write a slice of bytes using non-temporal (streaming) stores.
    ///
    /// This bypasses the CPU cache and writes directly to memory, which is
    /// optimal for VRAM writes where the data will not be read back immediately.
    /// Uses HAL streaming store functions on x86/x86_64, falls back to volatile
    /// writes on other architectures.
    ///
    /// After calling this method, you should call `mmio::sfence()` to ensure
    /// all streaming stores are globally visible.
    #[inline]
    pub fn write_bytes_streaming(&mut self, offset: usize, data: &[u8]) {
        if offset + data.len() > self.len {
            panic!("MmioWriter::write_bytes_streaming: out of bounds");
        }
        let addr = self.base + offset;
        #[cfg(all(feature = "std", feature = "bench"))]
        if std::env::var("RANY_DEBUG_DRAW").ok().as_deref() == Some("1") {
            eprintln!(
                "write_bytes_streaming: addr=0x{:x} len={} first4={:02x?}",
                addr,
                data.len(),
                &data[..core::cmp::min(4, data.len())]
            );
        }
        unsafe {
            mmio::stream_write_bytes(addr, data);
        }
    }

    /// Write a slice of u32 pixels using non-temporal (streaming) stores.
    ///
    /// This bypasses the CPU cache for better VRAM write throughput.
    /// After calling this method, you should call `mmio::sfence()` to ensure
    /// all streaming stores are globally visible.
    #[inline]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn write_u32_slice_streaming(&mut self, offset: usize, data: &[u32]) {
        let byte_len = data.len() * 4;
        if offset + byte_len > self.len {
            panic!("MmioWriter::write_u32_slice_streaming: out of bounds");
        }

        let mut ptr = self.base + offset;
        let mut i = 0usize;
        let len = data.len();

        #[cfg(all(feature = "std", feature = "bench"))]
        if std::env::var("RANY_DEBUG_DRAW").ok().as_deref() == Some("1") {
            eprintln!(
                "write_u32_slice_mmio_streaming: addr=0x{:x} len={}",
                ptr, len
            );
        }

        // If ptr is 4 mod 8, write a single u32 to reach 8-byte alignment
        if (ptr & 7) == 4 && i < len {
            #[cfg(all(feature = "std", feature = "bench"))]
            if bench_debug_print_allowed() {
                eprintln!("  stream_write_u32 at 0x{:x} val=0x{:x}", ptr, data[i]);
            }
            mmio::stream_write_u32(ptr, data[i]);
            ptr += 4;
            i += 1;
        }

        // Write u64 pairs using streaming stores
        while i + 1 < len {
            let pair = (data[i] as u64) | ((data[i + 1] as u64) << 32);
            #[cfg(all(feature = "std", feature = "bench"))]
            if bench_debug_print_allowed() {
                eprintln!("  stream_write_u64 at 0x{:x} pair=0x{:x}", ptr, pair);
            }
            mmio::stream_write_u64(ptr, pair);
            ptr += 8;
            i += 2;
        }

        // Handle odd trailing u32
        if i < len {
            #[cfg(all(feature = "std", feature = "bench"))]
            if bench_debug_print_allowed() {
                eprintln!("  stream_write_u32 at 0x{:x} val=0x{:x}", ptr, data[i]);
            }
            mmio::stream_write_u32(ptr, data[i]);
        }
    }

    /// Fallback for non-x86: just use volatile writes
    #[inline]
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    pub fn write_u32_slice_streaming(&mut self, offset: usize, data: &[u32]) {
        self.write_u32_slice(offset, data);
    }
}
