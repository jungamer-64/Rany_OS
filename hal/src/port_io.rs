// hal/src/port_io.rs - Centralized wrappers for x86_64 port I/O
#![allow(dead_code)]

use x86_64::instructions::port::{Port as XPort, PortRead, PortWrite};

/// Read a byte from a port
#[inline]
pub fn inb(port: u16) -> u8 {
    unsafe { XPort::new(port).read() }
}

/// Write a byte to a port
#[inline]
pub fn outb(port: u16, value: u8) {
    unsafe { XPort::new(port).write(value) }
}

/// Read a 16-bit word from a port
#[inline]
pub fn inw(port: u16) -> u16 {
    unsafe { XPort::new(port).read() }
}

/// Write a 16-bit word to a port
#[inline]
pub fn outw(port: u16, value: u16) {
    unsafe { XPort::new(port).write(value) }
}

/// Read a 32-bit word from a port
#[inline]
pub fn inl(port: u16) -> u32 {
    unsafe { XPort::new(port).read() }
}

/// Write a 32-bit word to a port
#[inline]
pub fn outl(port: u16, value: u32) {
    unsafe { XPort::new(port).write(value) }
}

/// Provide a small abstraction to wrap port access and accept u8/u16/u32
/// transparently where appropriate.
#[inline]
pub fn out(port: u16, data: u32) {
    // choose width based on value range (simple approximation)
    if data <= 0xFF {
        outb(port, data as u8)
    } else if data <= 0xFFFF {
        outw(port, data as u16)
    } else {
        outl(port, data)
    }
}

#[inline]
pub fn inp(port: u16) -> u32 {
    // only return 32-bit value; readers may narrow if needed
    inl(port)
}

/// IoPort is a small safe wrapper around the raw x86_64 Port type.
/// It exposes safe read/write methods by encapsulating the required unsafe
/// operations within the implementation. This reduces the number of
/// callers that need to use `unsafe { ... }` blocks for port I/O.
pub struct IoPort<T> {
    inner: XPort<T>,
    port: u16,
}

impl<T> IoPort<T>
where
    T: Copy + PortRead + PortWrite,
{
    pub const fn new(port: u16) -> Self {
        Self { inner: XPort::new(port), port }
    }

    pub fn read(&mut self) -> T {
        unsafe { self.inner.read() }
    }

    pub fn write(&mut self, value: T) {
        unsafe { self.inner.write(value) }
    }
}

// Provide REP INSW/OUTSW for word transfers (16-bit) on IoPort<u16>
impl IoPort<u16> {
    /// REP INSW - read `buffer.len()` u16 words from the given port.
    ///
    /// # Safety
    /// - The caller must ensure `buffer` is valid for writes and is properly aligned.
    /// - This uses the `rep insw` instruction and therefore depends on `x86_64` PIO semantics.
    #[inline]
    pub unsafe fn read_words(&mut self, buffer: &mut [u16]) {
        unsafe {
            core::arch::asm!(
                "rep insw",
                in("dx") self.port,
                in("rdi") buffer.as_mut_ptr(),
                in("rcx") buffer.len(),
                options(nostack)
            );
        }
    }

    /// REP OUTSW - write `buffer.len()` u16 words to the given port.
    ///
    /// # Safety
    /// - The caller must ensure `buffer` is valid for reads.
    /// - This uses the `rep outsw` instruction and relies on `x86_64` PIO semantics.
    #[inline]
    pub unsafe fn write_words(&mut self, buffer: &[u16]) {
        unsafe {
            core::arch::asm!(
                "rep outsw",
                in("dx") self.port,
                in("rsi") buffer.as_ptr(),
                in("rcx") buffer.len(),
                options(nostack)
            );
        }
    }
}
// Convenience aliases for common types
pub type PortU8 = IoPort<u8>;
pub type PortU16 = IoPort<u16>;
pub type PortU32 = IoPort<u32>;
