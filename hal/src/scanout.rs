//! Exclusive byte access to a retained scanout mapping. Register apertures use
//! `MappedMmio`; scanout memory has no read/write register side effects.

use alloc::sync::Arc;
use core::{cell::Cell, marker::PhantomData, ops::Range};

/// Invalid scanout geometry or a request outside its retained mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanoutError {
    InvalidMapping,
    OutOfBounds,
    InvalidPattern,
}

/// Retains the mapping and its exclusive CPU write authority. Hardware may read
/// pixels concurrently, but may not write them. This value cannot be cloned.
pub struct ScanoutBuffer {
    base: usize,
    length: usize,
    _owner: Arc<dyn Send + Sync>,
    _exclusive: PhantomData<Cell<()>>,
}

impl ScanoutBuffer {
    /// Adopts an externally retained pixel mapping.
    ///
    /// # Safety
    /// `owner` must keep this entire writable mapping live and exclude remap,
    /// unmap, CPU aliases, and device writes until the buffer is dropped. Every
    /// byte is initialized and readable without register side effects. Integer
    /// stores are supported, including x86 streaming stores with the configured
    /// cache type. The mapping must not contain ordinary aliased Rust objects.
    /// Hardware scanout may read the mapping without transferring write authority.
    /// For Rust allocations, `base` must expose the retained allocation's pointer
    /// provenance before conversion to an integer address.
    ///
    /// # Errors
    /// Returns `InvalidMapping` for empty, null, overflowing or oversized spans.
    #[expect(
        unsafe_code,
        reason = "mapping lifetime and exclusivity come from its resource owner"
    )]
    pub unsafe fn from_raw_parts(
        owner: Arc<dyn Send + Sync>,
        base: usize,
        length: usize,
    ) -> Result<Self, ScanoutError> {
        if base == 0
            || length == 0
            || length > isize::MAX as usize
            || base.checked_add(length - 1).is_none()
        {
            return Err(ScanoutError::InvalidMapping);
        }
        Ok(Self {
            base,
            length,
            _owner: owner,
            _exclusive: PhantomData,
        })
    }

    /// Size of the retained mapping.
    pub const fn len(&self) -> usize {
        self.length
    }
    /// Mappings are always nonempty.
    pub const fn is_empty(&self) -> bool {
        false
    }

    fn check(&self, offset: usize, length: usize) -> Result<(), ScanoutError> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.length)
        {
            return Err(ScanoutError::OutOfBounds);
        }
        Ok(())
    }

    /// Attenuates writes to one borrow of the checked span. No allocation, lock,
    /// or fence is performed; the caller fences after its complete drawing batch.
    ///
    /// # Errors
    /// Returns `OutOfBounds` before any access for an overflowing or excessive span.
    pub fn region_mut(
        &mut self,
        offset: usize,
        length: usize,
    ) -> Result<ScanoutRegion<'_>, ScanoutError> {
        self.check(offset, length)?;
        Ok(ScanoutRegion {
            base: if length == 0 {
                self.base
            } else {
                self.base + offset
            },
            length,
            _mapping: PhantomData,
        })
    }

    /// Reads an exact byte span without making a Rust reference to device memory.
    ///
    /// # Errors
    /// Returns `OutOfBounds` before accessing an invalid span.
    #[expect(
        unsafe_code,
        reason = "volatile byte reads remain inside the retained checked mapping"
    )]
    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), ScanoutError> {
        self.check(offset, output.len())?;
        order_readback();
        // LOOP_PROOF: mode=bounded; reason=The output slice has a finite length and every byte is visited once.;
        for (index, byte) in output.iter_mut().enumerate() {
            // SAFETY: the owner retains initialized side-effect-free bytes and
            // the complete source range was checked before any access.
            *byte = unsafe { core::ptr::read_volatile((self.base + offset + index) as *const u8) };
        }
        Ok(())
    }

    /// Copies with memmove overlap semantics and volatile device accesses.
    ///
    /// # Errors
    /// Returns `OutOfBounds` before any write if either complete span is invalid.
    #[expect(
        unsafe_code,
        reason = "device memory cannot be borrowed as an ordinary Rust slice"
    )]
    pub fn copy_within(
        &mut self,
        source: Range<usize>,
        destination: usize,
    ) -> Result<(), ScanoutError> {
        let length = source
            .end
            .checked_sub(source.start)
            .ok_or(ScanoutError::OutOfBounds)?;
        self.check(source.start, length)?;
        self.check(destination, length)?;
        order_readback();
        // LOOP_PROOF: mode=bounded; reason=The checked finite byte count decreases by one for every copied byte.;
        for step in 0..length {
            let index = if destination > source.start {
                length - step - 1
            } else {
                step
            };
            // SAFETY: both spans were checked, the owner excludes writers, and
            // copy direction prevents overwriting bytes which still need reading.
            unsafe {
                let value =
                    core::ptr::read_volatile((self.base + source.start + index) as *const u8);
                core::ptr::write_volatile((self.base + destination + index) as *mut u8, value);
            }
        }
        Ok(())
    }
}

impl Drop for ScanoutBuffer {
    fn drop(&mut self) {
        // Streaming writes must finish before releasing the mapping/allocation
        // owner. Drawing callers retain control of fences between batches.
        crate::mmio::sfence();
    }
}

/// One exclusive, bounded write span. Its mapping owner cannot be dropped,
/// moved or borrowed again while this value is live.
pub struct ScanoutRegion<'mapping> {
    base: usize,
    length: usize,
    _mapping: PhantomData<&'mapping mut ScanoutBuffer>,
}

impl ScanoutRegion<'_> {
    pub const fn len(&self) -> usize {
        self.length
    }
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Attenuates the current batch's write span. The returned borrow excludes
    /// access to its parent until it is released; no new resource is acquired.
    ///
    /// # Errors
    /// Rejects an overflowing or out-of-span byte range before any access.
    pub fn subregion_mut(
        &mut self,
        offset: usize,
        length: usize,
    ) -> Result<ScanoutRegion<'_>, ScanoutError> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.length)
        {
            return Err(ScanoutError::OutOfBounds);
        }
        let base = if length == 0 {
            self.base
        } else {
            self.base + offset
        };
        Ok(ScanoutRegion {
            base,
            length,
            _mapping: PhantomData,
        })
    }

    /// Writes the entire span. Leading/trailing bytes use volatile stores;
    /// aligned bulk stores use non-temporal x86 instructions without a per-row
    /// fence. Use `hal::mmio::sfence` before publication to scanout.
    ///
    /// # Errors
    /// Returns `OutOfBounds` without writes unless the input exactly fills this span.
    #[expect(
        unsafe_code,
        reason = "bounded scanout writes and architecture streaming stores"
    )]
    pub fn write_bytes(&mut self, input: &[u8]) -> Result<(), ScanoutError> {
        if input.len() != self.length {
            return Err(ScanoutError::OutOfBounds);
        }
        let mut index = 0;
        // LOOP_PROOF: mode=bounded; reason=Alignment consumes at most seven bytes within the checked input span.;
        while index < self.length && (self.base + index) & 7 != 0 {
            // SAFETY: index is within the exclusively borrowed span.
            unsafe {
                core::ptr::write_volatile((self.base + index) as *mut u8, input[index]);
            }
            index += 1;
        }
        // LOOP_PROOF: mode=bounded; reason=Every iteration consumes eight bytes from the finite checked span.;
        while self.length - index >= 8 {
            // SAFETY: eight source bytes are initialized and contained in input;
            // read_unaligned imposes no alignment on the source allocation.
            let value =
                unsafe { core::ptr::read_unaligned(input.as_ptr().add(index).cast::<u64>()) };
            // SAFETY: the prefix aligned the destination and this complete eight
            // byte store is inside the exclusive mapping borrow.
            unsafe {
                store_word(self.base + index, value);
            }
            index += 8;
        }
        // LOOP_PROOF: mode=bounded; reason=The remaining tail contains fewer than eight bytes.;
        while index < self.length {
            // SAFETY: index is within the exclusively borrowed span.
            unsafe {
                core::ptr::write_volatile((self.base + index) as *mut u8, input[index]);
            }
            index += 1;
        }
        Ok(())
    }

    /// Fills a span with repeated one, two, three or four byte pixels. Bounds and
    /// divisibility are checked before writes. The aligned word phase preserves
    /// three byte pixel ordering across every store.
    ///
    /// # Errors
    /// Returns `InvalidPattern` without writes for unsupported or partial pixels.
    #[expect(
        unsafe_code,
        reason = "bounded pixel pattern stores into an exclusive scanout borrow"
    )]
    pub fn fill(&mut self, pixel: &[u8]) -> Result<(), ScanoutError> {
        if !(1..=4).contains(&pixel.len()) || !self.length.is_multiple_of(pixel.len()) {
            return Err(ScanoutError::InvalidPattern);
        }
        let mut index = 0;
        // LOOP_PROOF: mode=bounded; reason=The prefix consumes at most seven bytes from the checked span.;
        while index < self.length && (self.base + index) & 7 != 0 {
            // SAFETY: index is within the exclusively borrowed span.
            unsafe {
                core::ptr::write_volatile(
                    (self.base + index) as *mut u8,
                    pixel[index % pixel.len()],
                );
            }
            index += 1;
        }
        let mut patterns = [0u64; 4];
        // LOOP_PROOF: mode=bounded; reason=There are at most four pixel phases and eight bytes in each word.;
        for (phase, value) in patterns.iter_mut().enumerate().take(pixel.len()) {
            let bytes = core::array::from_fn(|lane| pixel[(phase + lane) % pixel.len()]);
            *value = u64::from_ne_bytes(bytes);
        }
        // LOOP_PROOF: mode=bounded; reason=Each word consumes eight bytes from the finite checked span.;
        while self.length - index >= 8 {
            // SAFETY: the destination is aligned and eight bytes remain in this
            // exclusive mapping borrow. The phase indexes a prepared pattern.
            unsafe {
                store_word(self.base + index, patterns[index % pixel.len()]);
            }
            index += 8;
        }
        // LOOP_PROOF: mode=bounded; reason=The remaining tail contains fewer than eight bytes.;
        while index < self.length {
            // SAFETY: index is within the exclusively borrowed span.
            unsafe {
                core::ptr::write_volatile(
                    (self.base + index) as *mut u8,
                    pixel[index % pixel.len()],
                );
            }
            index += 1;
        }
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "private aligned word store for a checked scanout borrow"
)]
unsafe fn store_word(address: usize, value: u64) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: callers provide a live, aligned, exclusive eight byte device span.
    // movnti uses only a general register. Omitting nomem retains compiler order.
    unsafe {
        core::arch::asm!("movnti qword ptr [{address}], {value}", address = in(reg) address,
        value = in(reg) value, options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: the same checked aligned device span accepts a volatile word store.
    unsafe {
        core::ptr::write_volatile(address as *mut u64, value);
    }
}

#[expect(
    unsafe_code,
    reason = "orders prior non-temporal writes before device readback"
)]
fn order_readback() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    // SAFETY: supported x86 scanout platforms have SSE2 and mfence touches no
    // caller memory or SIMD register. Omitting nomem also orders the compiler.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(
        unsafe_code,
        reason = "this test transfers exclusive access to its retained allocation"
    )]
    fn mapping() -> (ScanoutBuffer, Arc<[u8; 512]>) {
        let mut owner = Arc::new([0xa5; 512]);
        let base = Arc::get_mut(&mut owner).unwrap().as_mut_ptr() as usize;
        // SAFETY: this private test owner retains the unique initialized byte
        // allocation. Tests access its bytes only after the mapping is dropped.
        let mapped = unsafe { ScanoutBuffer::from_raw_parts(owner.clone(), base, 512) }.unwrap();
        (mapped, owner)
    }

    #[test]
    fn writes_cover_every_alignment_without_touching_surrounding_bytes() {
        // LOOP_PROOF: mode=bounded; reason=Eight destination alignments and seventeen finite tail lengths are checked.;
        for offset in 0..8 {
            for length in 0..=65 {
                let (mut buffer, owner) = mapping();
                let data: alloc::vec::Vec<u8> = (0..length).map(|index| index as u8).collect();
                buffer
                    .region_mut(offset, length)
                    .unwrap()
                    .write_bytes(&data)
                    .unwrap();
                order_readback();
                drop(buffer);
                assert_eq!(&owner[offset..offset + length], data.as_slice());
                assert!(owner[..offset].iter().all(|&byte| byte == 0xa5));
                assert!(owner[offset + length..].iter().all(|&byte| byte == 0xa5));
            }
        }
    }

    #[test]
    fn pixel_patterns_preserve_byte_order_and_store_phase() {
        // LOOP_PROOF: mode=bounded; reason=All four pixel sizes and eight store alignments have finite vectors.;
        for pixel_size in 1..=4 {
            for offset in 0..8 {
                let (mut buffer, owner) = mapping();
                let pattern = [7, 23, 101, 239];
                let length = pixel_size * 71;
                buffer
                    .region_mut(offset, length)
                    .unwrap()
                    .fill(&pattern[..pixel_size])
                    .unwrap();
                order_readback();
                drop(buffer);
                for index in 0..length {
                    assert_eq!(owner[offset + index], pattern[index % pixel_size]);
                }
                assert!(owner[..offset].iter().all(|&byte| byte == 0xa5));
                assert!(owner[offset + length..].iter().all(|&byte| byte == 0xa5));
            }
        }
    }

    #[test]
    fn invalid_requests_have_no_partial_write() {
        let (mut buffer, owner) = mapping();
        assert!(matches!(
            buffer.region_mut(usize::MAX, 4),
            Err(ScanoutError::OutOfBounds)
        ));
        assert!(matches!(
            buffer.region_mut(510, 4),
            Err(ScanoutError::OutOfBounds)
        ));
        let mut span = buffer.region_mut(0, 12).unwrap();
        assert_eq!(span.write_bytes(&[0; 11]), Err(ScanoutError::OutOfBounds));
        assert_eq!(span.fill(&[]), Err(ScanoutError::InvalidPattern));
        assert_eq!(span.fill(&[0; 5]), Err(ScanoutError::InvalidPattern));
        assert_eq!(
            buffer.copy_within(510..513, 0),
            Err(ScanoutError::OutOfBounds)
        );
        drop(buffer);
        assert!(owner.iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn overlapping_copies_match_independent_memmove_vectors() {
        // LOOP_PROOF: mode=bounded; reason=Six fixed source and destination overlaps are exercised.;
        for (source, destination) in [
            (0..31, 1),
            (1..32, 0),
            (0..16, 32),
            (8..24, 8),
            (0..0, 512),
            (400..512, 399),
        ] {
            let (mut buffer, owner) = mapping();
            let data: alloc::vec::Vec<u8> = (0..512).map(|index| index as u8).collect();
            buffer
                .region_mut(0, 512)
                .unwrap()
                .write_bytes(&data)
                .unwrap();
            let mut expected = data.clone();
            expected.copy_within(source.clone(), destination);
            buffer.copy_within(source, destination).unwrap();
            order_readback();
            drop(buffer);
            assert_eq!(owner.as_slice(), expected.as_slice());
        }
    }

    #[test]
    fn mapping_retains_its_allocation_after_the_callers_owner_is_dropped() {
        let (mut buffer, owner) = mapping();
        let weak = Arc::downgrade(&owner);
        drop(owner);
        buffer
            .region_mut(0, 4)
            .unwrap()
            .write_bytes(&[1, 2, 3, 4])
            .unwrap();
        let mut read = [0; 4];
        buffer.read(0, &mut read).unwrap();
        assert_eq!(read, [1, 2, 3, 4]);
        assert!(weak.upgrade().is_some());
        drop(buffer);
        assert!(weak.upgrade().is_none());
    }
}
