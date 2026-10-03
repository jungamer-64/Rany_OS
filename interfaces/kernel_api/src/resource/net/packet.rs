//! Packet windows over one retained allocation. The memory owner supplies a
//! stable initialized region and receives the last lease for recycling or
//! retirement. Window mutation and splitting are owned here, independently of
//! the allocator and of device submission.

use alloc::sync::Arc;
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::{PacketByteCount, PacketMeta, PacketOwnershipError, PacketPayload, PacketWindowError};
use crate::dma::DmaByteCount;
use crate::resource::memory::PhysicalAddress;

/// Stable backing retained by its allocator until all packet windows return.
/// This header has no byte access or release authority outside a packet lease.
/// A retirement callback may return the allocation to a pool or transfer it to
/// a reserved retirement owner; it must retain any unfinished DMA mapping.
pub struct PacketBufferMemory {
    data: NonNull<u8>,
    capacity: DmaByteCount,
    physical: PhysicalAddress,
    references: AtomicUsize,
    allocation: Arc<dyn Send + Sync>,
    owner: NonNull<()>,
    retire: unsafe fn(NonNull<()>),
}

// SAFETY: construction requires stable backing and a thread-safe retirement
// owner. Only packet leases expose bytes, and their accessible ranges are
// disjoint. Header mutation consists solely of the atomic reference count.
unsafe impl Send for PacketBufferMemory {}
// SAFETY: shared header access never creates a byte reference or release token.
unsafe impl Sync for PacketBufferMemory {}

impl PacketBufferMemory {
    /// Establish the backing contract before publishing the header to a pool.
    ///
    /// # Safety
    /// `data` must describe `capacity` initialized bytes in one live allocation.
    /// The physical address must describe that same region, with its entire
    /// range fitting in `u64`. Device admission belongs to the submitting port;
    /// packet metadata and physical addresses never grant DMA authority.
    /// `allocation` independently retains the entire physical backing, even
    /// after the last CPU window returns, including every containing physical
    /// page needed for IOMMU granularity. It confers no byte access or release
    /// authority. Mapping owners retain it until IOTLB retirement completes.
    /// The owner must keep the header, backing, mapping and callback code valid
    /// until every acquired window returns, including during owner shutdown.
    /// No independent mutable reference may access an acquired window. DMA may
    /// only access bytes after a submission has consumed CPU access authority.
    /// `retire(owner)` runs exactly once when the last lease returns, on any
    /// CPU. It must neither unwind nor wait for hardware; unfinished retirement
    /// must move to an already reserved owner. Reuse requires a subsequent
    /// exclusive acquisition from the allocator.
    pub unsafe fn new(
        data: NonNull<u8>,
        capacity: DmaByteCount,
        physical: PhysicalAddress,
        allocation: Arc<dyn Send + Sync>,
        owner: NonNull<()>,
        retire: unsafe fn(NonNull<()>),
    ) -> Self {
        Self {
            data,
            capacity,
            physical,
            references: AtomicUsize::new(0),
            allocation,
            owner,
            retire,
        }
    }

    fn retain(&self) -> bool {
        self.references
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count != 0).then(|| count.checked_add(1)).flatten()
            })
            .is_ok()
    }
}

impl fmt::Debug for PacketBufferMemory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketBufferMemory")
            .field("capacity", &self.capacity)
            .field("references", &self.references.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Physical backing retained independently of packet recycling. This lease
/// grants no CPU byte access and no authority to submit or retire DMA.
#[derive(Clone)]
pub struct PacketBackingLease {
    physical: PhysicalAddress,
    capacity: DmaByteCount,
    allocation: Arc<dyn Send + Sync>,
}
impl PacketBackingLease {
    pub const fn physical_address(&self) -> PhysicalAddress {
        self.physical
    }
    pub const fn capacity(&self) -> DmaByteCount {
        self.capacity
    }
}
impl fmt::Debug for PacketBackingLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketBackingLease")
            .field("physical", &self.physical)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

/// An observed packet range retains its header until descriptor construction
/// ends. It exposes addresses only; device access requires a separate submission
/// authority. Keeping it across synchronous completion prevents pool reuse.
pub struct PacketDmaRegion {
    memory: NonNull<PacketBufferMemory>,
    offset: usize,
    len: PacketByteCount,
}
// SAFETY: this counted lease keeps a thread-safe header alive. It never exposes
// Rust byte references or CPU access authority, and retirement permits any CPU.
unsafe impl Send for PacketDmaRegion {}
// SAFETY: observations only read immutable header fields. No shared operation
// mutates packet bytes or releases the last lease.
unsafe impl Sync for PacketDmaRegion {}
impl PacketDmaRegion {
    fn backing(&self) -> &PacketBufferMemory {
        // SAFETY: the counted region retains the header through this borrow.
        unsafe { self.memory.as_ref() }
    }
    pub fn cpu_ptr(&self) -> *const u8 {
        // SAFETY: creation bounds the range within initialized backing.
        unsafe { self.backing().data.as_ptr().add(self.offset).cast_const() }
    }
    pub fn physical_address(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.backing().physical.as_u64() + self.offset as u64)
    }
    pub const fn len(&self) -> PacketByteCount {
        self.len
    }
    pub fn retains_backing(&self, lease: &PacketBackingLease) -> bool {
        Arc::ptr_eq(&self.backing().allocation, &lease.allocation)
    }
    pub fn backing_lease(&self) -> PacketBackingLease {
        let backing = self.backing();
        PacketBackingLease {
            physical: backing.physical,
            capacity: backing.capacity,
            allocation: Arc::clone(&backing.allocation),
        }
    }
}
impl fmt::Debug for PacketDmaRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketDmaRegion")
            .field("physical", &self.physical_address())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}
impl Drop for PacketDmaRegion {
    fn drop(&mut self) {
        release_reference(self.memory);
    }
}

fn release_reference(memory: NonNull<PacketBufferMemory>) {
    // SAFETY: the caller consumes one retained reference to this live header.
    let backing = unsafe { memory.as_ref() };
    if backing.references.fetch_sub(1, Ordering::AcqRel) == 1 {
        let owner = backing.owner;
        let retire = backing.retire;
        // SAFETY: this was the last window/descriptor. The constructor keeps
        // unfinished mappings independently retained; never access the header
        // after this callback may reclaim it.
        unsafe { retire(owner) };
    }
}

/// Rejection before any new window is published. The allocator retains its
/// backing and may retry after the existing packet windows have returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketAcquireError {
    InvalidHeadroom,
    Busy,
}

#[derive(Debug, Clone, Copy)]
struct PacketWindow {
    lower: usize,
    upper: usize,
    offset: usize,
    len: usize,
}

pub enum PacketFront {
    Whole(PacketRef),
    Prefix {
        front: PacketRef,
        remainder: PacketRef,
    },
}

pub enum PacketPayloadFront {
    Whole(PacketPayload),
    Prefix {
        front: PacketPayload,
        remainder: PacketPayload,
    },
}

/// Unique access to one partition of a retained packet allocation. Splitting
/// partitions the accessible region as well as the visible bytes: neither
/// descendant can grow or retreat into the other's allocation range.
pub struct PacketRef {
    memory: NonNull<PacketBufferMemory>,
    window: PacketWindow,
    meta: PacketMeta,
    _not_sync: PhantomData<*mut ()>,
}

impl PacketRef {
    /// Acquire an empty CPU window from the allocator's free backing.
    ///
    /// # Safety
    /// `memory` must point to a live header constructed under
    /// [`PacketBufferMemory::new`]'s contract. The allocator must retain the
    /// header throughout acquisition and keep it live until retirement. A free
    /// list entry grants exclusive acquisition; an address alone does not.
    ///
    /// # Errors
    /// Invalid headroom and an already acquired backing are distinct failures.
    /// Neither failure consumes or publishes any backing lease.
    pub unsafe fn acquire(
        memory: NonNull<PacketBufferMemory>,
        headroom: usize,
    ) -> Result<Self, PacketAcquireError> {
        // SAFETY: the allocator retains this live header throughout acquisition.
        let backing = unsafe { memory.as_ref() };
        let upper = backing.capacity.get();
        if headroom > upper {
            return Err(PacketAcquireError::InvalidHeadroom);
        }
        backing
            .references
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PacketAcquireError::Busy)?;
        Ok(Self {
            memory,
            window: PacketWindow {
                lower: 0,
                upper,
                offset: headroom,
                len: 0,
            },
            meta: PacketMeta::default(),
            _not_sync: PhantomData,
        })
    }

    fn backing(&self) -> &PacketBufferMemory {
        // SAFETY: this packet retains one count under the backing's contract.
        unsafe { self.memory.as_ref() }
    }

    pub fn as_ptr(&self) -> *const u8 {
        // SAFETY: the private window remains within its allocation partition.
        unsafe { self.backing().data.as_ptr().add(self.window.offset) }
    }

    /// Observe an initialized visible range without granting device access.
    ///
    /// # Errors
    /// Out-of-bounds ranges and a saturated retention count do not publish a
    /// descriptor. An empty range is excluded by `PacketByteCount`.
    pub fn dma_region(
        &self,
        offset: usize,
        len: PacketByteCount,
    ) -> Result<PacketDmaRegion, PacketWindowError> {
        if offset > self.len() || len.get() > self.len() - offset {
            return Err(PacketWindowError::OutOfBounds);
        }
        self.retain_dma_region(self.window.offset + offset, len)
    }

    fn retain_dma_region(
        &self,
        offset: usize,
        len: PacketByteCount,
    ) -> Result<PacketDmaRegion, PacketWindowError> {
        if !self.backing().retain() {
            return Err(PacketWindowError::ReferenceLimit);
        }
        Ok(PacketDmaRegion {
            memory: self.memory,
            offset,
            len,
        })
    }

    /// Observe an empty packet's writable capacity for RX admission. The owner
    /// remains inaccessible inside `RxBuffer` until hardware completion.
    pub(crate) fn rx_dma_region(&self) -> Option<PacketDmaRegion> {
        if !self.is_empty() {
            return None;
        }
        let len = PacketByteCount::new(self.data_capacity())?;
        self.retain_dma_region(self.window.offset, len).ok()
    }

    pub fn data(&self) -> &[u8] {
        // SAFETY: the visible window is initialized and CPU-owned for this
        // borrow. Device submission consumes access to the containing packet.
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len()) }
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        // SAFETY: this unique lease and mutable borrow exclude other access to
        // this partition. Split descendants own disjoint accessible regions.
        unsafe { core::slice::from_raw_parts_mut(self.as_ptr().cast_mut(), self.len()) }
    }

    pub const fn len(&self) -> usize {
        self.window.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub const fn data_capacity(&self) -> usize {
        self.window.upper - self.window.offset
    }
    pub const fn headroom(&self) -> usize {
        self.window.offset - self.window.lower
    }
    pub const fn tailroom(&self) -> usize {
        self.data_capacity() - self.len()
    }

    pub fn phys_addr(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.backing().physical.as_u64() + self.window.offset as u64)
    }

    /// # Errors
    /// A length beyond this partition's capacity leaves the window unchanged.
    /// Successful growth initializes the new tail before publishing its length.
    pub fn try_resize(&mut self, len: usize) -> Result<(), PacketWindowError> {
        if len > self.data_capacity() {
            return Err(PacketWindowError::OutOfBounds);
        }
        if len > self.len() {
            // SAFETY: checked capacity and exclusive ownership cover the new
            // tail; the old visible prefix remains untouched.
            unsafe {
                self.as_ptr()
                    .cast_mut()
                    .add(self.len())
                    .write_bytes(0, len - self.len())
            };
        }
        self.window.len = len;
        Ok(())
    }

    /// # Errors
    /// Advancing beyond the visible bytes changes neither origin nor length.
    pub fn try_advance(&mut self, size: PacketByteCount) -> Result<(), PacketWindowError> {
        if size.get() > self.len() {
            return Err(PacketWindowError::OutOfBounds);
        }
        self.window.offset += size.get();
        self.window.len -= size.get();
        Ok(())
    }

    /// # Errors
    /// Retreat beyond this partition's headroom leaves the window unchanged.
    /// The new prefix is initialized before becoming safely visible.
    pub fn try_retreat(&mut self, size: PacketByteCount) -> Result<(), PacketWindowError> {
        if size.get() > self.headroom() {
            return Err(PacketWindowError::OutOfBounds);
        }
        self.window.offset -= size.get();
        self.window.len += size.get();
        // SAFETY: the validated new prefix lies in this exclusive partition.
        unsafe { self.as_ptr().cast_mut().write_bytes(0, size.get()) };
        Ok(())
    }

    /// # Errors
    /// An out-of-bounds prefix or reference-count exhaustion returns the
    /// unchanged owner. Splitting neither copies bytes nor allocates memory.
    pub fn try_take_front(
        self,
        len: PacketByteCount,
    ) -> Result<PacketFront, PacketOwnershipError<Self>> {
        if len.get() > self.len() {
            return Err(PacketOwnershipError::new(
                PacketWindowError::OutOfBounds,
                self,
            ));
        }
        if len.get() == self.len() {
            return Ok(PacketFront::Whole(self));
        }
        if !self.backing().retain() {
            return Err(PacketOwnershipError::new(
                PacketWindowError::ReferenceLimit,
                self,
            ));
        }
        let packet = ManuallyDrop::new(self);
        let boundary = packet.window.offset + len.get();
        Ok(PacketFront::Prefix {
            front: Self {
                memory: packet.memory,
                window: PacketWindow {
                    upper: boundary,
                    len: len.get(),
                    ..packet.window
                },
                meta: packet.meta,
                _not_sync: PhantomData,
            },
            remainder: Self {
                memory: packet.memory,
                window: PacketWindow {
                    lower: boundary,
                    offset: boundary,
                    len: packet.window.len - len.get(),
                    ..packet.window
                },
                meta: packet.meta,
                _not_sync: PhantomData,
            },
        })
    }

    /// # Safety
    /// The device has finished writing `len` initialized bytes in this window
    /// and no longer has write access. Completion must belong to this lease.
    pub(crate) unsafe fn publish_device_written(
        &mut self,
        len: PacketByteCount,
    ) -> Result<(), PacketWindowError> {
        if len.get() > self.data_capacity() {
            return Err(PacketWindowError::OutOfBounds);
        }
        self.window.len = len.get();
        Ok(())
    }

    pub fn meta(&self) -> &PacketMeta {
        &self.meta
    }
    pub fn meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.meta
    }
    pub fn set_meta(&mut self, meta: PacketMeta) {
        self.meta = meta;
    }
}

impl Drop for PacketRef {
    fn drop(&mut self) {
        release_reference(self.memory);
    }
}

// SAFETY: unique partition ownership moves with the packet; retirement is
// thread-safe, and an active byte borrow prevents moving the packet.
unsafe impl Send for PacketRef {}

impl fmt::Debug for PacketRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketRef")
            .field("len", &self.len())
            .field("headroom", &self.headroom())
            .field("tailroom", &self.tailroom())
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::mem::MaybeUninit;

    struct Bytes(core::cell::UnsafeCell<Box<[u8]>>);
    // SAFETY: the fixture exposes no byte access; packet windows own disjoint
    // initialized ranges and mapping leases only retain allocation lifetime.
    unsafe impl Sync for Bytes {}

    struct Allocation {
        header: MaybeUninit<PacketBufferMemory>,
        bytes: Arc<Bytes>,
        returns: Arc<AtomicUsize>,
    }

    unsafe fn retire_allocation(owner: NonNull<()>) {
        // SAFETY: fixture construction transferred one Box to the last-window
        // retirement callback. This call consumes it exactly once.
        let mut allocation = unsafe { Box::from_raw(owner.cast::<Allocation>().as_ptr()) };
        allocation.returns.fetch_add(1, Ordering::SeqCst);
        // SAFETY: this last-reference callback consumes the initialized header.
        unsafe { allocation.header.assume_init_drop() };
    }

    fn packet(capacity: usize, headroom: usize) -> (PacketRef, Arc<AtomicUsize>) {
        let returns = Arc::new(AtomicUsize::new(0));
        let mut bytes = Arc::new(Bytes(core::cell::UnsafeCell::new(
            alloc::vec![0xab; capacity].into_boxed_slice(),
        )));
        let data =
            NonNull::new(Arc::get_mut(&mut bytes).unwrap().0.get_mut().as_mut_ptr()).unwrap();
        let mut allocation = Box::new(Allocation {
            header: MaybeUninit::uninit(),
            bytes,
            returns: Arc::clone(&returns),
        });
        let owner = NonNull::from(allocation.as_mut()).cast();
        // SAFETY: this Box retains initialized backing and the stable header.
        // Its unique ownership moves to the callback after acquisition below;
        // the callback frees it only after the last packet window returns.
        allocation.header.write(unsafe {
            PacketBufferMemory::new(
                data,
                DmaByteCount::new(capacity).unwrap(),
                PhysicalAddress::new(0x1000),
                Arc::clone(&allocation.bytes) as Arc<dyn Send + Sync>,
                owner,
                retire_allocation,
            )
        });
        let header = NonNull::new(allocation.header.as_mut_ptr()).unwrap();
        // SAFETY: this is the allocator's first exclusive acquisition of the
        // retained live header. Failed acquisition leaves the Box owned here.
        let packet = unsafe { PacketRef::acquire(header, headroom) }.unwrap();
        let _owner = Box::into_raw(allocation);
        (packet, returns)
    }

    #[test]
    fn descriptor_visit_and_mapping_retention_have_separate_lifetimes() {
        let (mut packet, returns) = packet(32, 8);
        packet.try_resize(8).unwrap();
        let region = packet
            .dma_region(2, PacketByteCount::new(4).unwrap())
            .unwrap();
        let mapping_backing = region.backing_lease();
        let allocation = Arc::downgrade(&mapping_backing.allocation);
        assert_eq!(region.physical_address().as_u64(), 0x100a);
        assert_eq!(region.len().get(), 4);
        drop(packet);
        assert_eq!(returns.load(Ordering::SeqCst), 0);
        drop(region);
        assert_eq!(returns.load(Ordering::SeqCst), 1);
        assert!(allocation.upgrade().is_some());
        drop(mapping_backing);
        assert!(allocation.upgrade().is_none());
    }

    #[test]
    fn descriptor_bounds_are_visible_bytes_and_split_views_share_backing() {
        let (mut packet, returns) = packet(32, 8);
        packet.try_resize(8).unwrap();
        assert!(matches!(
            packet.dma_region(7, PacketByteCount::new(2).unwrap()),
            Err(PacketWindowError::OutOfBounds)
        ));
        let backing = packet
            .dma_region(0, PacketByteCount::new(1).unwrap())
            .unwrap()
            .backing_lease();
        let PacketFront::Prefix { front, remainder } = packet
            .try_take_front(PacketByteCount::new(3).unwrap())
            .unwrap()
        else {
            panic!("partial split");
        };
        let a = front
            .dma_region(0, PacketByteCount::new(3).unwrap())
            .unwrap();
        let b = remainder
            .dma_region(0, PacketByteCount::new(5).unwrap())
            .unwrap();
        assert!(a.retains_backing(&backing));
        assert!(b.retains_backing(&backing));
        assert_eq!(
            b.physical_address().as_u64() - a.physical_address().as_u64(),
            3
        );
        drop((front, remainder, a));
        assert_eq!(returns.load(Ordering::SeqCst), 0);
        drop(b);
        assert_eq!(returns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn growth_initializes_only_the_new_visible_tail_and_rejection_preserves_bytes() {
        let (mut packet, returns) = packet(32, 8);
        packet.try_resize(4).unwrap();
        assert_eq!(packet.data(), &[0; 4]);
        packet.data_mut().copy_from_slice(b"abcd");
        packet.try_resize(8).unwrap();
        assert_eq!(packet.data(), b"abcd\0\0\0\0");
        assert_eq!(packet.try_resize(25), Err(PacketWindowError::OutOfBounds));
        assert_eq!(packet.data(), b"abcd\0\0\0\0");
        assert_eq!(
            packet.try_advance(PacketByteCount::new(9).unwrap()),
            Err(PacketWindowError::OutOfBounds)
        );
        assert_eq!(packet.len(), 8);
        drop(packet);
        assert_eq!(returns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn split_partitions_all_mutable_capacity_and_retains_backing_until_both_return() {
        let (mut packet, returns) = packet(32, 8);
        packet.try_resize(6).unwrap();
        packet.data_mut().copy_from_slice(b"abcdef");
        let PacketFront::Prefix {
            mut front,
            mut remainder,
        } = packet
            .try_take_front(PacketByteCount::new(3).unwrap())
            .unwrap()
        else {
            panic!("partial split");
        };
        assert_eq!(front.data(), b"abc");
        assert_eq!(remainder.data(), b"def");
        assert_eq!(front.tailroom(), 0);
        assert_eq!(remainder.headroom(), 0);
        assert_eq!(front.try_resize(4), Err(PacketWindowError::OutOfBounds));
        assert_eq!(
            remainder.try_retreat(PacketByteCount::new(1).unwrap()),
            Err(PacketWindowError::OutOfBounds)
        );
        front.data_mut()[0] = b'x';
        remainder.data_mut()[0] = b'y';
        assert_eq!(front.data(), b"xbc");
        assert_eq!(remainder.data(), b"yef");
        drop(front);
        assert_eq!(returns.load(Ordering::SeqCst), 0);
        drop(remainder);
        assert_eq!(returns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reference_limit_returns_the_unsplit_owner() {
        let (mut packet, returns) = packet(32, 8);
        packet.try_resize(6).unwrap();
        packet
            .backing()
            .references
            .store(usize::MAX, Ordering::Relaxed);
        let error = packet
            .try_take_front(PacketByteCount::new(3).unwrap())
            .err()
            .unwrap();
        assert_eq!(error.cause(), PacketWindowError::ReferenceLimit);
        let packet = error.into_owner();
        assert_eq!(packet.len(), 6);
        packet.backing().references.store(1, Ordering::Relaxed);
        drop(packet);
        assert_eq!(returns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn acquisition_rejects_a_busy_header_and_invalid_headroom_without_changing_its_owner() {
        let (packet, returns) = packet(16, 4);
        // SAFETY: the current lease retains this fixture's live header across
        // both rejection attempts; neither is permitted to publish a window.
        assert_eq!(
            unsafe { PacketRef::acquire(packet.memory, 17) }.err(),
            Some(PacketAcquireError::InvalidHeadroom)
        );
        // SAFETY: the same retained header cannot be exclusively acquired twice.
        assert_eq!(
            unsafe { PacketRef::acquire(packet.memory, 0) }.err(),
            Some(PacketAcquireError::Busy)
        );
        assert_eq!(packet.headroom(), 4);
        drop(packet);
        assert_eq!(returns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dma_completion_publishes_only_the_written_prefix_without_zeroing_it() {
        let (mut packet, returns) = packet(16, 4);
        // SAFETY: this fixture simulates a completed write into its exclusive
        // unpublished region and holds no outstanding device access.
        unsafe { packet.as_ptr().cast_mut().write_bytes(0x7e, 3) };
        // SAFETY: exactly these three bytes were initialized by the completed
        // fixture operation; publication must preserve their contents.
        unsafe { packet.publish_device_written(PacketByteCount::new(3).unwrap()) }.unwrap();
        assert_eq!(packet.data(), &[0x7e; 3]);
        assert_eq!(packet.tailroom(), 9);
        drop(packet);
        assert_eq!(returns.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn invalid_rx_layout_returns_the_completed_buffer_for_corrected_publication() {
        use crate::netdev::{NetRxFrameLayout, NetRxMeta, RxBuffer};
        let (packet, returns) = packet(16, 4);
        let buffer = RxBuffer::try_from_empty_packet(packet).unwrap();
        // SAFETY: the fixture exclusively owns this unpublished region and
        // simulates a device write that is finished before completion.
        unsafe {
            buffer
                .writable_region()
                .cpu_ptr()
                .cast_mut()
                .write_bytes(0x3e, 3)
        };
        let invalid = NetRxMeta::new(
            0,
            NetRxFrameLayout::whole_payload(PacketByteCount::new(13).unwrap()).unwrap(),
            0,
        );
        // SAFETY: device access ended. The invalid reported length must be
        // rejected without publishing bytes or losing the completed owner.
        let error = unsafe { buffer.complete(invalid) }.err().unwrap();
        assert_eq!(error.cause(), PacketWindowError::OutOfBounds);
        assert_eq!(returns.load(Ordering::SeqCst), 0);
        let valid = NetRxMeta::new(
            0,
            NetRxFrameLayout::whole_payload(PacketByteCount::new(3).unwrap()).unwrap(),
            0,
        );
        // SAFETY: this corrected layout describes the same three completed
        // bytes. The returned owner has not been reposted to any device.
        let received = unsafe { error.into_buffer().complete(valid) }.unwrap();
        let (packet, _) = received.into_parts();
        assert_eq!(packet.data(), &[0x3e; 3]);
        drop(packet);
        assert_eq!(returns.load(Ordering::SeqCst), 1);
    }
}
