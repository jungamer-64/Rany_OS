// ============================================================================
// kernel_api/src/types.rs - Shared Type Definitions
// ============================================================================
//!
//! Pure type definitions that can be used by kernel, drivers, and applications.
//! These types have no kernel dependencies.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, MaybeUninit, align_of, size_of};
use core::num::NonZeroUsize;
use core::ops::{Add, AddAssign};
use core::ptr;

/// Task handle - opaque reference to a spawned task
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskHandle {
    id: u64,
}

impl TaskHandle {
    /// Create a new task handle (kernel-only)
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Get the task ID
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// Interface selection used by network-related KAPI calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceScope {
    #[default]
    Any,
    Pinned(u16),
}

impl InterfaceScope {
    pub const fn pinned(if_id: u16) -> Self {
        Self::Pinned(if_id)
    }

    pub const fn as_if_id(self) -> Option<u16> {
        match self {
            Self::Any => None,
            Self::Pinned(if_id) => Some(if_id),
        }
    }
}

/// Shared default headroom for L2/L3/L4 header prepends.
pub const DEFAULT_PACKET_HEADROOM: usize = 128;

/// Canonical physical address wrapper shared across kernel-facing interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PhysicalAddress(u64);

impl PhysicalAddress {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl Add<u64> for PhysicalAddress {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl AddAssign<u64> for PhysicalAddress {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.saturating_add(rhs);
    }
}

/// Packet classification hint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    #[default]
    Unknown = 0,
    Unicast = 1,
    Multicast = 2,
    Broadcast = 3,
}

/// Parsed packet metadata cached across stack layers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketMeta {
    pub l2_len: u8,
    pub l3_len: u8,
    pub l4_len: u8,
    pub l4_proto: u8,
    pub flow_hash: u32,
    pub csum_flags: u8,
    pub pkt_type: PacketType,
    pub vlan_tag: Option<u16>,
    pub timestamp: u64,
}

impl PacketMeta {
    #[inline]
    pub fn ip_csum_verified(&self) -> bool {
        self.csum_flags & 0x01 != 0
    }

    #[inline]
    pub fn l4_csum_verified(&self) -> bool {
        self.csum_flags & 0x02 != 0
    }

    #[inline]
    pub fn set_ip_csum_verified(&mut self) {
        self.csum_flags |= 0x01;
    }

    #[inline]
    pub fn set_l4_csum_verified(&mut self) {
        self.csum_flags |= 0x02;
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        self.l2_len as usize + self.l3_len as usize + self.l4_len as usize
    }

    #[inline]
    pub fn l3_offset(&self) -> usize {
        self.l2_len as usize
    }

    #[inline]
    pub fn l4_offset(&self) -> usize {
        self.l2_len as usize + self.l3_len as usize
    }

    #[inline]
    pub fn payload_offset(&self) -> usize {
        self.header_len()
    }
}

pub const PACKET_REF_STORAGE_WORDS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketByteCount(NonZeroUsize);

impl PacketByteCount {
    pub const fn new(bytes: usize) -> Option<Self> {
        match NonZeroUsize::new(bytes) {
            Some(bytes) => Some(Self(bytes)),
            None => None,
        }
    }

    pub const fn get(self) -> usize {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketWindowError {
    Empty,
    OutOfBounds,
    BackendSplitUnsupported,
}

#[derive(Debug)]
pub struct PacketOwnershipError<T> {
    cause: PacketWindowError,
    owner: T,
}

impl<T> PacketOwnershipError<T> {
    pub const fn new(cause: PacketWindowError, owner: T) -> Self {
        Self { cause, owner }
    }

    pub const fn cause(&self) -> PacketWindowError {
        self.cause
    }

    pub fn into_owner(self) -> T {
        self.owner
    }

    pub fn into_parts(self) -> (PacketWindowError, T) {
        (self.cause, self.owner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketPayloadError {
    EmptyPayload,
    EmptySegment,
    LengthOverflow,
    AllocationFailed,
    OutOfBounds,
    BackendSplitUnsupported,
}

#[derive(Debug)]
pub struct PacketPayloadOwnershipError<T> {
    cause: PacketPayloadError,
    owner: T,
}

impl<T> PacketPayloadOwnershipError<T> {
    pub const fn new(cause: PacketPayloadError, owner: T) -> Self {
        Self { cause, owner }
    }

    pub const fn cause(&self) -> PacketPayloadError {
        self.cause
    }

    pub fn into_owner(self) -> T {
        self.owner
    }

    pub fn into_parts(self) -> (PacketPayloadError, T) {
        (self.cause, self.owner)
    }
}

/// Inline opaque storage used by `PacketRef` backings.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketRefStorage {
    words: [usize; PACKET_REF_STORAGE_WORDS],
}

impl PacketRefStorage {
    pub const fn zeroed() -> Self {
        Self {
            words: [0; PACKET_REF_STORAGE_WORDS],
        }
    }

    /// Pack an arbitrary backing state into the inline storage.
    ///
    /// # Safety
    /// `T` must fit into `PacketRefStorage` and must not require stronger
    /// alignment than `PacketRefStorage`.
    ///
    /// # Panics
    ///
    /// Panics if `T` is larger than the inline storage or requires stricter
    /// alignment than the storage provides.
    pub unsafe fn from_state<T>(state: T) -> Self {
        assert!(size_of::<T>() <= size_of::<Self>());
        assert!(align_of::<T>() <= align_of::<Self>());
        let mut storage = MaybeUninit::<Self>::zeroed();
        unsafe {
            storage.as_mut_ptr().cast::<T>().write(state);
            storage.assume_init()
        }
    }

    /// Reinterpret the storage as an immutable backing state.
    ///
    /// # Safety
    /// The storage must currently contain a valid `T`.
    pub unsafe fn as_state_ref<T>(&self) -> &T {
        debug_assert!(size_of::<T>() <= size_of::<Self>());
        debug_assert!(align_of::<T>() <= align_of::<Self>());
        unsafe { &*ptr::from_ref(self).cast::<T>() }
    }

    /// Reinterpret the storage as a mutable backing state.
    ///
    /// # Safety
    /// The storage must currently contain a valid `T`.
    pub unsafe fn as_state_mut<T>(&mut self) -> &mut T {
        debug_assert!(size_of::<T>() <= size_of::<Self>());
        debug_assert!(align_of::<T>() <= align_of::<Self>());
        unsafe { &mut *ptr::from_mut(self).cast::<T>() }
    }
}

/// Opaque backing operations for zero-copy packet references.
#[derive(Clone, Copy)]
pub struct PacketRefVTable {
    pub data_ptr: unsafe fn(&PacketRefStorage) -> *const u8,
    pub data_mut_ptr: unsafe fn(&mut PacketRefStorage) -> *mut u8,
    pub len: unsafe fn(&PacketRefStorage) -> usize,
    pub resize: unsafe fn(&mut PacketRefStorage, usize) -> bool,
    pub data_capacity: unsafe fn(&PacketRefStorage) -> usize,
    pub phys_addr: unsafe fn(&PacketRefStorage) -> u64,
    pub device_address: unsafe fn(&PacketRefStorage) -> u64,
    pub headroom: unsafe fn(&PacketRefStorage) -> usize,
    pub advance: unsafe fn(&mut PacketRefStorage, PacketByteCount) -> bool,
    pub retreat: unsafe fn(&mut PacketRefStorage, PacketByteCount) -> bool,
    pub split_front: unsafe fn(
        &PacketRefStorage,
        PacketByteCount,
    ) -> Option<(PacketRefStorage, PacketRefStorage)>,
    pub drop_storage: unsafe fn(&mut PacketRefStorage),
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

/// Shared zero-copy packet reference used by kernel adapters and driver crates.
pub struct PacketRef {
    storage: PacketRefStorage,
    vtable: &'static PacketRefVTable,
    meta_cache: PacketMeta,
    _not_sync: PhantomData<*mut ()>,
}

impl PacketRef {
    /// Construct from opaque backing storage.
    ///
    /// # Safety
    /// `storage` must contain the backing expected by `vtable`.
    pub unsafe fn from_opaque_parts(
        storage: PacketRefStorage,
        vtable: &'static PacketRefVTable,
    ) -> Self {
        Self {
            storage,
            vtable,
            meta_cache: PacketMeta::default(),
            _not_sync: PhantomData,
        }
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        let ptr = unsafe { (self.vtable.data_ptr)(&self.storage) };
        let len = unsafe { (self.vtable.len)(&self.storage) };
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = unsafe { (self.vtable.len)(&self.storage) };
        let ptr = unsafe { (self.vtable.data_mut_ptr)(&mut self.storage) };
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }

    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        unsafe { (self.vtable.data_ptr)(&self.storage) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        unsafe { (self.vtable.len)(&self.storage) }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    #[must_use]
    pub fn try_resize(&mut self, len: usize) -> Result<(), PacketWindowError> {
        let old_len = self.len();
        if len > self.data_capacity() {
            return Err(PacketWindowError::OutOfBounds);
        }
        if len > old_len {
            let initialize_len = len - old_len;
            let ptr = unsafe { (self.vtable.data_mut_ptr)(&mut self.storage) };
            // SAFETY: `len <= data_capacity` proves that the newly visible tail
            // lies within the exclusively owned packet backing.
            unsafe { ptr.add(old_len).write_bytes(0, initialize_len) };
        }
        if unsafe { (self.vtable.resize)(&mut self.storage, len) } {
            Ok(())
        } else {
            Err(PacketWindowError::OutOfBounds)
        }
    }

    #[inline]
    pub fn data_capacity(&self) -> usize {
        unsafe { (self.vtable.data_capacity)(&self.storage) }
    }

    #[inline]
    pub fn headroom(&self) -> usize {
        unsafe { (self.vtable.headroom)(&self.storage) }
    }

    #[inline]
    pub fn tailroom(&self) -> usize {
        self.data_capacity().saturating_sub(self.len())
    }

    #[inline]
    pub fn phys_addr(&self) -> PhysicalAddress {
        PhysicalAddress::new(unsafe { (self.vtable.phys_addr)(&self.storage) })
    }

    #[inline]
    pub fn device_address(&self) -> u64 {
        unsafe { (self.vtable.device_address)(&self.storage) }
    }

    #[inline]
    #[must_use]
    pub fn try_advance(&mut self, size: PacketByteCount) -> Result<(), PacketWindowError> {
        if unsafe { (self.vtable.advance)(&mut self.storage, size) } {
            Ok(())
        } else {
            Err(PacketWindowError::OutOfBounds)
        }
    }

    #[inline]
    pub fn try_retreat(&mut self, size: PacketByteCount) -> Result<(), PacketWindowError> {
        if size.get() > self.headroom() {
            return Err(PacketWindowError::OutOfBounds);
        }
        if !unsafe { (self.vtable.retreat)(&mut self.storage, size) } {
            return Err(PacketWindowError::OutOfBounds);
        }
        let ptr = unsafe { (self.vtable.data_mut_ptr)(&mut self.storage) };
        // SAFETY: a successful retreat made exactly `size` bytes at the new
        // data pointer part of the exclusively owned visible region.
        unsafe { ptr.write_bytes(0, size.get()) };
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required state cannot be read.
    pub fn try_take_front(
        self,
        len: PacketByteCount,
    ) -> Result<PacketFront, PacketOwnershipError<Self>> {
        let take = len.get();
        let total_len = self.len();
        if take > total_len {
            return Err(PacketOwnershipError::new(
                PacketWindowError::OutOfBounds,
                self,
            ));
        }
        if take == total_len {
            return Ok(PacketFront::Whole(self));
        }

        let storage = self.storage;
        let vtable = self.vtable;
        let meta = self.meta_cache;
        let Some((front_storage, remainder_storage)) =
            (unsafe { (vtable.split_front)(&storage, len) })
        else {
            return Err(PacketOwnershipError::new(
                PacketWindowError::BackendSplitUnsupported,
                self,
            ));
        };
        let _packet = ManuallyDrop::new(self);

        Ok(PacketFront::Prefix {
            front: unsafe { Self::from_opaque_parts_with_meta(front_storage, vtable, meta) },
            remainder: unsafe {
                Self::from_opaque_parts_with_meta(remainder_storage, vtable, meta)
            },
        })
    }

    unsafe fn from_opaque_parts_with_meta(
        storage: PacketRefStorage,
        vtable: &'static PacketRefVTable,
        meta_cache: PacketMeta,
    ) -> Self {
        Self {
            storage,
            vtable,
            meta_cache,
            _not_sync: PhantomData,
        }
    }

    pub(crate) fn unpublished_writable_region(&mut self) -> Option<(*mut u8, u64, usize)> {
        if !self.is_empty() {
            return None;
        }
        let writable_len = self.data_capacity();
        if writable_len == 0 {
            return None;
        }
        let cpu_ptr = unsafe { (self.vtable.data_mut_ptr)(&mut self.storage) };
        Some((cpu_ptr, self.device_address(), writable_len))
    }

    /// Publish bytes initialized by a device into the safe visible region.
    ///
    /// # Safety
    /// The caller must prove that the device has finished writing every byte
    /// in `0..len` and no longer holds write authority for the backing.
    pub(crate) unsafe fn publish_device_written(
        &mut self,
        len: PacketByteCount,
    ) -> Result<(), PacketWindowError> {
        if len.get() > self.data_capacity() {
            return Err(PacketWindowError::OutOfBounds);
        }
        if unsafe { (self.vtable.resize)(&mut self.storage, len.get()) } {
            Ok(())
        } else {
            Err(PacketWindowError::OutOfBounds)
        }
    }

    #[inline]
    pub fn meta(&self) -> &PacketMeta {
        &self.meta_cache
    }

    #[inline]
    pub fn meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.meta_cache
    }

    #[inline]
    pub fn set_meta(&mut self, meta: PacketMeta) {
        self.meta_cache = meta;
    }
}

impl Drop for PacketRef {
    fn drop(&mut self) {
        unsafe { (self.vtable.drop_storage)(&mut self.storage) };
    }
}

unsafe impl Send for PacketRef {}

impl fmt::Debug for PacketRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketRef")
            .field("len", &self.len())
            .field("data_capacity", &self.data_capacity())
            .field("headroom", &self.headroom())
            .field("tailroom", &self.tailroom())
            .field("phys_addr", &self.phys_addr())
            .field("device_address", &self.device_address())
            .field("meta", &self.meta_cache)
            .finish()
    }
}

#[derive(Debug)]
enum PacketSegmentStorage {
    One(PacketRef),
    Pair([PacketRef; 2]),
    Many(Vec<PacketRef>),
}

#[derive(Debug)]
pub struct PacketPayload {
    storage: PacketSegmentStorage,
    total_len: PacketByteCount,
}

pub struct PacketSegments {
    inner: PacketSegmentsInner,
}

enum PacketSegmentsInner {
    One(core::option::IntoIter<PacketRef>),
    Pair(core::array::IntoIter<PacketRef, 2>),
    Many(alloc::vec::IntoIter<PacketRef>),
}

impl Iterator for PacketSegments {
    type Item = PacketRef;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            PacketSegmentsInner::One(iter) => iter.next(),
            PacketSegmentsInner::Pair(iter) => iter.next(),
            PacketSegmentsInner::Many(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            PacketSegmentsInner::One(iter) => iter.size_hint(),
            PacketSegmentsInner::Pair(iter) => iter.size_hint(),
            PacketSegmentsInner::Many(iter) => iter.size_hint(),
        }
    }
}

impl ExactSizeIterator for PacketSegments {}

impl PacketPayload {
    pub fn try_single(packet: PacketRef) -> Result<Self, PacketPayloadOwnershipError<PacketRef>> {
        let Some(total_len) = PacketByteCount::new(packet.len()) else {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::EmptySegment,
                packet,
            ));
        };
        Ok(Self {
            storage: PacketSegmentStorage::One(packet),
            total_len,
        })
    }

    pub fn try_pair(
        first: PacketRef,
        second: PacketRef,
    ) -> Result<Self, PacketPayloadOwnershipError<(PacketRef, PacketRef)>> {
        let Some(total) = first.len().checked_add(second.len()) else {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::LengthOverflow,
                (first, second),
            ));
        };
        if first.is_empty() || second.is_empty() {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::EmptySegment,
                (first, second),
            ));
        }
        let Some(total_len) = PacketByteCount::new(total) else {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::EmptyPayload,
                (first, second),
            ));
        };
        Ok(Self {
            storage: PacketSegmentStorage::Pair([first, second]),
            total_len,
        })
    }

    pub fn try_from_segments(
        segments: Vec<PacketRef>,
    ) -> Result<Self, PacketPayloadOwnershipError<Vec<PacketRef>>> {
        if segments.is_empty() {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::EmptyPayload,
                segments,
            ));
        }
        let mut total = 0usize;
        for segment in &segments {
            if segment.is_empty() {
                return Err(PacketPayloadOwnershipError::new(
                    PacketPayloadError::EmptySegment,
                    segments,
                ));
            }
            let Some(next) = total.checked_add(segment.len()) else {
                return Err(PacketPayloadOwnershipError::new(
                    PacketPayloadError::LengthOverflow,
                    segments,
                ));
            };
            total = next;
        }
        let Some(total_len) = PacketByteCount::new(total) else {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::EmptyPayload,
                segments,
            ));
        };
        Ok(Self::from_validated_segments(segments, total_len))
    }

    fn from_validated_segments(segments: Vec<PacketRef>, total_len: PacketByteCount) -> Self {
        let storage = match segments.len() {
            1 => match <Vec<PacketRef> as TryInto<[PacketRef; 1]>>::try_into(segments) {
                Ok([packet]) => PacketSegmentStorage::One(packet),
                Err(segments) => PacketSegmentStorage::Many(segments),
            },
            2 => match <Vec<PacketRef> as TryInto<[PacketRef; 2]>>::try_into(segments) {
                Ok(pair) => PacketSegmentStorage::Pair(pair),
                Err(segments) => PacketSegmentStorage::Many(segments),
            },
            _ => PacketSegmentStorage::Many(segments),
        };
        Self { storage, total_len }
    }

    pub fn segments(&self) -> &[PacketRef] {
        match &self.storage {
            PacketSegmentStorage::One(packet) => core::slice::from_ref(packet),
            PacketSegmentStorage::Pair(pair) => pair,
            PacketSegmentStorage::Many(segments) => segments,
        }
    }

    pub fn segments_mut(&mut self) -> &mut [PacketRef] {
        match &mut self.storage {
            PacketSegmentStorage::One(packet) => core::slice::from_mut(packet),
            PacketSegmentStorage::Pair(pair) => pair,
            PacketSegmentStorage::Many(segments) => segments,
        }
    }

    pub const fn byte_len(&self) -> PacketByteCount {
        self.total_len
    }

    pub const fn total_len(&self) -> usize {
        self.total_len.get()
    }

    pub fn into_segments(self) -> PacketSegments {
        let inner = match self.storage {
            PacketSegmentStorage::One(packet) => PacketSegmentsInner::One(Some(packet).into_iter()),
            PacketSegmentStorage::Pair(pair) => PacketSegmentsInner::Pair(pair.into_iter()),
            PacketSegmentStorage::Many(segments) => PacketSegmentsInner::Many(segments.into_iter()),
        };
        PacketSegments { inner }
    }

    pub fn try_prepend(
        self,
        packet: PacketRef,
    ) -> Result<Self, PacketPayloadOwnershipError<(PacketRef, Self)>> {
        if packet.is_empty() {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::EmptySegment,
                (packet, self),
            ));
        }
        let Some(total) = self.total_len().checked_add(packet.len()) else {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::LengthOverflow,
                (packet, self),
            ));
        };
        let total_len = match PacketByteCount::new(total) {
            Some(total_len) => total_len,
            None => {
                return Err(PacketPayloadOwnershipError::new(
                    PacketPayloadError::LengthOverflow,
                    (packet, self),
                ));
            }
        };
        let Self {
            storage,
            total_len: old_total_len,
        } = self;
        let storage = match storage {
            PacketSegmentStorage::One(existing) => PacketSegmentStorage::Pair([packet, existing]),
            PacketSegmentStorage::Pair(pair) => {
                let mut segments = Vec::new();
                if segments.try_reserve_exact(3).is_err() {
                    let owner = Self {
                        storage: PacketSegmentStorage::Pair(pair),
                        total_len: old_total_len,
                    };
                    return Err(PacketPayloadOwnershipError::new(
                        PacketPayloadError::AllocationFailed,
                        (packet, owner),
                    ));
                }
                segments.push(packet);
                segments.extend(pair);
                PacketSegmentStorage::Many(segments)
            }
            PacketSegmentStorage::Many(mut segments) => {
                if segments.try_reserve(1).is_err() {
                    let owner = Self {
                        storage: PacketSegmentStorage::Many(segments),
                        total_len: old_total_len,
                    };
                    return Err(PacketPayloadOwnershipError::new(
                        PacketPayloadError::AllocationFailed,
                        (packet, owner),
                    ));
                }
                segments.insert(0, packet);
                PacketSegmentStorage::Many(segments)
            }
        };
        Ok(Self { storage, total_len })
    }

    pub fn try_append(
        self,
        other: Self,
    ) -> Result<Self, PacketPayloadOwnershipError<(Self, Self)>> {
        let Some(total) = self.total_len().checked_add(other.total_len()) else {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::LengthOverflow,
                (self, other),
            ));
        };
        let Some(total_len) = PacketByteCount::new(total) else {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::LengthOverflow,
                (self, other),
            ));
        };
        let Self {
            storage: left,
            total_len: left_len,
        } = self;
        let Self {
            storage: right,
            total_len: right_len,
        } = other;

        let allocation_failed = |left, right| {
            PacketPayloadOwnershipError::new(
                PacketPayloadError::AllocationFailed,
                (
                    Self {
                        storage: left,
                        total_len: left_len,
                    },
                    Self {
                        storage: right,
                        total_len: right_len,
                    },
                ),
            )
        };
        let storage = match (left, right) {
            (PacketSegmentStorage::One(first), PacketSegmentStorage::One(second)) => {
                PacketSegmentStorage::Pair([first, second])
            }
            (PacketSegmentStorage::One(first), PacketSegmentStorage::Pair(pair)) => {
                let mut segments = Vec::new();
                if segments.try_reserve_exact(3).is_err() {
                    return Err(allocation_failed(
                        PacketSegmentStorage::One(first),
                        PacketSegmentStorage::Pair(pair),
                    ));
                }
                segments.push(first);
                segments.extend(pair);
                PacketSegmentStorage::Many(segments)
            }
            (PacketSegmentStorage::Pair(pair), PacketSegmentStorage::One(last)) => {
                let mut segments = Vec::new();
                if segments.try_reserve_exact(3).is_err() {
                    return Err(allocation_failed(
                        PacketSegmentStorage::Pair(pair),
                        PacketSegmentStorage::One(last),
                    ));
                }
                segments.extend(pair);
                segments.push(last);
                PacketSegmentStorage::Many(segments)
            }
            (PacketSegmentStorage::One(first), PacketSegmentStorage::Many(mut right)) => {
                if right.try_reserve(1).is_err() {
                    return Err(allocation_failed(
                        PacketSegmentStorage::One(first),
                        PacketSegmentStorage::Many(right),
                    ));
                }
                right.insert(0, first);
                PacketSegmentStorage::Many(right)
            }
            (PacketSegmentStorage::Many(mut left), PacketSegmentStorage::One(last)) => {
                if left.try_reserve(1).is_err() {
                    return Err(allocation_failed(
                        PacketSegmentStorage::Many(left),
                        PacketSegmentStorage::One(last),
                    ));
                }
                left.push(last);
                PacketSegmentStorage::Many(left)
            }
            (PacketSegmentStorage::Pair(left_pair), PacketSegmentStorage::Pair(right_pair)) => {
                let mut segments = Vec::new();
                if segments.try_reserve_exact(4).is_err() {
                    return Err(allocation_failed(
                        PacketSegmentStorage::Pair(left_pair),
                        PacketSegmentStorage::Pair(right_pair),
                    ));
                }
                segments.extend(left_pair);
                segments.extend(right_pair);
                PacketSegmentStorage::Many(segments)
            }
            (PacketSegmentStorage::Pair(pair), PacketSegmentStorage::Many(mut right)) => {
                if right.try_reserve(2).is_err() {
                    return Err(allocation_failed(
                        PacketSegmentStorage::Pair(pair),
                        PacketSegmentStorage::Many(right),
                    ));
                }
                let [first, second] = pair;
                right.insert(0, second);
                right.insert(0, first);
                PacketSegmentStorage::Many(right)
            }
            (PacketSegmentStorage::Many(mut left), PacketSegmentStorage::Pair(pair)) => {
                if left.try_reserve(2).is_err() {
                    return Err(allocation_failed(
                        PacketSegmentStorage::Many(left),
                        PacketSegmentStorage::Pair(pair),
                    ));
                }
                left.extend(pair);
                PacketSegmentStorage::Many(left)
            }
            (PacketSegmentStorage::Many(mut left), PacketSegmentStorage::Many(mut right)) => {
                if left.try_reserve(right.len()).is_err() {
                    return Err(allocation_failed(
                        PacketSegmentStorage::Many(left),
                        PacketSegmentStorage::Many(right),
                    ));
                }
                left.append(&mut right);
                PacketSegmentStorage::Many(left)
            }
        };
        Ok(Self { storage, total_len })
    }

    /// Split this payload while preserving the original owner on failure.
    ///
    /// # Errors
    /// Returns the unchanged payload if `len` is out of bounds, backing split
    /// is unsupported, or storage for a multi-segment prefix cannot be reserved.
    pub fn try_take_front(
        self,
        len: PacketByteCount,
    ) -> Result<PacketPayloadFront, PacketPayloadOwnershipError<Self>> {
        let take = len.get();
        let total = self.total_len();
        if take > total {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::OutOfBounds,
                self,
            ));
        }
        if take == total {
            return Ok(PacketPayloadFront::Whole(self));
        }
        let remainder_len = PacketByteCount::new(total - take);
        let front_len = PacketByteCount::new(take);
        let (Some(front_len), Some(remainder_len)) = (front_len, remainder_len) else {
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::OutOfBounds,
                self,
            ));
        };

        match self.storage {
            PacketSegmentStorage::One(packet) => match packet.try_take_front(len) {
                Ok(PacketFront::Prefix { front, remainder }) => Ok(PacketPayloadFront::Prefix {
                    front: Self {
                        storage: PacketSegmentStorage::One(front),
                        total_len: front_len,
                    },
                    remainder: Self {
                        storage: PacketSegmentStorage::One(remainder),
                        total_len: remainder_len,
                    },
                }),
                Ok(PacketFront::Whole(packet)) => Ok(PacketPayloadFront::Whole(Self {
                    storage: PacketSegmentStorage::One(packet),
                    total_len: front_len,
                })),
                Err(error) => Err(PacketPayloadOwnershipError::new(
                    map_window_error(error.cause()),
                    Self {
                        storage: PacketSegmentStorage::One(error.into_owner()),
                        total_len: PacketByteCount::new(total).unwrap_or(front_len),
                    },
                )),
            },
            PacketSegmentStorage::Pair([first, second]) => {
                split_pair(first, second, len, front_len, remainder_len)
            }
            PacketSegmentStorage::Many(segments) => {
                split_many(segments, len, front_len, remainder_len)
            }
        }
    }
}

fn map_window_error(error: PacketWindowError) -> PacketPayloadError {
    match error {
        PacketWindowError::Empty => PacketPayloadError::EmptyPayload,
        PacketWindowError::OutOfBounds => PacketPayloadError::OutOfBounds,
        PacketWindowError::BackendSplitUnsupported => PacketPayloadError::BackendSplitUnsupported,
    }
}

fn split_pair(
    first: PacketRef,
    second: PacketRef,
    len: PacketByteCount,
    front_len: PacketByteCount,
    remainder_len: PacketByteCount,
) -> Result<PacketPayloadFront, PacketPayloadOwnershipError<PacketPayload>> {
    let first_len = first.len();
    if len.get() == first_len {
        return Ok(PacketPayloadFront::Prefix {
            front: PacketPayload {
                storage: PacketSegmentStorage::One(first),
                total_len: front_len,
            },
            remainder: PacketPayload {
                storage: PacketSegmentStorage::One(second),
                total_len: remainder_len,
            },
        });
    }
    if len.get() < first_len {
        return match first.try_take_front(len) {
            Ok(PacketFront::Prefix { front, remainder }) => Ok(PacketPayloadFront::Prefix {
                front: PacketPayload {
                    storage: PacketSegmentStorage::One(front),
                    total_len: front_len,
                },
                remainder: PacketPayload {
                    storage: PacketSegmentStorage::Pair([remainder, second]),
                    total_len: remainder_len,
                },
            }),
            Ok(PacketFront::Whole(first)) => Ok(PacketPayloadFront::Prefix {
                front: PacketPayload {
                    storage: PacketSegmentStorage::One(first),
                    total_len: front_len,
                },
                remainder: PacketPayload {
                    storage: PacketSegmentStorage::One(second),
                    total_len: remainder_len,
                },
            }),
            Err(error) => Err(PacketPayloadOwnershipError::new(
                map_window_error(error.cause()),
                PacketPayload {
                    storage: PacketSegmentStorage::Pair([error.into_owner(), second]),
                    total_len: PacketByteCount::new(first_len + remainder_len.get())
                        .unwrap_or(remainder_len),
                },
            )),
        };
    }

    let within_second = PacketByteCount::new(len.get() - first_len);
    let Some(within_second) = within_second else {
        return Err(PacketPayloadOwnershipError::new(
            PacketPayloadError::OutOfBounds,
            PacketPayload {
                storage: PacketSegmentStorage::Pair([first, second]),
                total_len: PacketByteCount::new(first_len + remainder_len.get())
                    .unwrap_or(remainder_len),
            },
        ));
    };
    match second.try_take_front(within_second) {
        Ok(PacketFront::Prefix { front, remainder }) => Ok(PacketPayloadFront::Prefix {
            front: PacketPayload {
                storage: PacketSegmentStorage::Pair([first, front]),
                total_len: front_len,
            },
            remainder: PacketPayload {
                storage: PacketSegmentStorage::One(remainder),
                total_len: remainder_len,
            },
        }),
        Ok(PacketFront::Whole(second)) => Ok(PacketPayloadFront::Whole(PacketPayload {
            storage: PacketSegmentStorage::Pair([first, second]),
            total_len: front_len,
        })),
        Err(error) => Err(PacketPayloadOwnershipError::new(
            map_window_error(error.cause()),
            PacketPayload {
                storage: PacketSegmentStorage::Pair([first, error.into_owner()]),
                total_len: PacketByteCount::new(front_len.get() + remainder_len.get())
                    .unwrap_or(front_len),
            },
        )),
    }
}

fn split_many(
    mut segments: Vec<PacketRef>,
    len: PacketByteCount,
    front_len: PacketByteCount,
    remainder_len: PacketByteCount,
) -> Result<PacketPayloadFront, PacketPayloadOwnershipError<PacketPayload>> {
    let total_len =
        PacketByteCount::new(front_len.get() + remainder_len.get()).unwrap_or(front_len);
    let mut consumed = 0usize;
    let mut split_index = 0usize;
    let mut within_segment = 0usize;
    for (index, segment) in segments.iter().enumerate() {
        let next = consumed + segment.len();
        if len.get() <= next {
            split_index = index;
            within_segment = len.get() - consumed;
            break;
        }
        consumed = next;
    }

    let prefix_count = split_index + usize::from(within_segment != 0);
    let mut prefix = Vec::new();
    if prefix.try_reserve_exact(prefix_count).is_err() {
        return Err(PacketPayloadOwnershipError::new(
            PacketPayloadError::AllocationFailed,
            PacketPayload {
                storage: PacketSegmentStorage::Many(segments),
                total_len,
            },
        ));
    }

    if within_segment == 0 {
        prefix.extend(segments.drain(..split_index));
    } else {
        let segment = segments.remove(split_index);
        let Some(within) = PacketByteCount::new(within_segment) else {
            segments.insert(split_index, segment);
            return Err(PacketPayloadOwnershipError::new(
                PacketPayloadError::OutOfBounds,
                PacketPayload {
                    storage: PacketSegmentStorage::Many(segments),
                    total_len,
                },
            ));
        };
        match segment.try_take_front(within) {
            Ok(PacketFront::Prefix { front, remainder }) => {
                prefix.extend(segments.drain(..split_index));
                prefix.push(front);
                segments.insert(0, remainder);
            }
            Ok(PacketFront::Whole(segment)) => {
                prefix.extend(segments.drain(..split_index));
                prefix.push(segment);
            }
            Err(error) => {
                segments.insert(split_index, error.into_owner());
                return Err(PacketPayloadOwnershipError::new(
                    PacketPayloadError::BackendSplitUnsupported,
                    PacketPayload {
                        storage: PacketSegmentStorage::Many(segments),
                        total_len,
                    },
                ));
            }
        }
    }

    Ok(PacketPayloadFront::Prefix {
        front: PacketPayload::from_validated_segments(prefix, front_len),
        remainder: PacketPayload::from_validated_segments(segments, remainder_len),
    })
}

/// System information
#[derive(Debug)]
pub struct SystemInfo {
    pub total_memory: u64,
    pub free_memory: u64,
    pub uptime_ms: u64,
    pub cpu_count: u32,
}

/// File open mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
    Append,
    Create,
}

/// File handle
pub struct FileHandle {
    id: u64,
    mode: OpenMode,
}

impl FileHandle {
    /// Create new file handle (kernel-only)
    pub const fn new(id: u64, mode: OpenMode) -> Self {
        Self { id, mode }
    }

    /// Get file ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get open mode
    pub fn mode(&self) -> OpenMode {
        self.mode
    }
}

/// Direct block device handle (NVMe namespace)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectBlockHandle {
    device_id: u64,
    start_block: u64,
    block_count: u64,
    block_size: u32,
    /// Optional kernel-assigned open id (0 == not an open returned by kernel)
    open_id: u64,
}

impl DirectBlockHandle {
    /// Create a new direct block handle (kernel-only)
    /// This constructor represents a *standalone* handle (not a kernel-registered open).
    pub const fn new(device_id: u64, start_block: u64, block_count: u64, block_size: u32) -> Self {
        Self {
            device_id,
            start_block,
            block_count,
            block_size,
            open_id: 0,
        }
    }

    /// Create a kernel-registered handle with an `open_id`
    pub const fn new_with_id(
        device_id: u64,
        start_block: u64,
        block_count: u64,
        block_size: u32,
        open_id: u64,
    ) -> Self {
        Self {
            device_id,
            start_block,
            block_count,
            block_size,
            open_id,
        }
    }

    pub fn device_id(&self) -> u64 {
        self.device_id
    }

    pub fn start_block(&self) -> u64 {
        self.start_block
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Kernel-assigned open id (0 if not from `nvme_open_direct_with_token`)
    pub fn open_id(&self) -> u64 {
        self.open_id
    }
}

/// IPC channel handle
pub struct ChannelHandle {
    id: u64,
}

impl ChannelHandle {
    /// Create new channel handle (kernel-only)
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Get channel ID
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// Shared socket address for KAPI TCP endpoint operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetSocketAddr {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
}

impl NetSocketAddr {
    pub const fn v4(ip: [u8; 4], port: u16) -> Self {
        Self::V4 { ip, port }
    }

    pub const fn v6(ip: [u8; 16], port: u16) -> Self {
        Self::V6 { ip, port }
    }

    pub const fn port(self) -> u16 {
        match self {
            Self::V4 { port, .. } | Self::V6 { port, .. } => port,
        }
    }

    pub const fn is_ipv6(self) -> bool {
        matches!(self, Self::V6 { .. })
    }
}

// ============================================================================
// NVMe I/O Request Types (io_scheduler abstraction)
// ============================================================================

/// NVMe I/O operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeIoType {
    /// Read operation
    Read,
    /// Write operation
    Write,
    /// Flush operation
    Flush,
    /// Discard/TRIM operation
    Discard,
}

/// NVMe I/O priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvmeIoPriority {
    /// Background (lowest)
    Background,
    /// Idle
    Idle,
    /// Normal (default)
    #[default]
    Normal,
    /// High priority
    High,
    /// Realtime (highest)
    Realtime,
}

/// NVMe Read/Write request parameters
#[derive(Debug)]
pub struct NvmeRwRequest {
    /// NVMe device ID
    pub device_id: u64,
    /// NVMe namespace ID
    pub namespace_id: u32,
    /// Starting LBA
    pub lba: u64,
    /// Number of blocks
    pub blocks: u16,
    /// PRP1 (first page IOVA)
    pub prp1: u64,
    /// PRP2 (second page or PRP list IOVA)
    pub prp2: u64,
    /// Transfer size in bytes
    pub bytes: usize,
    /// I/O priority
    pub priority: NvmeIoPriority,
}

/// NVMe I/O request handle
#[derive(Debug, Clone, Copy)]
pub struct NvmeIoHandle {
    request_id: u64,
}

impl NvmeIoHandle {
    /// Create a new handle (kernel-only)
    pub const fn new(request_id: u64) -> Self {
        Self { request_id }
    }

    /// Get the request ID
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
}

/// NVMe I/O result
#[derive(Debug)]
pub enum NvmeIoResult {
    /// Success with transferred byte count
    Success(usize),
    /// Device error
    DeviceError,
    /// Timeout
    Timeout,
    /// Cancelled
    Cancelled,
    /// Invalid parameter
    InvalidParameter,
}

#[cfg(test)]
mod packet_ref_tests {
    use super::*;
    use alloc::boxed::Box;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DMA_RELEASES: AtomicUsize = AtomicUsize::new(0);

    struct SharedDmaBuffer {
        dma: Box<crate::dma::DmaSlice<crate::dma::CpuOwned>>,
        phys_addr: u64,
        device_addr: u64,
        ref_count: AtomicUsize,
    }

    #[derive(Clone, Copy)]
    struct DmaPacketState {
        backing: NonNull<SharedDmaBuffer>,
        offset: usize,
        len: usize,
    }

    fn dma_backing(state: &DmaPacketState) -> &SharedDmaBuffer {
        unsafe { state.backing.as_ref() }
    }

    unsafe fn dma_state_ref(storage: &PacketRefStorage) -> &DmaPacketState {
        unsafe { storage.as_state_ref::<DmaPacketState>() }
    }

    unsafe fn dma_state_mut(storage: &mut PacketRefStorage) -> &mut DmaPacketState {
        unsafe { storage.as_state_mut::<DmaPacketState>() }
    }

    unsafe fn dma_data_ptr(storage: &PacketRefStorage) -> *const u8 {
        let state = unsafe { dma_state_ref(storage) };
        dma_backing(state).dma.as_ptr().wrapping_add(state.offset)
    }

    unsafe fn dma_data_mut_ptr(storage: &mut PacketRefStorage) -> *mut u8 {
        let state = unsafe { dma_state_mut(storage) };
        dma_backing(state).dma.as_ptr().wrapping_add(state.offset)
    }

    unsafe fn dma_len(storage: &PacketRefStorage) -> usize {
        unsafe { dma_state_ref(storage) }.len
    }

    unsafe fn dma_resize(storage: &mut PacketRefStorage, len: usize) -> bool {
        let state = unsafe { dma_state_mut(storage) };
        if len > dma_backing(state).dma.size().saturating_sub(state.offset) {
            return false;
        }
        state.len = len;
        true
    }

    unsafe fn dma_capacity(storage: &PacketRefStorage) -> usize {
        let state = unsafe { dma_state_ref(storage) };
        dma_backing(state).dma.size().saturating_sub(state.offset)
    }

    unsafe fn dma_headroom(storage: &PacketRefStorage) -> usize {
        unsafe { dma_state_ref(storage) }.offset
    }

    unsafe fn dma_phys(storage: &PacketRefStorage) -> u64 {
        let state = unsafe { dma_state_ref(storage) };
        dma_backing(state).phys_addr + state.offset as u64
    }

    unsafe fn dma_device(storage: &PacketRefStorage) -> u64 {
        let state = unsafe { dma_state_ref(storage) };
        dma_backing(state).device_addr + state.offset as u64
    }

    unsafe fn dma_advance(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
        let state = unsafe { dma_state_mut(storage) };
        let size = size.get();
        if size > state.len {
            return false;
        }
        state.offset += size;
        state.len -= size;
        true
    }

    unsafe fn dma_retreat(storage: &mut PacketRefStorage, size: PacketByteCount) -> bool {
        let state = unsafe { dma_state_mut(storage) };
        let size = size.get();
        if size > state.offset {
            return false;
        }
        let Some(new_len) = state.len.checked_add(size) else {
            return false;
        };
        let new_offset = state.offset - size;
        if new_len > dma_backing(state).dma.size().saturating_sub(new_offset) {
            return false;
        }
        state.offset = new_offset;
        state.len = new_len;
        true
    }

    unsafe fn dma_drop(storage: &mut PacketRefStorage) {
        let state = unsafe { storage.as_state_mut::<DmaPacketState>() };
        let backing = state.backing;
        if unsafe { backing.as_ref().ref_count.fetch_sub(1, Ordering::AcqRel) } == 1 {
            unsafe {
                ptr::drop_in_place(state);
                drop(Box::from_raw(backing.as_ptr()));
            }
        }
    }

    unsafe fn dma_split_front(
        storage: &PacketRefStorage,
        len: PacketByteCount,
    ) -> Option<(PacketRefStorage, PacketRefStorage)> {
        let state = *unsafe { dma_state_ref(storage) };
        let len = len.get();
        if len == 0 || len >= state.len {
            return None;
        }
        unsafe {
            state
                .backing
                .as_ref()
                .ref_count
                .fetch_add(1, Ordering::AcqRel);
        }
        let front = DmaPacketState {
            backing: state.backing,
            offset: state.offset,
            len,
        };
        let remainder = DmaPacketState {
            backing: state.backing,
            offset: state.offset.checked_add(len)?,
            len: state.len - len,
        };
        Some((unsafe { PacketRefStorage::from_state(front) }, unsafe {
            PacketRefStorage::from_state(remainder)
        }))
    }

    static DMA_VTABLE: PacketRefVTable = PacketRefVTable {
        data_ptr: dma_data_ptr,
        data_mut_ptr: dma_data_mut_ptr,
        len: dma_len,
        resize: dma_resize,
        data_capacity: dma_capacity,
        phys_addr: dma_phys,
        device_address: dma_device,
        headroom: dma_headroom,
        advance: dma_advance,
        retreat: dma_retreat,
        split_front: dma_split_front,
        drop_storage: dma_drop,
    };

    fn dma_releaser(ptr: *mut u8, size: usize, phys_addr: u64) {
        assert_eq!(size, 64);
        assert_eq!(phys_addr, 0x3000);
        DMA_RELEASES.fetch_add(1, Ordering::SeqCst);
        let _ = unsafe { Box::from_raw(ptr.cast::<[u8; 64]>()) };
    }

    fn make_dma_packet() -> PacketRef {
        let mut raw = Box::new([0u8; 64]);
        raw[..7].copy_from_slice(b"packet!");
        let ptr = Box::into_raw(raw).cast::<u8>();
        let dma = unsafe {
            crate::dma::DmaSlice::from_internal_parts_unchecked(
                0x3000,
                0x4000,
                ptr,
                64,
                crate::dma::InternalDmaReclaimer::KernelBuffer {
                    releaser: Some(dma_releaser),
                },
            )
        };
        let state = DmaPacketState {
            backing: NonNull::from(Box::leak(Box::new(SharedDmaBuffer {
                phys_addr: 0x3000,
                device_addr: 0x4000,
                ref_count: AtomicUsize::new(1),
                dma: Box::new(dma),
            }))),
            offset: 0,
            len: 7,
        };

        unsafe { PacketRef::from_opaque_parts(PacketRefStorage::from_state(state), &DMA_VTABLE) }
    }

    #[test]
    fn dma_backing_matches_packet_ref_contract() {
        DMA_RELEASES.store(0, Ordering::SeqCst);

        let mut packet = make_dma_packet();
        assert_eq!(packet.len(), 7);
        assert_eq!(packet.data(), b"packet!");
        assert_eq!(packet.data_capacity(), 64);
        assert_eq!(packet.phys_addr().as_u64(), 0x3000);
        assert_eq!(packet.device_address(), 0x4000);

        packet.try_resize(6).expect("packet resize succeeds");
        packet
            .try_advance(PacketByteCount::new(1).expect("non-empty advance"))
            .expect("packet advance succeeds");
        assert_eq!(packet.len(), 5);
        assert_eq!(packet.data(), b"acket");
        assert_eq!(packet.phys_addr().as_u64(), 0x3001);
        assert_eq!(packet.device_address(), 0x4001);

        packet.meta_mut().pkt_type = PacketType::Unicast;
        assert_eq!(packet.meta().pkt_type, PacketType::Unicast);
        assert_eq!(packet.device_address(), 0x4001);

        drop(packet);
        assert_eq!(DMA_RELEASES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn packet_ref_take_front_exact_len_keeps_single_owner() {
        DMA_RELEASES.store(0, Ordering::SeqCst);

        let packet = make_dma_packet();
        let len = PacketByteCount::new(packet.len()).expect("non-empty packet");

        match packet.try_take_front(len).expect("exact split succeeds") {
            PacketFront::Whole(packet) => {
                assert_eq!(packet.data(), b"packet!");
                drop(packet);
            }
            PacketFront::Prefix { .. } => panic!("exact split must not create windows"),
        }

        assert_eq!(DMA_RELEASES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn packet_ref_take_front_splits_disjoint_windows() {
        DMA_RELEASES.store(0, Ordering::SeqCst);

        let packet = make_dma_packet();
        let len = PacketByteCount::new(3).expect("non-empty prefix");

        let (front, remainder) = match packet.try_take_front(len).expect("prefix split succeeds") {
            PacketFront::Prefix { front, remainder } => (front, remainder),
            PacketFront::Whole(_) => panic!("prefix split must produce two windows"),
        };

        assert_eq!(front.data(), b"pac");
        assert_eq!(remainder.data(), b"ket!");
        assert_eq!(front.device_address(), 0x4000);
        assert_eq!(remainder.device_address(), 0x4003);

        drop(front);
        assert_eq!(DMA_RELEASES.load(Ordering::SeqCst), 0);
        drop(remainder);
        assert_eq!(DMA_RELEASES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn packet_ref_take_front_rejects_out_of_bounds_len() {
        DMA_RELEASES.store(0, Ordering::SeqCst);

        let packet = make_dma_packet();
        let len = PacketByteCount::new(packet.len() + 1).expect("non-empty invalid length");

        assert_eq!(
            packet.try_take_front(len).err().map(|error| error.cause()),
            Some(PacketWindowError::OutOfBounds)
        );
        assert_eq!(DMA_RELEASES.load(Ordering::SeqCst), 1);
    }
}
