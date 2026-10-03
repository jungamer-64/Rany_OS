//! Unique type-erased ownership preserves allocation geometry and pointer
//! metadata without borrowing payload that a device may still be accessing.
use super::{DomainId, RRef};
use core::alloc::Layout;
use core::any::TypeId;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::{self, NonNull};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawPartsError {
    TypeMismatch,
}

/// Rejection retains the sole erased owner. No destructor runs implicitly:
/// translation completion must be established before typed access or release.
#[derive(Debug)]
pub struct RawPartsFailure {
    pub parts: RRefRawParts,
    pub kind: RawPartsError,
}

/// Erasure does not grant CPU access or prove DMA retirement. Forgetting this
/// owner retains RAM. It cannot be copied or reconstructed from an address.
#[derive(Debug)]
pub struct RRefRawParts {
    ptr: NonNull<u8>,
    owner: DomainId,
    meta: usize,
    layout: Layout,
    identity: TypeId,
    drop_fn: unsafe fn(NonNull<u8>, DomainId, usize, Layout),
}

// SAFETY: only erasure of T: Send can construct this owner. Transfer moves one
// destructor/return obligation; no payload borrow survives the move.
unsafe impl Send for RRefRawParts {}
// SAFETY: shared access only observes domain identity. Access or release needs
// consumption plus an explicit inactive-device/translation-completion proof.
unsafe impl Sync for RRefRawParts {}

impl RRefRawParts {
    fn encode_metadata<T: ?Sized>(metadata: <T as ptr::Pointee>::Metadata) -> usize {
        let size = core::mem::size_of::<<T as ptr::Pointee>::Metadata>();
        assert!(size <= core::mem::size_of::<usize>());
        let mut encoded = 0usize;
        // SAFETY: the checked extent fits initialized encoding storage. Reading
        // compiler pointer metadata does not form a reference to its payload.
        unsafe {
            ptr::copy_nonoverlapping(
                (&metadata as *const <T as ptr::Pointee>::Metadata).cast::<u8>(),
                (&mut encoded as *mut usize).cast::<u8>(),
                size,
            );
        }
        encoded
    }

    /// # Safety
    /// The encoding came from this exact T's pointer metadata, without alteration.
    unsafe fn decode_metadata<T: ?Sized>(encoded: usize) -> <T as ptr::Pointee>::Metadata {
        let size = core::mem::size_of::<<T as ptr::Pointee>::Metadata>();
        assert!(size <= core::mem::size_of::<usize>());
        let mut metadata = MaybeUninit::<<T as ptr::Pointee>::Metadata>::uninit();
        // SAFETY: the original initialized metadata's representation is retained;
        // zero-sized metadata has no bytes to initialize. No payload is read.
        unsafe {
            ptr::copy_nonoverlapping(
                (&encoded as *const usize).cast::<u8>(),
                metadata.as_mut_ptr().cast::<u8>(),
                size,
            );
            metadata.assume_init()
        }
    }

    pub(super) fn from_rref<T: Send + ?Sized + 'static>(rref: RRef<T>) -> Self {
        unsafe fn drop_value<T: ?Sized>(
            pointer: NonNull<u8>,
            owner: DomainId,
            encoded: usize,
            layout: Layout,
        ) {
            // SAFETY: the private function pointer is paired with metadata from
            // this exact T. The caller established CPU ownership after retirement.
            let metadata = unsafe { RRefRawParts::decode_metadata::<T>(encoded) };
            let pointer = ptr::from_raw_parts_mut::<T>(pointer.as_ptr().cast::<()>(), metadata);
            // SAFETY: the sole allocation owner retains nonnull provenance,
            // original layout and fully initialized T values until this drop.
            drop(RRef {
                ptr: unsafe { NonNull::new_unchecked(pointer) },
                owner,
                layout,
            });
        }
        let owner = ManuallyDrop::new(rref);
        Self {
            ptr: owner.ptr.cast(),
            owner: owner.owner,
            meta: Self::encode_metadata::<T>(ptr::metadata(owner.ptr.as_ptr())),
            layout: owner.layout,
            identity: TypeId::of::<T>(),
            drop_fn: drop_value::<T>,
        }
    }

    /// # Safety
    /// No device or independent borrower accesses this allocation, and every
    /// translation allowing such access has completed retirement. Rejection
    /// returns the unchanged owner before decoding metadata or touching payload.
    pub unsafe fn into_rref<T: ?Sized + 'static>(self) -> Result<RRef<T>, RawPartsFailure> {
        if self.identity != TypeId::of::<T>() {
            return Err(RawPartsFailure {
                parts: self,
                kind: RawPartsError::TypeMismatch,
            });
        }
        // SAFETY: exact TypeId equality establishes the original metadata type.
        let metadata = unsafe { Self::decode_metadata::<T>(self.meta) };
        let pointer = ptr::from_raw_parts_mut::<T>(self.ptr.as_ptr().cast::<()>(), metadata);
        // SAFETY: rebuilding original metadata preserves the owned nonnull data
        // pointer; TypeId equality establishes its exact initialized value type.
        let pointer = unsafe { NonNull::new_unchecked(pointer) };
        Ok(RRef {
            ptr: pointer,
            owner: self.owner,
            layout: self.layout,
        })
    }

    /// # Safety
    /// The backing has no payload borrow or device access. Required TLB/IOTLB,
    /// paging-structure, ATS and DMA-drain completion precedes this consumption.
    pub unsafe fn drop_erased(self) {
        // SAFETY: the private destructor retains exact type, metadata and Layout;
        // the caller proved reuse is allowed. Consumption prevents a second drop.
        unsafe { (self.drop_fn)(self.ptr, self.owner, self.meta, self.layout) };
    }

    pub fn owner(&self) -> DomainId {
        self.owner
    }
}
