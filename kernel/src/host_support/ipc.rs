#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DomainId(u64);

impl DomainId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const KERNEL: DomainId = DomainId(0);
}

pub mod rref {
    use alloc::boxed::Box;
    use core::ops::{Deref, DerefMut};
    use core::ptr::NonNull;

    use super::DomainId;

    #[derive(Debug)]
    pub struct RRef<T: ?Sized> {
        ptr: NonNull<T>,
        owner: DomainId,
    }

    impl<T> RRef<T> {
        pub fn new(owner: DomainId, val: T) -> Self {
            let boxed = Box::new(val);
            let ptr = NonNull::new(Box::into_raw(boxed)).expect("RRef Box pointer is null");
            Self { ptr, owner }
        }

        pub fn into_raw_parts(self) -> RRefRawParts {
            RRefRawParts::from_rref(self)
        }

        pub unsafe fn from_raw_parts_for_zombie(parts: RRefRawParts) -> Self {
            // Test shim only supports sized types; panic on mismatch in debug mode.
            unsafe {
                parts
                    .into_rref::<T>()
                    .expect("RRefRawParts type mismatch in test shim")
            }
        }
    }

    impl<T: ?Sized> RRef<T> {
        pub unsafe fn from_raw(ptr: NonNull<T>, owner: DomainId) -> Self {
            Self { ptr, owner }
        }

        pub fn into_raw(self) -> (NonNull<T>, DomainId) {
            let ptr = self.ptr;
            let owner = self.owner;
            core::mem::forget(self);
            (ptr, owner)
        }
    }

    impl<T: ?Sized> Deref for RRef<T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            unsafe { self.ptr.as_ref() }
        }
    }

    impl<T: ?Sized> DerefMut for RRef<T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            unsafe { self.ptr.as_mut() }
        }
    }

    impl<T: ?Sized> Drop for RRef<T> {
        fn drop(&mut self) {
            unsafe {
                drop(Box::from_raw(self.ptr.as_ptr()));
            }
        }
    }

    unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
    unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RawPartsError {
        TypeMismatch,
        SizeMismatch,
    }

    #[derive(Debug)]
    pub struct RRefRawParts {
        ptr: NonNull<u8>,
        owner: DomainId,
        meta: usize,
        #[cfg(debug_assertions)]
        size: usize,
        #[cfg(debug_assertions)]
        type_hash: u64,
        drop_fn: unsafe fn(NonNull<u8>, DomainId, usize),
    }

    unsafe impl Send for RRefRawParts {}
    unsafe impl Sync for RRefRawParts {}

    impl RRefRawParts {
        pub fn from_rref<T: Sized>(rref: RRef<T>) -> Self {
            #[cfg(debug_assertions)]
            let size = core::mem::size_of_val(&*rref);
            #[cfg(debug_assertions)]
            let type_hash = debug_type_hash(&*rref);
            let (ptr, owner) = rref.into_raw();
            // Simplified: avoid unstable ptr::metadata / ptr::from_raw_parts usage by
            // only supporting sized `RRef<T>` in the test shim. Store meta as zero.
            let meta = 0usize;

            // Embed type-specific drop function (Sized-only for test shim)
            unsafe fn drop_impl<T: Sized>(ptr: NonNull<u8>, owner: DomainId, _meta: usize) {
                // For sized types we can reconstruct the typed pointer directly.
                let data_ptr = ptr.as_ptr() as *mut T;
                let rref: RRef<T> =
                    unsafe { RRef::from_raw(NonNull::new_unchecked(data_ptr), owner) };
                drop(rref);
            }

            Self {
                ptr: ptr.cast(),
                owner,
                meta,
                #[cfg(debug_assertions)]
                size,
                #[cfg(debug_assertions)]
                type_hash,
                drop_fn: drop_impl::<T>,
            }
        }

        pub unsafe fn into_rref<T: Sized>(self) -> Result<RRef<T>, RawPartsError> {
            // Reconstruct typed pointer - test shim assumes sized T.
            let typed_ptr = self.ptr.as_ptr() as *mut T;

            #[cfg(debug_assertions)]
            {
                let typed_ref: &T = unsafe { &*typed_ptr };
                let actual_size = core::mem::size_of_val(typed_ref);
                let actual_hash = debug_type_hash(typed_ref);
                if self.type_hash != actual_hash {
                    return Err(RawPartsError::TypeMismatch);
                }
                if self.size != actual_size {
                    return Err(RawPartsError::SizeMismatch);
                }
            }

            Ok(unsafe { RRef::from_raw(NonNull::new_unchecked(typed_ptr), self.owner) })
        }

        pub unsafe fn drop_erased(self) {
            unsafe { (self.drop_fn)(self.ptr, self.owner, self.meta) };
        }

        pub(crate) fn into_components(
            self,
        ) -> (
            NonNull<u8>,
            DomainId,
            usize,
            unsafe fn(NonNull<u8>, DomainId, usize),
        ) {
            (self.ptr, self.owner, self.meta, self.drop_fn)
        }

        pub fn owner(&self) -> DomainId {
            self.owner
        }
    }

    #[cfg(debug_assertions)]
    fn debug_type_hash<T: ?Sized>(val: &T) -> u64 {
        crate::util::compute_type_hash(
            core::any::type_name::<T>(),
            core::mem::size_of_val(val),
            core::mem::align_of_val(val),
        )
    }
}

pub use rref::RRef;
