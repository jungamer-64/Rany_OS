use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use super::DomainId;

#[derive(Debug)]
pub struct RRef<T: ?Sized> {
    ptr: NonNull<T>,
    owner: DomainId,
    layout: core::alloc::Layout,
}

// Host backing retains the allocation Layout in RAM, just as an Exchange
// allocation retains its origin header. Erased retirement therefore needs
// neither a heap allocation nor an address-derived deallocation Layout.
struct AllocationHeader {
    raw: NonNull<u8>,
    layout: core::alloc::Layout,
}

struct RawAllocation {
    data: NonNull<u8>,
    raw: NonNull<u8>,
    layout: core::alloc::Layout,
}

impl RawAllocation {
    fn allocate(payload: core::alloc::Layout) -> Option<Self> {
        let (extended, offset) = core::alloc::Layout::new::<AllocationHeader>()
            .extend(payload)
            .ok()?;
        let layout = extended.pad_to_align();
        // SAFETY: layout has nonzero size and valid alignment, including
        // space for the origin header and the requested payload.
        let raw = NonNull::new(unsafe { alloc::alloc::alloc(layout) })?;
        // SAFETY: Layout::extend places payload within this allocation.
        let data = unsafe { NonNull::new_unchecked(raw.as_ptr().add(offset)) };
        Some(Self { data, raw, layout })
    }

    fn commit(self) -> NonNull<u8> {
        let data = self.data;
        // SAFETY: the payload offset reserves at least this header size;
        // the header has no live predecessor and is written exactly once.
        unsafe {
            data.as_ptr()
                .sub(core::mem::size_of::<AllocationHeader>())
                .cast::<AllocationHeader>()
                .write(AllocationHeader {
                    raw: self.raw,
                    layout: self.layout,
                });
        }
        core::mem::forget(self);
        data
    }
}

impl Drop for RawAllocation {
    fn drop(&mut self) {
        // SAFETY: this uncommitted owner retains the exact allocation and
        // Layout and has not transferred reclamation to an RRef header.
        unsafe { alloc::alloc::dealloc(self.raw.as_ptr(), self.layout) };
    }
}

struct InitializingSlice<T> {
    allocation: RawAllocation,
    initialized: usize,
    marker: core::marker::PhantomData<T>,
}

impl<T> Drop for InitializingSlice<T> {
    fn drop(&mut self) {
        // SAFETY: only the initialized prefix contains T values. After
        // these destructors, RawAllocation frees the original Layout.
        unsafe {
            core::ptr::drop_in_place(core::ptr::slice_from_raw_parts_mut(
                self.allocation.data.as_ptr().cast::<T>(),
                self.initialized,
            ));
        }
    }
}

impl<T> RRef<T> {
    pub fn new(owner: DomainId, value: T) -> Self {
        let allocation = RawAllocation::allocate(core::alloc::Layout::new::<T>())
            .unwrap_or_else(|| {
                alloc::alloc::handle_alloc_error(core::alloc::Layout::new::<T>())
            });
        // SAFETY: this unique aligned allocation has room for one T; no
        // fallible operation follows initialization before commit.
        unsafe { allocation.data.as_ptr().cast::<T>().write(value) };
        Self {
            ptr: allocation.commit().cast(),
            owner,
        }
    }
}

impl<T> RRef<[T]> {
    pub fn new_slice_with_aligned(
        owner: DomainId,
        len: usize,
        alignment: usize,
        mut init: impl FnMut(usize) -> T,
    ) -> Option<Self> {
        if len == 0 || !alignment.is_power_of_two() {
            return None;
        }
        let elements = core::alloc::Layout::array::<T>(len).ok()?;
        let payload = core::alloc::Layout::from_size_align(
            elements.size(),
            alignment.max(elements.align()),
        )
        .ok()?;
        let mut prefix = InitializingSlice::<T> {
            allocation: RawAllocation::allocate(payload)?,
            initialized: 0,
            marker: core::marker::PhantomData,
        };
        for index in 0..len {
            let value = init(index);
            // SAFETY: index lies in the allocation and this element has
            // not been initialized before; ownership moves into the prefix.
            unsafe {
                prefix
                    .allocation
                    .data
                    .as_ptr()
                    .cast::<T>()
                    .add(index)
                    .write(value)
            };
            prefix.initialized += 1;
        }
        let prefix = core::mem::ManuallyDrop::new(prefix);
        // SAFETY: every element is initialized. The prefix owner is consumed
        // once, so only the returned RRef can run destructors or release RAM.
        let allocation = unsafe { core::ptr::read(&prefix.allocation) };
        let pointer =
            core::ptr::slice_from_raw_parts_mut(allocation.commit().as_ptr().cast::<T>(), len);
        Some(Self {
            // SAFETY: the committed allocation is nonnull, correctly
            // aligned and owns exactly len initialized elements.
            ptr: unsafe { NonNull::new_unchecked(pointer) },
            owner,
        })
    }

    pub fn new_slice_default_aligned(
        owner: DomainId,
        len: usize,
        alignment: usize,
    ) -> Option<Self>
    where
        T: Default,
    {
        Self::new_slice_with_aligned(owner, len, alignment, |_| T::default())
    }
}

impl<T: ?Sized> Drop for RRef<T> {
    fn drop(&mut self) {
        // SAFETY: constructors and raw ownership transfers retain this
        // origin header immediately before the payload. It is consumed
        // only by the unique RRef, including erased slice retirement.
        let header = unsafe {
            self.ptr
                .as_ptr()
                .cast::<u8>()
                .sub(core::mem::size_of::<AllocationHeader>())
                .cast::<AllocationHeader>()
                .read()
        };
        // SAFETY: this RRef exclusively owns the initialized T (including
        // its slice extent) and retains the original allocation Layout.
        unsafe {
            core::ptr::drop_in_place(self.ptr.as_ptr());
            alloc::alloc::dealloc(header.raw.as_ptr(), header.layout);
        }
    }
}

impl<T: ?Sized> RRef<T> {
    pub fn into_raw_parts(self) -> RRefRawParts
    where
        T: 'static,
    {
        RRefRawParts::from_rref(self)
    }

    pub(crate) fn allocation_ptr(&self) -> NonNull<T> {
        self.ptr
    }

    /// # Safety
    /// `ptr` must transfer one live RRef allocation from these constructors,
    /// retaining its origin header and exact pointee metadata. No other
    /// owner, CPU borrow or hardware access may survive the transfer.



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

unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}

