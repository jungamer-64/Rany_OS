// ============================================================================
// kernel_api/src/dma.rs - Public typestate DMA surface
// ============================================================================

use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::{Ordering, fence};

/// CPU owns the DMA buffer and may access its contents.
#[derive(Debug)]
pub struct CpuOwned;

/// A device owns the DMA buffer and CPU access APIs are unavailable.
#[derive(Debug)]
pub struct DeviceOwned;

mod sealed {
    pub trait DmaState {
        const RECLAIM_ON_DROP: bool;
    }

    impl DmaState for super::CpuOwned {
        const RECLAIM_ON_DROP: bool = true;
    }

    impl DmaState for super::DeviceOwned {
        const RECLAIM_ON_DROP: bool = false;
    }
}

pub trait DmaState: sealed::DmaState {}
impl DmaState for CpuOwned {}
impl DmaState for DeviceOwned {}

type ReleaseFn = unsafe fn(*mut u8, usize, u64);

/// Public DMA slice wrapper used across driver and kernel interfaces.
#[derive(Debug)]
pub struct DmaSlice<State: DmaState> {
    phys_addr: u64,
    device_addr: u64,
    virt_addr: NonNull<u8>,
    size: usize,
    releaser: Option<ReleaseFn>,
    _state: PhantomData<State>,
}

unsafe impl<State: DmaState> Send for DmaSlice<State> {}

impl DmaSlice<CpuOwned> {
    /// Construct a DMA slice from kernel-managed raw parts.
    ///
    /// # Safety
    /// The caller must ensure the pointer is valid for `size` bytes and that
    /// `releaser` matches the allocation represented by this buffer.
    pub unsafe fn from_raw_parts(
        phys_addr: u64,
        device_addr: u64,
        virt_addr: *mut u8,
        size: usize,
        releaser: Option<ReleaseFn>,
    ) -> Self {
        let virt_addr = NonNull::new(virt_addr).expect("DMA slice pointer must be non-null");
        Self {
            phys_addr,
            device_addr,
            virt_addr,
            size,
            releaser,
            _state: PhantomData,
        }
    }

    /// Access the DMA region as bytes while CPU-owned.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.virt_addr.as_ptr(), self.size) }
    }

    /// Mutably access the DMA region while CPU-owned.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt_addr.as_ptr(), self.size) }
    }

    /// Start DMA and move the buffer into device-owned state.
    pub fn start_dma(self) -> (DmaSlice<DeviceOwned>, DmaGuard) {
        fence(Ordering::Release);

        let guard = DmaGuard {
            ptr: self.virt_addr,
            phys_addr: self.phys_addr,
            device_addr: self.device_addr,
            size: self.size,
            releaser: self.releaser,
            completed: false,
        };

        let device_owned = DmaSlice {
            phys_addr: self.phys_addr,
            device_addr: self.device_addr,
            virt_addr: self.virt_addr,
            size: self.size,
            releaser: self.releaser,
            _state: PhantomData,
        };

        core::mem::forget(self);
        (device_owned, guard)
    }

    /// Decompose the DMA slice into raw parts for kernel-side bookkeeping.
    pub fn into_raw_parts(
        self,
    ) -> (
        u64,
        u64,
        *mut u8,
        usize,
        Option<unsafe fn(*mut u8, usize, u64)>,
    ) {
        let parts = (
            self.phys_addr,
            self.device_addr,
            self.virt_addr.as_ptr(),
            self.size,
            self.releaser,
        );
        core::mem::forget(self);
        parts
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.virt_addr.as_ptr()
    }
}

impl<State: DmaState> DmaSlice<State> {
    pub fn physical_address(&self) -> u64 {
        self.phys_addr
    }

    pub fn device_address(&self) -> u64 {
        self.device_addr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl<State: DmaState> Drop for DmaSlice<State> {
    fn drop(&mut self) {
        if <State as sealed::DmaState>::RECLAIM_ON_DROP {
            if let Some(releaser) = self.releaser {
                unsafe { releaser(self.virt_addr.as_ptr(), self.size, self.phys_addr) };
            }
        }
    }
}

/// In-flight DMA ownership guard.
#[must_use = "DMA transfers must be completed to recover CPU ownership"]
#[derive(Debug)]
pub struct DmaGuard {
    ptr: NonNull<u8>,
    phys_addr: u64,
    device_addr: u64,
    size: usize,
    releaser: Option<ReleaseFn>,
    completed: bool,
}

unsafe impl Send for DmaGuard {}

impl DmaGuard {
    pub fn physical_address(&self) -> u64 {
        self.phys_addr
    }

    pub fn device_address(&self) -> u64 {
        self.device_addr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn complete(mut self, device_owned: DmaSlice<DeviceOwned>) -> DmaSlice<CpuOwned> {
        debug_assert_eq!(self.ptr, device_owned.virt_addr);
        debug_assert_eq!(self.size, device_owned.size);
        fence(Ordering::Acquire);
        self.completed = true;
        core::mem::drop(device_owned);

        DmaSlice {
            phys_addr: self.phys_addr,
            device_addr: self.device_addr,
            virt_addr: self.ptr,
            size: self.size,
            releaser: self.releaser,
            _state: PhantomData,
        }
    }
}

impl Drop for DmaGuard {
    fn drop(&mut self) {
        if !self.completed {
            #[cfg(debug_assertions)]
            panic!(
                "DmaGuard dropped without complete(); phys={:#x} size={}",
                self.phys_addr, self.size
            );
            #[cfg(not(debug_assertions))]
            log::warn!(
                "DmaGuard leaked without complete(); phys={:#x} size={}",
                self.phys_addr,
                self.size
            );
        }
    }
}
