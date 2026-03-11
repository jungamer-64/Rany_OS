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

type HandleReleaseFn = unsafe fn(u64);
type KernelReleaseFn = fn(*mut u8, usize, u64);

/// Public DMA slice wrapper used across driver and kernel interfaces.
#[derive(Debug)]
pub struct DmaSlice<State: DmaState> {
    dma_handle_id: u64,
    host_addr: u64,
    device_addr: u64,
    virt_addr: NonNull<u8>,
    size: usize,
    handle_releaser: Option<HandleReleaseFn>,
    kernel_releaser: Option<KernelReleaseFn>,
    _state: PhantomData<State>,
}

unsafe impl<State: DmaState> Send for DmaSlice<State> {}

impl DmaSlice<CpuOwned> {
    /// Construct a DMA slice from ABI-managed raw parts.
    ///
    /// This constructor is intended for driver / cell-runtime import paths
    /// where the kernel tracks ownership via an opaque DMA handle ID.
    ///
    /// # Safety
    /// The caller must ensure the pointer is valid for `size` bytes and that
    /// `releaser` matches the allocation represented by this buffer.
    pub unsafe fn from_raw_parts(
        dma_handle_id: u64,
        device_addr: u64,
        virt_addr: *mut u8,
        size: usize,
        releaser: Option<HandleReleaseFn>,
    ) -> Self {
        unsafe { Self::from_kernel_parts(0, dma_handle_id, device_addr, virt_addr, size, releaser) }
    }

    /// Construct a DMA slice from kernel-managed raw parts.
    ///
    /// # Safety
    /// The caller must ensure the pointer is valid for `size` bytes and that
    /// `releaser` matches the allocation represented by this buffer.
    pub unsafe fn from_kernel_parts(
        host_addr: u64,
        dma_handle_id: u64,
        device_addr: u64,
        virt_addr: *mut u8,
        size: usize,
        releaser: Option<HandleReleaseFn>,
    ) -> Self {
        let virt_addr = NonNull::new(virt_addr).expect("DMA slice pointer must be non-null");
        Self {
            dma_handle_id,
            host_addr,
            device_addr,
            virt_addr,
            size,
            handle_releaser: releaser,
            kernel_releaser: None,
            _state: PhantomData,
        }
    }

    /// Construct a DMA slice owned by in-kernel infrastructure.
    ///
    /// # Safety
    /// The caller must ensure `virt_addr` and `kernel_releaser` describe the
    /// same allocation and that the buffer remains valid for `size` bytes.
    pub unsafe fn from_internal_parts(
        host_addr: u64,
        device_addr: u64,
        virt_addr: *mut u8,
        size: usize,
        kernel_releaser: Option<KernelReleaseFn>,
    ) -> Self {
        let virt_addr = NonNull::new(virt_addr).expect("DMA slice pointer must be non-null");
        Self {
            dma_handle_id: 0,
            host_addr,
            device_addr,
            virt_addr,
            size,
            handle_releaser: None,
            kernel_releaser,
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
            dma_handle_id: self.dma_handle_id,
            host_addr: self.host_addr,
            device_addr: self.device_addr,
            size: self.size,
            handle_releaser: self.handle_releaser,
            kernel_releaser: self.kernel_releaser,
            completed: false,
        };

        let device_owned = DmaSlice {
            dma_handle_id: self.dma_handle_id,
            host_addr: self.host_addr,
            device_addr: self.device_addr,
            virt_addr: self.virt_addr,
            size: self.size,
            handle_releaser: self.handle_releaser,
            kernel_releaser: self.kernel_releaser,
            _state: PhantomData,
        };

        core::mem::forget(self);
        (device_owned, guard)
    }

    /// Decompose the DMA slice into raw parts for kernel-side bookkeeping.
    pub fn into_raw_parts(self) -> (u64, u64, u64, *mut u8, usize, Option<unsafe fn(u64)>) {
        let parts = (
            self.host_addr,
            self.dma_handle_id,
            self.device_addr,
            self.virt_addr.as_ptr(),
            self.size,
            self.handle_releaser,
        );
        core::mem::forget(self);
        parts
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.virt_addr.as_ptr()
    }
}

impl<State: DmaState> DmaSlice<State> {
    pub fn dma_handle_id(&self) -> u64 {
        self.dma_handle_id
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
            if let Some(releaser) = self.handle_releaser {
                unsafe { releaser(self.dma_handle_id) };
            } else if let Some(releaser) = self.kernel_releaser {
                releaser(self.virt_addr.as_ptr(), self.size, self.host_addr);
            }
        }
    }
}

/// In-flight DMA ownership guard.
#[must_use = "DMA transfers must be completed to recover CPU ownership"]
#[derive(Debug)]
pub struct DmaGuard {
    ptr: NonNull<u8>,
    dma_handle_id: u64,
    host_addr: u64,
    device_addr: u64,
    size: usize,
    handle_releaser: Option<HandleReleaseFn>,
    kernel_releaser: Option<KernelReleaseFn>,
    completed: bool,
}

unsafe impl Send for DmaGuard {}

impl DmaGuard {
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
            dma_handle_id: self.dma_handle_id,
            host_addr: self.host_addr,
            device_addr: self.device_addr,
            virt_addr: self.ptr,
            size: self.size,
            handle_releaser: self.handle_releaser,
            kernel_releaser: self.kernel_releaser,
            _state: PhantomData,
        }
    }
}

impl Drop for DmaGuard {
    fn drop(&mut self) {
        if !self.completed {
            #[cfg(debug_assertions)]
            panic!(
                "DmaGuard dropped without complete(); dma_handle_id={} device={:#x} size={}",
                self.dma_handle_id, self.device_addr, self.size
            );
            #[cfg(not(debug_assertions))]
            log::warn!(
                "DmaGuard leaked without complete(); dma_handle_id={} device={:#x} size={}",
                self.dma_handle_id,
                self.device_addr,
                self.size
            );
        }
    }
}
