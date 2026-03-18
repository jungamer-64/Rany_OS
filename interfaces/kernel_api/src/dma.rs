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
type KernelObjectReleaseFn = fn(usize);
type KernelReleaseFn = fn(*mut u8, usize, u64);

/// Drop strategy for DMA buffers materialized by kernel/framework code.
///
/// This is the only public raw construction policy left in the Rust DMA API.
/// Driver/application code should obtain DMA buffers through higher-level
/// allocation APIs instead of constructing `DmaSlice` values directly.
#[derive(Clone, Copy)]
pub enum InternalDmaReclaimer {
    /// The buffer is tracked by an opaque kernel DMA handle.
    KernelHandle {
        dma_handle_id: u64,
        releaser: Option<unsafe fn(u64)>,
    },
    /// The buffer remains owned by an opaque in-kernel RAII object. The token
    /// must identify exactly one boxed owner value whose drop path performs the
    /// matching cleanup for this DMA allocation.
    KernelObject {
        token: usize,
        releaser: Option<fn(usize)>,
    },
    /// The buffer is owned by in-kernel infrastructure and is reclaimed by
    /// a raw pointer/size/host-address callback.
    KernelBuffer {
        releaser: Option<fn(*mut u8, usize, u64)>,
    },
}

/// Public DMA slice wrapper used across driver and kernel interfaces.
#[derive(Debug)]
pub struct DmaSlice<State: DmaState> {
    dma_handle_id: u64,
    host_addr: u64,
    device_addr: u64,
    virt_addr: NonNull<u8>,
    size: usize,
    handle_releaser: Option<HandleReleaseFn>,
    kernel_object_token: usize,
    kernel_object_releaser: Option<KernelObjectReleaseFn>,
    kernel_releaser: Option<KernelReleaseFn>,
    _state: PhantomData<State>,
}

unsafe impl<State: DmaState> Send for DmaSlice<State> {}

impl DmaSlice<CpuOwned> {
    unsafe fn from_parts_unchecked(
        host_addr: u64,
        dma_handle_id: u64,
        device_addr: u64,
        virt_addr: *mut u8,
        size: usize,
        handle_releaser: Option<HandleReleaseFn>,
        kernel_object_token: usize,
        kernel_object_releaser: Option<KernelObjectReleaseFn>,
        kernel_releaser: Option<KernelReleaseFn>,
    ) -> Self {
        assert!(
            size <= isize::MAX as usize,
            "DMA slice size must fit within isize"
        );
        debug_assert!(
            (handle_releaser.is_some() as u8)
                + (kernel_object_releaser.is_some() as u8)
                + (kernel_releaser.is_some() as u8)
                <= 1,
            "DMA slice must not carry multiple reclaim paths"
        );
        let virt_addr = NonNull::new(virt_addr).expect("DMA slice pointer must be non-null");
        Self {
            dma_handle_id,
            host_addr,
            device_addr,
            virt_addr,
            size,
            handle_releaser,
            kernel_object_token,
            kernel_object_releaser,
            kernel_releaser,
            _state: PhantomData,
        }
    }

    /// Construct a DMA slice from ABI-managed raw parts.
    ///
    /// # Safety
    /// The caller must ensure that `virt_addr` points to a live allocation
    /// valid for `size` bytes, that `dma_handle_id` identifies the same buffer,
    /// and that `releaser` will eventually release that handle exactly once.
    pub(crate) unsafe fn from_abi_parts_unchecked(
        dma_handle_id: u64,
        device_addr: u64,
        virt_addr: *mut u8,
        size: usize,
        releaser: Option<HandleReleaseFn>,
    ) -> Self {
        unsafe {
            Self::from_parts_unchecked(
                0,
                dma_handle_id,
                device_addr,
                virt_addr,
                size,
                releaser,
                0,
                None,
                None,
            )
        }
    }

    /// Construct a DMA slice from kernel/framework-owned raw DMA parts.
    ///
    /// # Safety
    /// `virt_addr` must be non-null and valid for `size` bytes, `host_addr` and
    /// `device_addr` must describe the same backing allocation, and `reclaimer`
    /// must match the ownership model of that allocation. `KernelObject`
    /// requires that `token` identify exactly one boxed kernel owner whose drop
    /// path reclaims the same DMA allocation, while `KernelBuffer` requires a
    /// matching raw pointer/size/host-address releaser. The caller must ensure
    /// no competing CPU-owned `DmaSlice` exists for the same buffer.
    pub unsafe fn from_internal_parts_unchecked(
        host_addr: u64,
        device_addr: u64,
        virt_addr: *mut u8,
        size: usize,
        reclaimer: InternalDmaReclaimer,
    ) -> Self {
        let (
            dma_handle_id,
            handle_releaser,
            kernel_object_token,
            kernel_object_releaser,
            kernel_releaser,
        ) = match reclaimer {
            InternalDmaReclaimer::KernelHandle {
                dma_handle_id,
                releaser,
            } => (dma_handle_id, releaser, 0, None, None),
            InternalDmaReclaimer::KernelObject { token, releaser } => {
                (0, None, token, releaser, None)
            }
            InternalDmaReclaimer::KernelBuffer { releaser } => (0, None, 0, None, releaser),
        };
        unsafe {
            Self::from_parts_unchecked(
                host_addr,
                dma_handle_id,
                device_addr,
                virt_addr,
                size,
                handle_releaser,
                kernel_object_token,
                kernel_object_releaser,
                kernel_releaser,
            )
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
            kernel_object_token: self.kernel_object_token,
            kernel_object_releaser: self.kernel_object_releaser,
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
            kernel_object_token: self.kernel_object_token,
            kernel_object_releaser: self.kernel_object_releaser,
            kernel_releaser: self.kernel_releaser,
            _state: PhantomData,
        };

        core::mem::forget(self);
        (device_owned, guard)
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
            } else if let Some(releaser) = self.kernel_object_releaser {
                releaser(self.kernel_object_token);
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
    kernel_object_token: usize,
    kernel_object_releaser: Option<KernelObjectReleaseFn>,
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
            kernel_object_token: self.kernel_object_token,
            kernel_object_releaser: self.kernel_object_releaser,
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::alloc::{Layout, alloc, dealloc};
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    static KERNEL_RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static KERNEL_RELEASE_HOST: AtomicU64 = AtomicU64::new(0);
    static KERNEL_OBJECT_RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static KERNEL_OBJECT_LAST_TOKEN: AtomicUsize = AtomicUsize::new(0);

    fn release_kernel_buffer(ptr: *mut u8, size: usize, host_addr: u64) {
        KERNEL_RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
        KERNEL_RELEASE_HOST.store(host_addr, Ordering::SeqCst);
        let layout = Layout::from_size_align(size.max(1), 1).expect("valid test DMA layout");
        unsafe { dealloc(ptr, layout) };
    }

    fn alloc_test_buffer(size: usize) -> *mut u8 {
        let layout = Layout::from_size_align(size.max(1), 1).expect("valid test DMA layout");
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null());
        unsafe { core::ptr::write_bytes(ptr, 0, size) };
        ptr
    }

    struct TestKernelObjectOwner {
        ptr: *mut u8,
        size: usize,
    }

    impl Drop for TestKernelObjectOwner {
        fn drop(&mut self) {
            let layout =
                Layout::from_size_align(self.size.max(1), 1).expect("valid test DMA layout");
            unsafe { dealloc(self.ptr, layout) };
        }
    }

    fn release_kernel_object(token: usize) {
        KERNEL_OBJECT_RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
        KERNEL_OBJECT_LAST_TOKEN.store(token, Ordering::SeqCst);
        let _ = unsafe { Box::from_raw(token as *mut TestKernelObjectOwner) };
    }

    #[test]
    fn internal_unchecked_constructor_reclaims_on_drop() {
        KERNEL_RELEASE_COUNT.store(0, Ordering::SeqCst);
        KERNEL_RELEASE_HOST.store(0, Ordering::SeqCst);

        let ptr = alloc_test_buffer(64);
        let dma = unsafe {
            DmaSlice::from_internal_parts_unchecked(
                0x3000,
                0x4000,
                ptr,
                64,
                InternalDmaReclaimer::KernelBuffer {
                    releaser: Some(release_kernel_buffer),
                },
            )
        };

        drop(dma);

        assert_eq!(KERNEL_RELEASE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(KERNEL_RELEASE_HOST.load(Ordering::SeqCst), 0x3000);
    }

    #[test]
    fn kernel_object_reclaimer_runs_once_on_drop() {
        KERNEL_OBJECT_RELEASE_COUNT.store(0, Ordering::SeqCst);
        KERNEL_OBJECT_LAST_TOKEN.store(0, Ordering::SeqCst);

        let ptr = alloc_test_buffer(48);
        let token = Box::into_raw(Box::new(TestKernelObjectOwner { ptr, size: 48 })) as usize;
        let dma = unsafe {
            DmaSlice::from_internal_parts_unchecked(
                0x7100,
                0x7200,
                ptr,
                48,
                InternalDmaReclaimer::KernelObject {
                    token,
                    releaser: Some(release_kernel_object),
                },
            )
        };

        drop(dma);

        assert_eq!(KERNEL_OBJECT_RELEASE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(KERNEL_OBJECT_LAST_TOKEN.load(Ordering::SeqCst), token);
    }

    #[test]
    fn start_dma_and_complete_preserve_cpu_access() {
        KERNEL_RELEASE_COUNT.store(0, Ordering::SeqCst);
        KERNEL_RELEASE_HOST.store(0, Ordering::SeqCst);

        let ptr = alloc_test_buffer(32);
        let mut dma = unsafe {
            DmaSlice::from_internal_parts_unchecked(
                0x5000,
                0x6000,
                ptr,
                32,
                InternalDmaReclaimer::KernelBuffer {
                    releaser: Some(release_kernel_buffer),
                },
            )
        };
        dma.as_slice_mut()[0] = 0xAA;
        dma.as_slice_mut()[31] = 0x55;

        let (device_owned, guard) = dma.start_dma();
        let cpu_owned = guard.complete(device_owned);

        assert_eq!(cpu_owned.as_slice()[0], 0xAA);
        assert_eq!(cpu_owned.as_slice()[31], 0x55);
        drop(cpu_owned);

        assert_eq!(KERNEL_RELEASE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(KERNEL_RELEASE_HOST.load(Ordering::SeqCst), 0x5000);
    }

    #[test]
    fn kernel_object_reclaimer_survives_start_dma_and_complete() {
        KERNEL_OBJECT_RELEASE_COUNT.store(0, Ordering::SeqCst);
        KERNEL_OBJECT_LAST_TOKEN.store(0, Ordering::SeqCst);

        let ptr = alloc_test_buffer(24);
        let token = Box::into_raw(Box::new(TestKernelObjectOwner { ptr, size: 24 })) as usize;
        let mut dma = unsafe {
            DmaSlice::from_internal_parts_unchecked(
                0x8100,
                0x8200,
                ptr,
                24,
                InternalDmaReclaimer::KernelObject {
                    token,
                    releaser: Some(release_kernel_object),
                },
            )
        };
        dma.as_slice_mut()[0] = 0x11;
        dma.as_slice_mut()[23] = 0x22;

        let (device_owned, guard) = dma.start_dma();
        let cpu_owned = guard.complete(device_owned);

        assert_eq!(cpu_owned.as_slice()[0], 0x11);
        assert_eq!(cpu_owned.as_slice()[23], 0x22);
        drop(cpu_owned);

        assert_eq!(KERNEL_OBJECT_RELEASE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(KERNEL_OBJECT_LAST_TOKEN.load(Ordering::SeqCst), token);
    }
}
