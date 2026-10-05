//! Driver-side RX authority over framework-owned packet storage.
//!
//! The framework retains physical backing and translations until port stop.
//! A posted lease cannot expose CPU bytes or return storage on Drop. Matching
//! hardware completion grants access only to the initialized prefix; hardware
//! quiescence instead returns an unpublished CPU owner. Abandoning a posted
//! capsule leaves its framework lease outstanding for port finalization.

use super::{AbiError, AbiNetPortRuntime, AbiNetRxMeta, AbiRxLease};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxDeviceRegion {
    pub device_addr: u64,
    pub writable_len: usize,
}

struct RxLeaseCore {
    cookie: u64,
    release: unsafe extern "C" fn(u64, *mut AbiRxLease) -> i32,
    submit: unsafe extern "C" fn(u64, *mut AbiRxLease, AbiNetRxMeta) -> i32,
    lease: AbiRxLease,
}

// SAFETY: acquisition requires a runtime whose callbacks support exclusive
// ownership transfer between CPUs. No CPU reference escapes its lease borrow.
unsafe impl Send for RxLeaseCore {}

impl core::fmt::Debug for RxLeaseCore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxLeaseCore")
            .field("lease_id", &self.lease.lease_id())
            .field("capacity", &self.lease.region.writable_len)
            .finish()
    }
}

impl RxLeaseCore {
    fn device_region(&self) -> RxDeviceRegion {
        RxDeviceRegion {
            device_addr: self.lease.region.device_addr,
            writable_len: self.lease.region.writable_len,
        }
    }

    fn release(&mut self) -> AbiError {
        if self.lease.lease_id().is_none() {
            return AbiError::Success;
        }
        // SAFETY: acquisition retains the callback owner for this lease's
        // lifetime. Only unpublished or quiesced/completed owners call release.
        let status = unsafe { (self.release)(self.cookie, &mut self.lease) };
        let status = AbiError::from_raw(status);
        if status.is_success() && self.lease.lease_id().is_some() {
            AbiError::IoError
        } else {
            status
        }
    }

    fn release_on_drop(&mut self) {
        let cause = self.release();
        if !cause.is_success() {
            // The framework table retains unconsumed storage and its mapping
            // owner for port stop. Drop has no surviving caller to retry.
            log::warn!("RX lease return incomplete; framework retains backing: {cause:?}");
        }
    }
}

#[derive(Debug)]
pub struct CpuRxLease {
    core: RxLeaseCore,
}

impl CpuRxLease {
    pub fn device_region(&self) -> RxDeviceRegion {
        self.core.device_region()
    }

    /// Acquire unpublished packet storage from its retained runtime.
    ///
    /// # Errors
    /// Runtime admission errors are preserved. Invalid storage geometry returns
    /// `InvalidParam` and returns any unpublished wire lease to the framework.
    ///
    /// # Safety
    /// The cookie, callbacks and code must remain live until all acquired
    /// owners end. Callbacks must support ownership transfer between CPUs and
    /// issue unique, exclusively writable packet storage with valid provenance
    /// and backing for the reported capacity. Successful publication must be
    /// followed by hardware completion or quiescence before that storage is
    /// reused. Port finalization retains abandoned leases until DMA ends.
    pub unsafe fn acquire(runtime: AbiNetPortRuntime) -> Result<Self, AbiError> {
        let mut result = Self {
            core: RxLeaseCore {
                cookie: runtime.runtime_cookie,
                release: runtime.release_rx_buffer,
                submit: runtime.submit_rx_buffer,
                lease: AbiRxLease::default(),
            },
        };
        // SAFETY: the caller retains the runtime; this initialized wire slot
        // is exclusively borrowed for the synchronous acquisition callback.
        let status =
            unsafe { (runtime.lease_rx_buffer)(runtime.runtime_cookie, &mut result.core.lease) };
        let status = AbiError::from_raw(status);
        if !status.is_success() {
            return Err(status);
        }
        let region = result
            .core
            .lease
            .writable_region()
            .ok_or(AbiError::InvalidParam)?;
        if region.writable_len > isize::MAX as usize
            || region
                .cpu_ptr
                .addr()
                .checked_add(region.writable_len)
                .is_none()
            || u64::try_from(region.writable_len)
                .ok()
                .and_then(|len| region.device_addr.checked_add(len - 1))
                .is_none()
        {
            return Err(AbiError::InvalidParam);
        }
        Ok(result)
    }

    /// Transfer software authority before the descriptor becomes visible.
    /// Dropping the returned capsule retains the framework's packet lease.
    pub fn arm(mut self) -> PostedRxLease {
        PostedRxLease {
            core: RxLeaseCore {
                cookie: self.core.cookie,
                release: self.core.release,
                submit: self.core.submit,
                lease: core::mem::take(&mut self.core.lease),
            },
        }
    }

    /// Return storage after proving it has no hardware consumer.
    ///
    /// # Errors
    /// Callback failure preserves whether the wire lease was consumed. A
    /// retained owner can retry; consumed failures must not be retried.
    pub fn close(mut self) -> Result<(), RxLeaseCloseError> {
        let cause = self.core.release();
        if cause.is_success() {
            Ok(())
        } else {
            let retained = self.core.lease.lease_id().is_some().then_some(self);
            Err(RxLeaseCloseError { cause, retained })
        }
    }
}

impl Drop for CpuRxLease {
    fn drop(&mut self) {
        self.core.release_on_drop();
    }
}

#[derive(Debug)]
pub struct RxLeaseCloseError {
    pub cause: AbiError,
    pub retained: Option<CpuRxLease>,
}

#[derive(Debug)]
pub struct PostedRxLease {
    core: RxLeaseCore,
}

impl PostedRxLease {
    pub fn device_region(&self) -> RxDeviceRegion {
        self.core.device_region()
    }

    /// End device ownership after a matching terminal hardware completion.
    ///
    /// # Errors
    /// An oversized prefix returns the original posted owner. No CPU access or
    /// buffer return is granted by an invalid completion length.
    ///
    /// # Safety
    /// The driver must validate this lease's queue/slot/generation completion,
    /// establish that the device no longer accesses its region, and acquire
    /// visibility of exactly `written` initialized bytes. No other descriptor
    /// or CPU alias may still access that region.
    pub unsafe fn complete(
        self,
        written: usize,
    ) -> Result<CompletedRxLease, RxLeaseCompletionError> {
        if written > self.core.lease.region.writable_len {
            return Err(RxLeaseCompletionError {
                cause: AbiError::InvalidParam,
                lease: self,
            });
        }
        Ok(CompletedRxLease {
            core: self.core,
            written,
        })
    }

    /// Return CPU authority without claiming any initialized packet bytes.
    ///
    /// # Safety
    /// This lease was never published, or matching queue/device shutdown has
    /// completed and fenced every DMA access to the retained packet region.
    /// A timeout, queue count or scheduler handoff does not prove quiescence.
    pub unsafe fn quiesce(self) -> CpuRxLease {
        CpuRxLease { core: self.core }
    }
}

#[derive(Debug)]
pub struct RxLeaseCompletionError {
    pub cause: AbiError,
    pub lease: PostedRxLease,
}

#[derive(Debug)]
pub struct CompletedRxLease {
    core: RxLeaseCore,
    written: usize,
}

impl CompletedRxLease {
    /// CPU access excludes every byte outside the validated completion prefix.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: acquisition established valid retained storage; completion
        // ended device access and initialized precisely this checked prefix.
        unsafe { core::slice::from_raw_parts(self.core.lease.region.cpu_ptr, self.written) }
    }

    /// Deliver a layout inside the initialized prefix. Every outcome consumes
    /// this driver owner; a rejected frame is returned to its runtime.
    pub fn submit(mut self, meta: AbiNetRxMeta) -> AbiError {
        if !meta.layout().is_valid() || meta.layout().frame_len() > self.written {
            return AbiError::InvalidParam;
        }
        // SAFETY: acquisition retains the callback runtime; completion proved
        // the layout's bytes are initialized and no longer accessed by device.
        let status = unsafe { (self.core.submit)(self.core.cookie, &mut self.core.lease, meta) };
        let status = AbiError::from_raw(status);
        if status.is_success() && self.core.lease.lease_id().is_some() {
            AbiError::IoError
        } else {
            status
        }
    }
}

impl Drop for CompletedRxLease {
    fn drop(&mut self) {
        self.core.release_on_drop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::driver::{
        AbiNetDriverEvent, AbiNetRxFrameLayout, AbiRxWritableRegion, AbiTxDeviceOutcome,
    };
    use core::cell::{Cell, UnsafeCell};
    use core::num::NonZeroU64;

    struct Runtime {
        bytes: UnsafeCell<[u8; 32]>,
        outstanding: Cell<bool>,
        releases: Cell<usize>,
        submitted: Cell<usize>,
        close_failures: Cell<usize>,
        consume_failure: Cell<bool>,
    }

    impl Runtime {
        fn new() -> Self {
            Self {
                bytes: UnsafeCell::new([0xa5; 32]),
                outstanding: Cell::new(false),
                releases: Cell::new(0),
                submitted: Cell::new(0),
                close_failures: Cell::new(0),
                consume_failure: Cell::new(false),
            }
        }

        fn table(&self) -> AbiNetPortRuntime {
            AbiNetPortRuntime::new(
                self as *const Self as u64,
                acquire,
                release,
                submit,
                complete_tx,
                schedule,
                link,
                log_message,
            )
        }
    }

    unsafe extern "C" fn acquire(cookie: u64, out: *mut AbiRxLease) -> i32 {
        // SAFETY: each test retains its Runtime and exclusively borrows out for
        // this synchronous callback, following CpuRxLease::acquire's contract.
        let runtime = unsafe { &*(cookie as *const Runtime) };
        if runtime.outstanding.replace(true) {
            return AbiError::DeviceBusy as i32;
        }
        let lease = AbiRxLease::new(
            NonZeroU64::new(1).unwrap(),
            AbiRxWritableRegion {
                cpu_ptr: runtime.bytes.get().cast(),
                device_addr: 0x2000,
                writable_len: 32,
            },
        )
        .unwrap();
        // SAFETY: the initialized output slot is exclusively borrowed for this
        // callback and receives exactly one newly admitted wire lease.
        unsafe { out.write(lease) };
        AbiError::Success as i32
    }

    unsafe extern "C" fn release(cookie: u64, lease: *mut AbiRxLease) -> i32 {
        // SAFETY: this callback's Runtime is retained by the enclosing test.
        let runtime = unsafe { &*(cookie as *const Runtime) };
        if runtime.close_failures.get() != 0 {
            runtime.close_failures.set(runtime.close_failures.get() - 1);
            return AbiError::DeviceBusy as i32;
        }
        // SAFETY: CPU/completed owners lend their sole initialized wire slot.
        if unsafe { AbiRxLease::take(lease) }.is_none() {
            return AbiError::DeviceNotFound as i32;
        }
        runtime.outstanding.set(false);
        runtime.releases.set(runtime.releases.get() + 1);
        if runtime.consume_failure.get() {
            AbiError::IoError as i32
        } else {
            AbiError::Success as i32
        }
    }

    unsafe extern "C" fn submit(cookie: u64, lease: *mut AbiRxLease, meta: AbiNetRxMeta) -> i32 {
        // SAFETY: this callback's Runtime remains retained by the test.
        let runtime = unsafe { &*(cookie as *const Runtime) };
        // SAFETY: a completed owner lends its sole initialized wire slot.
        if unsafe { AbiRxLease::take(lease) }.is_none() {
            return AbiError::DeviceNotFound as i32;
        }
        runtime.outstanding.set(false);
        runtime.submitted.set(meta.layout().frame_len());
        AbiError::Success as i32
    }

    unsafe extern "C" fn complete_tx(_: u64, _: u64, _: AbiTxDeviceOutcome) -> i32 {
        AbiError::Success as i32
    }
    unsafe extern "C" fn schedule(_: u64, _: AbiNetDriverEvent) -> i32 {
        AbiError::Success as i32
    }
    unsafe extern "C" fn link(_: u64, _: bool) -> i32 {
        AbiError::Success as i32
    }
    unsafe extern "C" fn log_message(_: u64, _: u32, _: *const u8, _: usize) {}

    #[test]
    fn abandoned_posted_lease_remains_owned_by_framework() {
        let runtime = Runtime::new();
        // SAFETY: runtime storage and callbacks remain live through this owner.
        let cpu = unsafe { CpuRxLease::acquire(runtime.table()) }.unwrap();
        drop(cpu);
        assert_eq!(runtime.releases.get(), 1);
        // SAFETY: the same live runtime issues fresh unique storage.
        let posted = unsafe { CpuRxLease::acquire(runtime.table()) }
            .unwrap()
            .arm();
        drop(posted);
        assert!(runtime.outstanding.get());
        assert_eq!(runtime.releases.get(), 1);
        // The runtime is the finalization owner; no hardware was published in
        // this independent callback model, so its teardown may reclaim storage.
    }

    #[test]
    fn completion_exposes_only_written_prefix_and_submits_once() {
        let runtime = Runtime::new();
        // SAFETY: runtime stays live through completion and submission.
        let posted = unsafe { CpuRxLease::acquire(runtime.table()) }
            .unwrap()
            .arm();
        // SAFETY: no hardware was published; the fixture's first 12 initialized
        // bytes model a validated matching terminal hardware completion.
        let completed = unsafe { posted.complete(12) }.unwrap();
        assert_eq!(completed.bytes(), &[0xa5; 12]);
        let meta = AbiNetRxMeta::new(0, AbiNetRxFrameLayout::new(12, 4, 8).unwrap(), 0);
        assert_eq!(completed.submit(meta), AbiError::Success);
        assert_eq!(runtime.submitted.get(), 12);
        assert_eq!(runtime.releases.get(), 0);
        assert!(!runtime.outstanding.get());
    }

    #[test]
    fn oversized_completion_retains_lease_and_unwritten_layout_is_rejected() {
        let runtime = Runtime::new();
        // SAFETY: the fixture stays live through all transitions below.
        let posted = unsafe { CpuRxLease::acquire(runtime.table()) }
            .unwrap()
            .arm();
        // SAFETY: no hardware consumer exists; the reported length is checked
        // independently of initialization and must not grant CPU access.
        let failure = unsafe { posted.complete(33) }.unwrap_err();
        assert_eq!(failure.cause, AbiError::InvalidParam);
        assert!(runtime.outstanding.get());
        assert_eq!(runtime.releases.get(), 0);
        // SAFETY: the same unpublished region has 12 initialized fixture bytes.
        let completed = unsafe { failure.lease.complete(12) }.unwrap();
        let meta = AbiNetRxMeta::new(0, AbiNetRxFrameLayout::whole_payload(13).unwrap(), 0);
        assert_eq!(completed.submit(meta), AbiError::InvalidParam);
        assert_eq!(runtime.submitted.get(), 0);
        assert_eq!(runtime.releases.get(), 1);
    }

    #[test]
    fn close_distinguishes_retained_and_consumed_failure() {
        let runtime = Runtime::new();
        runtime.close_failures.set(2);
        // SAFETY: the runtime stays live through retries and final consumption.
        let posted = unsafe { CpuRxLease::acquire(runtime.table()) }
            .unwrap()
            .arm();
        // SAFETY: no descriptor was published in this model.
        let cpu = unsafe { posted.quiesce() };
        let first = cpu.close().unwrap_err();
        assert_eq!(first.cause, AbiError::DeviceBusy);
        let second = first.retained.unwrap().close().unwrap_err();
        assert_eq!(second.cause, AbiError::DeviceBusy);
        assert_eq!(runtime.releases.get(), 0);
        second.retained.unwrap().close().unwrap();
        assert_eq!(runtime.releases.get(), 1);
        runtime.consume_failure.set(true);
        // SAFETY: the live runtime admits another unique unpublished lease.
        let cpu = unsafe { CpuRxLease::acquire(runtime.table()) }.unwrap();
        let consumed = cpu.close().unwrap_err();
        assert_eq!(consumed.cause, AbiError::IoError);
        assert!(consumed.retained.is_none());
        assert_eq!(runtime.releases.get(), 2);
        assert!(!runtime.outstanding.get());
    }
}
