//! Ownership and completion of an asynchronous C driver lifecycle operation.
//!
//! The ABI context owns one host reference until successful remove. An admitted
//! task owns the driver and a copied context. No borrow of the caller's context
//! survives a callback, and no driver future is polled under the host lock.

use super::{AbiError, DriverContext};
use crate::driver::{AsyncDriver, DriverIrqSource};
use crate::error::{KapiError, KapiResult};
use crate::resource::task::{SpawnError, TaskId, TaskOptions};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use exorust_sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Probe,
    Start,
    Stop,
    Remove,
}

enum State<T> {
    Idle {
        driver: T,
        irq: Option<Arc<dyn DriverIrqSource>>,
    },
    Running {
        operation: Operation,
        irq: Option<Arc<dyn DriverIrqSource>>,
    },
    Completed {
        operation: Operation,
        driver: T,
        context: DriverContext,
        result: KapiResult<()>,
        irq: Option<Arc<dyn DriverIrqSource>>,
    },
    Closed,
}

/// Retains a driver until its lifecycle task and explicit remove have completed.
///
/// The exported callbacks report `DeviceBusy` while an operation is running.
/// Repeating the same callback consumes its completion result. A failed stop
/// retains the driver for retry; successful remove releases the context owner.
pub struct AsyncDriverHost<T: AsyncDriver> {
    state: Mutex<State<T>>,
}

struct OperationOwner<T: AsyncDriver> {
    host: Arc<AsyncDriverHost<T>>,
    driver: Option<T>,
    context: DriverContext,
    operation: Operation,
}

impl<T: AsyncDriver> OperationOwner<T> {
    fn finish(mut self, result: KapiResult<()>) {
        self.publish(result);
    }

    fn publish(&mut self, result: KapiResult<()>) {
        if let Some(driver) = self.driver.take() {
            let irq = T::IRQ_SOURCE.and_then(|acquire| acquire(&driver));
            let mut state = self.host.state.lock();
            assert!(
                matches!(*state, State::Running { operation, .. } if operation == self.operation)
            );
            *state = State::Completed {
                operation: self.operation,
                driver,
                context: self.context,
                result,
                irq,
            };
        }
    }

    async fn execute(mut self) {
        let driver = self
            .driver
            .as_mut()
            .expect("operation owns its driver until completion");
        let result = match self.operation {
            Operation::Probe => driver.probe(&mut self.context).await,
            Operation::Start => driver.start().await,
            Operation::Stop => driver.stop().await,
            Operation::Remove => driver.remove().await,
        };
        self.finish(result);
    }
}

impl<T: AsyncDriver> Drop for OperationOwner<T> {
    fn drop(&mut self) {
        // Cancellation is an uncertain device outcome. Keep the driver, copied
        // context and resource owners; the lifecycle owner must request cleanup.
        self.publish(Err(KapiError::IoError));
    }
}

fn admission_error(cause: SpawnError) -> AbiError {
    match cause {
        SpawnError::PhysicalMemoryExhausted => AbiError::OutOfMemory,
        SpawnError::TaskSlotsExhausted | SpawnError::TaskIdentityExhausted => AbiError::DeviceBusy,
        SpawnError::MappingFailed(_) => AbiError::IoError,
        SpawnError::InvalidOptions | SpawnError::InvalidAbiResponse => AbiError::InvalidParam,
        SpawnError::RuntimeAbiMismatch => AbiError::NotSupported,
        _ => AbiError::NotInitialized,
    }
}

impl<T: AsyncDriver> AsyncDriverHost<T> {
    fn request(
        self: &Arc<Self>,
        context: &mut DriverContext,
        operation: Operation,
        admit: impl FnOnce(Pin<Box<dyn Future<Output = ()> + Send>>) -> Result<TaskId, SpawnError>,
    ) -> AbiError {
        let owner = {
            let mut state = self.state.lock();
            match &*state {
                State::Running { .. } => return AbiError::DeviceBusy,
                State::Completed {
                    operation: completed,
                    ..
                } if *completed != operation => {
                    return AbiError::DeviceBusy;
                }
                State::Closed => return AbiError::NotInitialized,
                _ => {}
            }
            match core::mem::replace(&mut *state, State::Closed) {
                State::Completed {
                    driver,
                    context: completed,
                    result,
                    irq,
                    ..
                } => {
                    let identity = context.driver_data;
                    *context = completed;
                    context.driver_data = identity;
                    if result.is_ok() && operation == Operation::Remove {
                        *state = State::Closed;
                        drop(state);
                        drop(driver);
                    } else {
                        *state = State::Idle { driver, irq };
                    }
                    return result.err().map_or(AbiError::Success, AbiError::from);
                }
                State::Idle { driver, irq } => {
                    *state = State::Running { operation, irq };
                    OperationOwner {
                        host: Arc::clone(self),
                        driver: Some(driver),
                        context: *context,
                        operation,
                    }
                }
                _ => {
                    unreachable!("running and closed states are rejected before ownership transfer")
                }
            }
        };
        // Preparation and scheduler admission run outside the host lock. Even an
        // unpolled task carries OperationOwner, so cancellation retains its driver.
        let admitted = Box::try_new(owner.execute())
            .map(Box::into_pin)
            .map_err(|_| SpawnError::PhysicalMemoryExhausted)
            .and_then(|future| admit(future));
        match admitted {
            Ok(_) => AbiError::DeviceBusy,
            Err(cause) => {
                // Rejection consumed no task. Dropping the prepared future has
                // returned the driver to Completed; restore admission eligibility.
                let mut state = self.state.lock();
                let completed = core::mem::replace(&mut *state, State::Closed);
                let State::Completed {
                    driver,
                    operation: completed,
                    irq,
                    ..
                } = completed
                else {
                    unreachable!("rejected future synchronously returns its driver");
                };
                assert!(completed == operation);
                *state = State::Idle { driver, irq };
                admission_error(cause)
            }
        }
    }

    /// Admit probe, or collect the result of an already admitted probe.
    ///
    /// # Safety
    /// `context` is an exclusively borrowed, initialized ABI context. Nonzero
    /// `driver_data` must be the still-owned reference produced by this host's
    /// probe, with the same `T`. The caller must retain the code lease until all
    /// operations and successful remove have completed.
    pub unsafe fn probe(context: *mut DriverContext, constructor: impl FnOnce() -> T) -> i32 {
        let Some(mut context) = core::ptr::NonNull::new(context).filter(|p| p.is_aligned()) else {
            return AbiError::InvalidParam as i32;
        };
        // SAFETY: initialization and exclusive access are the callback contract.
        let context = unsafe { context.as_mut() };
        if context.driver_data == 0 {
            let driver = constructor();
            let irq = T::IRQ_SOURCE.and_then(|acquire| acquire(&driver));
            let host = match Arc::try_new(Self {
                state: Mutex::new(State::Idle { driver, irq }),
            }) {
                Ok(host) => host,
                Err(_) => return AbiError::OutOfMemory as i32,
            };
            context.driver_data = Arc::into_raw(host).expose_provenance() as u64;
        }
        // SAFETY: driver_data is this host's retained context reference.
        unsafe { Self::dispatch(context, Operation::Probe) }
    }

    /// Admit start, or collect its completed result.
    ///
    /// # Safety
    /// The context and code ownership requirements of [`Self::probe`] apply.
    pub unsafe fn start(context: *mut DriverContext) -> i32 {
        // SAFETY: forwarded exclusive context and retained owner contract.
        unsafe { Self::dispatch_pointer(context, Operation::Start) }
    }

    /// Request stop without acknowledging completion before the future returns.
    ///
    /// # Safety
    /// The context and code ownership requirements of [`Self::probe`] apply.
    pub unsafe fn stop(context: *mut DriverContext) -> i32 {
        // SAFETY: forwarded exclusive context and retained owner contract.
        unsafe { Self::dispatch_pointer(context, Operation::Stop) }
    }

    /// Release the context reference only after successful remove completion.
    ///
    /// # Safety
    /// The context and code ownership requirements of [`Self::probe`] apply.
    pub unsafe fn remove(context: *mut DriverContext) -> i32 {
        // SAFETY: forwarded exclusive context and retained owner contract.
        unsafe { Self::dispatch_pointer(context, Operation::Remove) }
    }

    /// Invoke only the retained IRQ resource, including while the lifecycle
    /// task owns the mutable driver. No operation Future is polled here.
    ///
    /// # Safety
    /// The caller retains the initialized ABI context, original host reference
    /// and callback code for the call, excluding concurrent context mutation or
    /// acknowledged removal. Invocation runs on a relay task, never in ISR.
    pub unsafe fn handle_irq(context: *mut DriverContext) -> bool {
        let Some(context) = core::ptr::NonNull::new(context).filter(|p| p.is_aligned()) else {
            return false;
        };
        // SAFETY: the caller retains initialized context storage through this
        // synchronous borrow and excludes mutation/removal for its duration.
        let context = unsafe { context.as_ref() };
        if context.driver_data == 0 {
            return false;
        }
        let pointer = core::ptr::with_exposed_provenance::<Self>(context.driver_data as usize);
        // SAFETY: this exact host reference remains owned by the ABI context.
        let host = unsafe { &*pointer };
        host.relay_irq(context.irq)
    }

    fn relay_irq(&self, vector: u32) -> bool {
        let source = {
            let state = self.state.lock();
            match &*state {
                State::Idle { irq, .. }
                | State::Running { irq, .. }
                | State::Completed { irq, .. } => irq.clone(),
                State::Closed => None,
            }
        };
        // The resource clone outlives its unpublication. Queue/device shutdown
        // must serialize against this source's own access boundary. Neither
        // the host lock nor the operation's driver borrow survives this call.
        source.is_some_and(|source| source.handle_irq(vector))
    }

    unsafe fn dispatch_pointer(context: *mut DriverContext, operation: Operation) -> i32 {
        let Some(mut context) = core::ptr::NonNull::new(context).filter(|p| p.is_aligned()) else {
            return AbiError::InvalidParam as i32;
        };
        // SAFETY: the callback contract supplies exclusive initialized storage.
        unsafe { Self::dispatch(context.as_mut(), operation) }
    }

    unsafe fn dispatch(context: &mut DriverContext, operation: Operation) -> i32 {
        if context.driver_data == 0 {
            return if matches!(operation, Operation::Stop | Operation::Remove) {
                AbiError::Success
            } else {
                AbiError::NotInitialized
            } as i32;
        }
        let pointer = core::ptr::with_exposed_provenance::<Self>(context.driver_data as usize);
        // SAFETY: the context owns this Arc reference until successful remove;
        // increment creates a temporary callback reference without consuming it.
        unsafe { Arc::increment_strong_count(pointer) };
        // SAFETY: paired with the increment above; the original owner remains.
        let host = unsafe { Arc::from_raw(pointer) };
        let status = host.request(context, operation, |future| {
            crate::service::kernel::instance().spawn(future, TaskOptions::any())
        });
        if status == AbiError::Success && operation == Operation::Remove {
            context.driver_data = 0;
            // SAFETY: remove's successful completion consumed the driver and
            // uniquely releases the original context reference, once.
            unsafe { drop(Arc::from_raw(pointer)) };
        }
        status as i32
    }
}

/// Export lifecycle callbacks backed by an owned asynchronous operation host.
#[macro_export]
macro_rules! export_async_driver {
    (
        type: $driver:ty,
        constructor: $constructor:expr,
        name: $name:expr,
        driver_type: $kind:expr,
        version: $version:expr
    ) => {
        $crate::declare_rany_type_id_section!(
            $crate::__type_id::IPC_INTERFACE,
            $crate::__type_id::KERNEL_API_INTERFACE,
            $crate::__type_id::DRIVER_EXPORTS_INTERFACE
        );
        pub fn standalone_driver_vtable() -> *const $crate::abi::driver::DriverVTable {
            use $crate::abi::driver::{
                AsyncDriverHost, DRIVER_ABI_VERSION, DriverContext, DriverVTable, DriverVTableFns,
            };
            extern "C" fn probe(context: *mut DriverContext) -> i32 {
                // SAFETY: the service host exclusively retains context and code
                // until acknowledged remove, as required by the driver ABI.
                unsafe { AsyncDriverHost::<$driver>::probe(context, || $constructor) }
            }
            extern "C" fn start(context: *mut DriverContext) -> i32 {
                // SAFETY: the driver ABI retains the context's host reference.
                unsafe { AsyncDriverHost::<$driver>::start(context) }
            }
            extern "C" fn stop(context: *mut DriverContext) -> i32 {
                // SAFETY: the driver ABI retains the context's host reference.
                unsafe { AsyncDriverHost::<$driver>::stop(context) }
            }
            extern "C" fn remove(context: *mut DriverContext) -> i32 {
                // SAFETY: the driver ABI retains the context's host reference.
                unsafe { AsyncDriverHost::<$driver>::remove(context) }
            }
            unsafe extern "C" fn irq(context: *mut DriverContext) -> bool {
                // SAFETY: the relay owns the live context/instance/code through
                // this call; the host lends only its retained IRQ resource.
                unsafe { AsyncDriverHost::<$driver>::handle_irq(context) }
            }
            extern "C" fn name() -> *const u8 {
                ($name)().as_ptr()
            }
            extern "C" fn name_len() -> usize {
                ($name)().len()
            }
            extern "C" fn kind() -> u32 {
                ($kind) as u32
            }
            extern "C" fn version() -> u64 {
                $version as u64
            }
            static VTABLE: DriverVTable = DriverVTable::new(
                DRIVER_ABI_VERSION,
                DriverVTableFns {
                    probe,
                    start,
                    stop,
                    remove,
                    name,
                    name_len,
                    driver_type: kind,
                    version,
                    request_capabilities: None,
                    handle_irq: match <$driver as $crate::driver::AsyncDriver>::IRQ_SOURCE {
                        Some(_) => Some(irq),
                        None => None,
                    },
                },
            );
            &VTABLE
        }
        #[cfg(all(feature = "export_driver_entry", not(test)))]
        #[unsafe(no_mangle)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::abi::driver::DriverVTable {
            standalone_driver_vtable()
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::DriverType;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};

    #[derive(Default)]
    struct Observations {
        probe_calls: AtomicUsize,
        stop_calls: AtomicUsize,
        probe_irq: AtomicUsize,
        allow_probe: AtomicBool,
        drops: AtomicUsize,
        irq_calls: AtomicUsize,
    }

    struct Driver {
        observations: Arc<Observations>,
    }

    impl DriverIrqSource for Observations {
        fn handle_irq(&self, vector: u32) -> bool {
            self.irq_calls.fetch_add(1, Ordering::Relaxed);
            self.probe_irq.store(vector as usize, Ordering::Relaxed);
            self.allow_probe.store(true, Ordering::Release);
            true
        }
    }

    fn irq_source(driver: &Driver) -> Option<Arc<dyn DriverIrqSource>> {
        Some(Arc::clone(&driver.observations) as Arc<dyn DriverIrqSource>)
    }

    impl Drop for Driver {
        fn drop(&mut self) {
            self.observations.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl AsyncDriver for Driver {
        const IRQ_SOURCE: Option<crate::driver::DriverIrqSourceAcquire<Self>> = Some(irq_source);
        fn name(&self) -> &str {
            "owned-lifecycle"
        }
        fn driver_type(&self) -> DriverType {
            DriverType::Network
        }
        async fn probe(&mut self, context: &mut DriverContext) -> KapiResult<()> {
            self.observations
                .probe_calls
                .fetch_add(1, Ordering::Relaxed);
            self.observations
                .probe_irq
                .store(context.irq as usize, Ordering::Relaxed);
            core::future::poll_fn(|_| {
                if self.observations.allow_probe.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            context.flags = 71;
            Ok(())
        }
        async fn stop(&mut self) -> KapiResult<()> {
            if self.observations.stop_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(KapiError::Busy)
            } else {
                Ok(())
            }
        }
        async fn remove(&mut self) -> KapiResult<()> {
            Ok(())
        }
    }

    fn host(observations: &Arc<Observations>) -> Arc<AsyncDriverHost<Driver>> {
        let driver = Driver {
            observations: Arc::clone(observations),
        };
        let irq = irq_source(&driver);
        Arc::new(AsyncDriverHost {
            state: Mutex::new(State::Idle { driver, irq }),
        })
    }

    #[test]
    fn context_is_copied_and_completion_is_collected_after_the_future_returns() {
        let observations = Arc::new(Observations::default());
        let host = host(&observations);
        let mut context = DriverContext::new();
        context.irq = 7;
        let mut admitted = None;
        assert_eq!(
            host.request(&mut context, Operation::Probe, |future| {
                admitted = Some(future);
                Ok(TaskId::from_raw(11))
            }),
            AbiError::DeviceBusy
        );
        context.irq = 99;
        let mut future = admitted.unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(observations.probe_irq.load(Ordering::Relaxed), 7);
        assert_eq!(
            host.request(&mut context, Operation::Stop, |_| {
                panic!("a second operation cannot acquire a running driver")
            }),
            AbiError::DeviceBusy
        );
        observations.allow_probe.store(true, Ordering::Release);
        assert!(future.as_mut().poll(&mut cx).is_ready());
        drop(future);
        assert_eq!(context.flags, 0);
        assert_eq!(
            host.request(&mut context, Operation::Probe, |_| {
                panic!("completion collection must not admit a second poll")
            }),
            AbiError::Success
        );
        assert_eq!(context.flags, 71);
        assert_eq!(context.irq, 7);
        assert_eq!(observations.probe_calls.load(Ordering::Relaxed), 1);
        assert_eq!(observations.drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn irq_resource_progresses_while_lifecycle_owns_the_driver_and_ends_on_remove() {
        let observations = Arc::new(Observations::default());
        let host = host(&observations);
        let mut context = DriverContext::new();
        let context_owner = Arc::into_raw(Arc::clone(&host));
        context.driver_data = context_owner.expose_provenance() as u64;
        context.irq = 41;
        let mut admitted = None;
        assert_eq!(
            host.request(&mut context, Operation::Probe, |future| {
                admitted = Some(future);
                Ok(TaskId::from_raw(15))
            }),
            AbiError::DeviceBusy
        );
        let mut future = admitted.unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert!(!observations.allow_probe.load(Ordering::Acquire));
        // SAFETY: the context owns exactly this live host reference and the
        // test retains its code/storage for the exclusive relay callback borrow.
        assert!(unsafe { AsyncDriverHost::<Driver>::handle_irq(&mut context) });
        assert_eq!(observations.irq_calls.load(Ordering::Relaxed), 1);
        assert!(future.as_mut().poll(&mut cx).is_ready());
        drop(future);
        assert_eq!(
            host.request(&mut context, Operation::Probe, |_| {
                panic!("probe completion must be collected without repolling the driver")
            }),
            AbiError::Success
        );
        let mut admitted = None;
        assert_eq!(
            host.request(&mut context, Operation::Remove, |future| {
                admitted = Some(future);
                Ok(TaskId::from_raw(16))
            }),
            AbiError::DeviceBusy
        );
        let mut future = admitted.unwrap();
        assert!(future.as_mut().poll(&mut cx).is_ready());
        drop(future);
        assert_eq!(
            host.request(&mut context, Operation::Remove, |_| {
                panic!("remove acknowledgement cannot admit another operation")
            }),
            AbiError::Success
        );
        assert!(!host.relay_irq(41));
        assert_eq!(observations.irq_calls.load(Ordering::Relaxed), 1);
        assert_eq!(observations.drops.load(Ordering::Relaxed), 1);
        context.driver_data = 0;
        // SAFETY: request collected removal above; this releases exactly the
        // context's original Arc reference, normally consumed by dispatch.
        unsafe { drop(Arc::from_raw(context_owner)) };
    }

    #[test]
    fn unpolled_and_pending_cancellation_keep_the_driver_for_explicit_cleanup() {
        for poll_once in [false, true] {
            let observations = Arc::new(Observations::default());
            let host = host(&observations);
            let mut context = DriverContext::new();
            let mut admitted = None;
            assert_eq!(
                host.request(&mut context, Operation::Probe, |future| {
                    admitted = Some(future);
                    Ok(TaskId::from_raw(12))
                }),
                AbiError::DeviceBusy
            );
            let mut future = admitted.unwrap();
            if poll_once {
                assert!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            drop(future);
            assert_eq!(observations.drops.load(Ordering::Relaxed), 0);
            assert_eq!(
                host.request(&mut context, Operation::Probe, |_| {
                    panic!("cancelled completion belongs to the lifecycle owner")
                }),
                AbiError::IoError
            );
            let mut admitted = None;
            assert_eq!(
                host.request(&mut context, Operation::Remove, |future| {
                    admitted = Some(future);
                    Ok(TaskId::from_raw(13))
                }),
                AbiError::DeviceBusy
            );
            let mut future = admitted.unwrap();
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
            drop(future);
            assert_eq!(observations.drops.load(Ordering::Relaxed), 0);
            assert_eq!(
                host.request(&mut context, Operation::Remove, |_| {
                    panic!("remove is acknowledged only once")
                }),
                AbiError::Success
            );
            assert_eq!(observations.drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn scheduler_rejection_restores_the_driver_without_polling_it() {
        let observations = Arc::new(Observations::default());
        let host = host(&observations);
        let mut context = DriverContext::new();
        assert_eq!(
            host.request(&mut context, Operation::Probe, |future| {
                drop(future);
                Err(SpawnError::PhysicalMemoryExhausted)
            }),
            AbiError::OutOfMemory
        );
        assert!(matches!(*host.state.lock(), State::Idle { .. }));
        assert_eq!(observations.probe_calls.load(Ordering::Relaxed), 0);
        assert_eq!(observations.drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn incomplete_device_stop_can_be_retried_without_releasing_the_driver() {
        let observations = Arc::new(Observations::default());
        let host = host(&observations);
        let mut context = DriverContext::new();
        for expected in [AbiError::DeviceBusy, AbiError::Success] {
            let mut admitted = None;
            assert_eq!(
                host.request(&mut context, Operation::Stop, |future| {
                    admitted = Some(future);
                    Ok(TaskId::from_raw(14))
                }),
                AbiError::DeviceBusy
            );
            let mut future = admitted.unwrap();
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
            drop(future);
            assert_eq!(
                host.request(&mut context, Operation::Stop, |_| {
                    panic!("device completion must be collected before retry")
                }),
                expected
            );
            assert_eq!(observations.drops.load(Ordering::Relaxed), 0);
        }
        assert_eq!(observations.stop_calls.load(Ordering::Relaxed), 2);
    }
}
