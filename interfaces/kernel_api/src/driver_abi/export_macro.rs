use super::*;


/// Export an `AsyncDriver` implementation as a C-compatible `DriverVTable`.
#[macro_export]
macro_rules! export_async_driver {
    // Entry point: parse args and delegate to @impl
    (
        type: $driver_type:ty,
        constructor: $constructor:expr,
        name: $name:expr,
        driver_type: $dtype:expr,
        version: $version:expr
        $(, irq: $irq:path)?
    ) => {
        $crate::export_async_driver!(@impl
            type = $driver_type,
            constructor = $constructor,
            name = $name,
            driver_type = $dtype,
            version = $version
            $(, irq = $irq)?
        );
    };

    // Impl with IRQ
    (@impl
        type = $driver_type:ty,
        constructor = $constructor:expr,
        name = $name:expr,
        driver_type = $dtype:expr,
        version = $version:expr,
        irq = $irq:path
    ) => {
        #[cfg(feature = "export_driver_entry")]
        #[no_mangle]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::driver_abi::DriverVTable {
            $crate::export_async_driver!(@common_adapters
                type = $driver_type,
                constructor = $constructor,
                name = $name,
                driver_type = $dtype,
                version = $version
            );
            $crate::export_async_driver!(@common_adapters
                type = $driver_type,
                constructor = $constructor,
                name = $name,
                driver_type = $dtype,
                version = $version
            );

            // IRQ Adapter
            extern "C" fn irq_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> bool {
                let ctx_safe = unsafe { &mut *ctx };
                let driver_ptr = ctx_safe.driver_data as *mut $crate::driver_abi::AsyncDriverWrapper<$driver_type>;
                if driver_ptr.is_null() { return false; }
                let wrapper = unsafe { &mut *driver_ptr };
                // Optional: Check busy? IRQs usually are high priority.
                // Assuming IRQ handler is safe to run concurrent with async task logic
                // OR implementation must handle it.
                // However, safe bet: access wrapper.driver
                ($irq)(&mut wrapper.driver)
            }

            static VTABLE: $crate::driver_abi::DriverVTable = $crate::driver_abi::DriverVTable::new(
                $crate::driver_abi::DRIVER_ABI_VERSION,
                probe_adapter,
                start_adapter,
                stop_adapter,
                remove_adapter,
                name_adapter,
                name_len_adapter,
                type_adapter,
                version_adapter,
                None,
                Some(irq_adapter),
            );
            &VTABLE
        }
    };

    // Impl without IRQ
    (@impl
        type = $driver_type:ty,
        constructor = $constructor:expr,
        name = $name:expr,
        driver_type = $dtype:expr,
        version = $version:expr
    ) => {
        #[cfg(feature = "export_driver_entry")]
        #[no_mangle]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::driver_abi::DriverVTable {
             $crate::export_async_driver!(@common_adapters
                type = $driver_type,
                constructor = $constructor,
                name = $name,
                driver_type = $dtype,
                version = $version
            );
             $crate::export_async_driver!(@common_adapters
                type = $driver_type,
                constructor = $constructor,
                name = $name,
                driver_type = $dtype,
                version = $version
            );

            static VTABLE: $crate::driver_abi::DriverVTable = $crate::driver_abi::DriverVTable::new(
                $crate::driver_abi::DRIVER_ABI_VERSION,
                probe_adapter,
                start_adapter,
                stop_adapter,
                remove_adapter,
                name_adapter,
                name_len_adapter,
                type_adapter,
                version_adapter,
                None,
                None,
            );
            &VTABLE
        }
        #[cfg(test)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::driver_abi::DriverVTable {
            // --- Mandatory Adapters ---
            extern "C" fn probe_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                ($probe)(ctx_safe)
            }
            extern "C" fn remove_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                ($remove)(ctx_safe)
            }
            extern "C" fn name_adapter() -> *const u8 {
                ($name)().as_ptr()
            }
            extern "C" fn name_len_adapter() -> usize {
                ($name)().len()
            }
            extern "C" fn type_adapter() -> u32 {
                ($driver_type) as u32
            }
            extern "C" fn version_adapter() -> u64 {
                $version as u64
            }

            // --- Optional Adapters (start/stop) ---
            extern "C" fn start_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($start)(ctx_safe); )?
                rv
            }
            extern "C" fn stop_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($stop)(ctx_safe); )?
                rv
            }

            static VTABLE: $crate::driver_abi::DriverVTable = $crate::driver_abi::DriverVTable::new(
                $crate::driver_abi::DRIVER_ABI_VERSION,
                probe_adapter,
                start_adapter,
                stop_adapter,
                remove_adapter,
                name_adapter,
                name_len_adapter,
                type_adapter,
                version_adapter,
                None,
                None,
            );

            &VTABLE
        }
    };

    // Common adapters generation
    (@common_adapters
        type = $driver_type:ty,
        constructor = $constructor:expr,
        name = $name:expr,
        driver_type = $dtype:expr,
        version = $version:expr
    ) => {
            use $crate::driver::{AsyncDriver, DriverType};
            use $crate::driver_abi::{DriverContext, DriverVTable, DRIVER_ABI_VERSION, AsyncDriverWrapper};
            use $crate::services::kernel;
            use alloc::boxed::Box;
            use alloc::format;
            use core::sync::atomic::Ordering;

            extern "C" fn probe_adapter(ctx: *mut DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };

                // 1. Create the driver instance wrapped
                let driver = Box::new(AsyncDriverWrapper::new($constructor));
                let driver_ptr = Box::into_raw(driver);
                ctx_safe.driver_data = driver_ptr as u64;

                // 2. Spawn async probe
                let future = async move {
                    let wrapper = unsafe { &mut *driver_ptr };
                    let ctx_ref = unsafe { &mut *ctx };

                    // Mark busy
                    if wrapper.busy.swap(true, Ordering::Acquire) {
                        kernel().log("Async probe blocked: Driver busy");
                        return;
                    }

                    if let Err(err) = wrapper.driver.probe(ctx_ref).await {
                         let msg = format!("Async probe failed: {err}");
                         kernel().log(&msg);
                    }

                    // Release busy
                    wrapper.busy.store(false, Ordering::Release);
                };

                match kernel().spawn_task(Box::pin(future)) {
                    Ok(_) => 0,
                    Err(_) => -1,
                }
            }

            extern "C" fn start_adapter(ctx: *mut DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };
                let driver_ptr = ctx_safe.driver_data as *mut AsyncDriverWrapper<$driver_type>;
                if driver_ptr.is_null() { return -1; }

                // Check busy synchronously first (optimization)
                // CAUTION: Determining busy here is racy versus the task starting.
                // However, if we return -3 (DeviceBusy) synchronously, the kernel knows.
                // But the busy flag is set IN the task in probe_adapter.
                // So if we check here, we might miss it.
                // Ideally, we should set busy HERE?
                // If we set busy here, we own the state.
                let wrapper_ref = unsafe { &*driver_ptr };
                if wrapper_ref.busy.swap(true, Ordering::Acquire) {
                    return -3; // DeviceBusy
                }

                // We own the busy lock now. Pass it to task.
                let future = async move {
                    let wrapper = unsafe { &mut *driver_ptr };
                    let _ = wrapper.driver.start().await;
                    wrapper.busy.store(false, Ordering::Release);
                };

                // If spawn fails, we must release lock!
                match kernel().spawn_task(Box::pin(future)) {
                    Ok(_) => 0,
                    Err(_) => {
                        unsafe { (*driver_ptr).busy.store(false, Ordering::Release); }
                        -1
                    }
                }
            }

            extern "C" fn stop_adapter(ctx: *mut DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };
                let driver_ptr = ctx_safe.driver_data as *mut AsyncDriverWrapper<$driver_type>;
                if driver_ptr.is_null() { return 0; }

                let wrapper_ref = unsafe { &*driver_ptr };
                if wrapper_ref.busy.swap(true, Ordering::Acquire) {
                    return -3; // DeviceBusy
                }

                let future = async move {
                    let wrapper = unsafe { &mut *driver_ptr };
                    let _ = wrapper.driver.stop().await;
                    wrapper.busy.store(false, Ordering::Release);
                };

                match kernel().spawn_task(Box::pin(future)) {
                    Ok(_) => 0,
                    Err(_) => {
                         unsafe { (*driver_ptr).busy.store(false, Ordering::Release); }
                        -1
                    }
                }
            }

            extern "C" fn remove_adapter(ctx: *mut DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };
                let driver_ptr = ctx_safe.driver_data as *mut AsyncDriverWrapper<$driver_type>;
                if driver_ptr.is_null() { return 0; }

                // Remove logic should perhaps wait or force?
                // Let's try to take lock.
                let wrapper_ref = unsafe { &*driver_ptr };
                if wrapper_ref.busy.swap(true, Ordering::Acquire) {
                     return -3;
                }

                let future = async move {
                    let wrapper = unsafe { &mut *driver_ptr };
                    let _ = wrapper.driver.remove().await;
                    // Drop wrapper (and driver)
                    unsafe { let _ = Box::from_raw(driver_ptr); }
                    // No need to unlock busy, wrapper is gone.
                };

                match kernel().spawn_task(Box::pin(future)) {
                    Ok(_) => 0,
                    Err(_) => {
                        unsafe { (*driver_ptr).busy.store(false, Ordering::Release); }
                        -1
                    }
                }
            }

            extern "C" fn name_adapter() -> *const u8 {
                ($name)().as_ptr()
            }
            extern "C" fn name_len_adapter() -> usize {
                ($name)().len()
            }
            extern "C" fn type_adapter() -> u32 {
                ($dtype) as u32
            }
            extern "C" fn version_adapter() -> u64 {
                $version as u64
            }
    };
}
