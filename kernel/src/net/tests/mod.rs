#[cfg(any(test, feature = "qemu-test-export"))]
use alloc::sync::Arc;
#[cfg(any(test, feature = "qemu-test-export"))]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "qemu-test-export")]
pub mod qemu;

#[cfg(any(test, feature = "qemu-test-export"))]
extern crate alloc;

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn run_with_network_event_task<F>(future: F) -> F::Output
where
    F: core::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    crate::net::l4::endpoint::event::reset_event_system_for_tests();

    let result_slot = Arc::new(crate::sync::PoisonLock::new(None));
    let completed = Arc::new(AtomicBool::new(false));

    let mut executor = crate::task::Executor::new();

    let result_slot_clone = result_slot.clone();
    let completed_clone = completed.clone();
    executor.spawn(crate::task::Task::new(async move {
        let output = future.await;
        let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(output);
        completed_clone.store(true, Ordering::Release);
    }));
    executor.spawn(crate::task::Task::new(async {
        crate::net::l4::endpoint::tcp_rx::network_event_task().await;
    }));

    for _ in 0..100_000 {
        executor.drive_once_for_test();
        if completed.load(Ordering::Acquire) {
            let output = result_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .expect("network test helper missing result");
            crate::net::l4::endpoint::event::reset_event_system_for_tests();
            return output;
        }
    }

    crate::net::l4::endpoint::event::reset_event_system_for_tests();
    panic!("network event task helper timed out");
}
