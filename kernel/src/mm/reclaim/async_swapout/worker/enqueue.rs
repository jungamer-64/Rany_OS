use super::*;
#[cfg(any(
    feature = "qemu-test-export",
    all(test, not(feature = "full_mm_tests"))
))]
use core::sync::atomic::Ordering as AtomicOrdering;

// 公開API: try_enqueue_swapout
mod tests;
pub fn try_enqueue_swapout(frame: FrameIndex, kind: SwapKind) -> Result<SwapHandle, SwapError> {
    #[cfg(feature = "qemu-test-export")]
    {
        if let Some(err) =
            decode_test_enqueue_override(QEMU_TEST_ENQUEUE_OVERRIDE.load(AtomicOrdering::Acquire))
        {
            return Err(err);
        }
    }

    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        if let Some(err) =
            decode_test_enqueue_override(TEST_ENQUEUE_OVERRIDE.load(AtomicOrdering::Acquire))
        {
            return Err(err);
        }
        test_impl::try_enqueue(frame, kind)
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::try_enqueue(frame, kind)
    }
}

#[cfg(test)]
pub fn set_test_enqueue_override(value: Option<SwapError>) {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        TEST_ENQUEUE_OVERRIDE.store(encode_test_enqueue_override(value), AtomicOrdering::Release);
    }

    #[cfg(not(all(test, not(feature = "full_mm_tests"))))]
    {
        let _ = value;
    }
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_set_enqueue_override(value: Option<SwapError>) {
    QEMU_TEST_ENQUEUE_OVERRIDE.store(encode_test_enqueue_override(value), AtomicOrdering::Release);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_clear_enqueue_override() {
    qemu_test_set_enqueue_override(None);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_drain_until_idle(max_rounds: usize) -> bool {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::qemu_test_drain_until_idle(max_rounds)
    }

    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        let _ = max_rounds;
        false
    }
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_reset_worker_runtime_state() {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::qemu_test_reset_worker_runtime_state();
    }
}

/// Start the async swapout worker (tests call test worker, kernel calls kernel worker)
pub fn start_worker() {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::start_worker();
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::start_worker();
    }
}

/// Stop the async swapout worker
pub fn stop_worker() {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::stop_worker();
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::stop_worker();
    }
}

/// Return whether the worker is running
pub fn is_worker_running() -> bool {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::is_worker_running()
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::is_worker_running()
    }
}

/// Return (queue_len, file_queue_len)
pub fn queued_counts() -> (usize, usize) {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        (test_impl::_queue_len(), test_impl::_file_queue_len())
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::queued_counts()
    }
}

/// Return the current token count (anon token bucket)
pub fn token_count() -> usize {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::_token_count()
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::token_count()
    }
}

/// Runtime tunables (top-level wrappers)
pub fn set_token_bucket_capacity(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::set_token_bucket_capacity(n);
    }
}

pub fn token_bucket_capacity() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::token_bucket_capacity()
    }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        0
    }
}

pub fn set_token_refill_per_batch(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::set_token_refill_per_batch(n);
    }
}

pub fn token_refill_per_batch() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::token_refill_per_batch()
    }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        0
    }
}

pub fn set_reserved_file_slots(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::set_reserved_file_slots(n);
    }
}

pub fn reserved_file_slots() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::reserved_file_slots()
    }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        0
    }
}

pub fn set_token_count(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::set_token_count(n);
    }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::set_tokens(n);
    }
}

pub fn add_tokens(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::add_tokens_public(n);
    }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::add_tokens(n);
    }
}
