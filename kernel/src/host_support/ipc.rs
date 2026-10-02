#[path = "ipc/rref.rs"]
pub mod rref;

pub use rref::RRef;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Counted(Arc<AtomicUsize>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn aligned_slice_erasure_preserves_layout_and_all_element_destructors() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let owner = RRef::new_slice_with_aligned(DomainId::KERNEL, 5, 4096, |_| {
            Counted(Arc::clone(&dropped))
        })
        .expect("aligned backing");
        assert_eq!(
            owner.allocation_ptr().as_ptr().cast::<u8>().addr() % 4096,
            0
        );
        assert_eq!(owner.len(), 5);
        let raw = owner.into_raw_parts();
        // SAFETY: the sole erased owner retains the exact slice metadata and
        // allocation header; no hardware or Rust borrow uses this backing.
        unsafe { raw.drop_erased() };
        assert_eq!(dropped.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn initializer_unwind_drops_only_the_constructed_prefix() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let outcome = std::panic::catch_unwind(|| {
            RRef::new_slice_with_aligned(DomainId::KERNEL, 8, 4096, |index| {
                if index == 3 {
                    panic!("injected initializer interruption");
                }
                Counted(Arc::clone(&dropped))
            })
        });
        assert!(outcome.is_err());
        assert_eq!(dropped.load(Ordering::Relaxed), 3);
    }
}
