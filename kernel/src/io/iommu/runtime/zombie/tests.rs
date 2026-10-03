use super::*;
use alloc::sync::Arc;
use core::sync::atomic::AtomicUsize;

struct OwnedValue {
    identity: usize,
    progress: usize,
    dropped: Arc<AtomicUsize>,
}
impl Drop for OwnedValue {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
fn value(identity: usize, dropped: &Arc<AtomicUsize>) -> OwnedValue {
    OwnedValue {
        identity,
        progress: 0,
        dropped: Arc::clone(dropped),
    }
}
// The fixture models the caller retaining its owned value when admission fails.
fn offer<const N: usize>(
    slots: &ReclaimSlots<OwnedValue, N>,
    value: OwnedValue,
) -> Result<(), OwnedValue> {
    match slots.reserve() {
        Some(slot) => {
            slot.publish(value);
            Ok(())
        }
        None => Err(value),
    }
}
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn rejected_queue_value_retains_ownership_and_completed_values_drop_once() {
    let slots = ReclaimSlots::<OwnedValue, 2>::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    assert!(offer(&slots, value(1, &dropped)).is_ok());
    assert!(offer(&slots, value(2, &dropped)).is_ok());
    let rejected = offer(&slots, value(3, &dropped))
        .err()
        .expect("full queue returns owner");
    assert_eq!(rejected.identity, 3);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    assert_eq!(slots.process(1, |_| Ok(())), 1);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert!(offer(&slots, rejected).is_ok());
    assert_eq!(slots.process(2, |_| Ok(())), 2);
    assert_eq!(dropped.load(Ordering::Relaxed), 3);
    assert!(!slots.has_pending());
}
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn failed_retirement_retains_progress_and_counts_against_pass_budget() {
    let slots = ReclaimSlots::<OwnedValue, 2>::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    assert!(offer(&slots, value(10, &dropped)).is_ok());
    assert!(offer(&slots, value(20, &dropped)).is_ok());
    let mut attempts = 0;
    assert_eq!(
        slots.process(1, |owner| {
            owner.progress += 1;
            attempts += 1;
            Err(IommuError::Timeout)
        }),
        0
    );
    assert_eq!(attempts, 1);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    assert!(slots.has_pending());
    let mut progress = 0;
    assert_eq!(
        slots.process(2, |owner| {
            progress += owner.progress;
            Ok(())
        }),
        2
    );
    assert_eq!(progress, 1);
    assert_eq!(dropped.load(Ordering::Relaxed), 2);
}
#[cfg(all(feature = "std", test))]
#[test]
fn concurrent_producers_return_every_unaccepted_owner() {
    let slots = Arc::new(ReclaimSlots::<OwnedValue, 32>::new());
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut producers = alloc::vec::Vec::new();
    for producer in 0..4 {
        let slots = Arc::clone(&slots);
        let dropped = Arc::clone(&dropped);
        producers.push(std::thread::spawn(move || {
            let mut rejected = alloc::vec::Vec::new();
            for index in 0..100 {
                if let Err(owner) = offer(&slots, value(producer * 100 + index, &dropped)) {
                    rejected.push(owner);
                }
            }
            rejected
        }));
    }
    let mut rejected = alloc::vec::Vec::new();
    for producer in producers {
        rejected.extend(producer.join().expect("producer"));
    }
    let mut seen = [false; 400];
    let completed = slots.process(32, |owner| {
        assert!(!seen[owner.identity]);
        seen[owner.identity] = true;
        Ok(())
    });
    for owner in &rejected {
        assert!(!seen[owner.identity]);
        seen[owner.identity] = true;
    }
    assert_eq!(completed + rejected.len(), 400);
    assert!(seen.into_iter().all(|present| present));
    drop(rejected);
    assert_eq!(dropped.load(Ordering::Relaxed), 400);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn admitted_slot_survives_a_full_queue_and_cancellation_releases_capacity() {
    let slots = ReclaimSlots::<OwnedValue, 2>::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let first = slots.reserve().expect("first admission");
    let second = slots.reserve().expect("second admission");
    assert!(slots.reserve().is_none());
    assert_eq!(slots.process(2, |_| Ok(())), 0);
    drop(second);
    assert!(offer(&slots, value(2, &dropped)).is_ok());
    // The earlier reservation publishes without probing despite all slots
    // being occupied. It cannot fail after DMA publication.
    first.publish(value(1, &dropped));
    assert_eq!(slots.process(2, |_| Ok(())), 2);
    assert_eq!(dropped.load(Ordering::Relaxed), 2);
    assert!(slots.reserve().is_some());
}

#[cfg(all(feature = "std", test))]
#[test]
fn interrupted_reclaimer_retains_its_progress_and_owner() {
    let slots = ReclaimSlots::<OwnedValue, 1>::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    assert!(offer(&slots, value(17, &dropped)).is_ok());
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        slots.process(1, |owner| {
            owner.progress = 7;
            panic!("injected reclaimer interruption");
        });
    }));
    assert!(outcome.is_err());
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    assert!(slots.has_pending());
    assert_eq!(
        slots.process(1, |owner| {
            assert_eq!(owner.identity, 17);
            assert_eq!(owner.progress, 7);
            Ok(())
        }),
        1
    );
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}

#[cfg(all(feature = "std", test))]
#[test]
fn panicking_destructor_cannot_republish_a_consumed_value() {
    struct PanickingDrop(Arc<AtomicUsize>);
    impl Drop for PanickingDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
            panic!("injected destructor interruption");
        }
    }
    let slots = ReclaimSlots::<PanickingDrop, 1>::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    slots
        .reserve()
        .expect("admission")
        .publish(PanickingDrop(Arc::clone(&dropped)));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        slots.process(1, |_| Ok(()));
    }));
    assert!(outcome.is_err());
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert!(!slots.has_pending());
    let admission = slots.reserve().expect("consumed slot is available");
    drop(admission);
    drop(slots);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}
