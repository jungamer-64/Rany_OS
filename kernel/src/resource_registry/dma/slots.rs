//! Fixed metadata storage for admitted DMA owners. Occupancy and generation
//! are one state, and failed admission returns the unaccepted owner unchanged.
//! The enclosing registry serializes every lookup, admission and removal.

use core::num::NonZeroU32;
use kernel_api::dma::DmaLeaseId;

enum Slot<T> {
    Vacant { next_generation: NonZeroU32 },
    Occupied { generation: NonZeroU32, owner: T },
    Exhausted,
}

pub(super) struct LeaseSlots<T, const N: usize> {
    slots: [Slot<T>; N],
}

/// Each physical metadata slot is visited once, even if another operation
/// removes or reuses a previously visited generation between registry borrows.
pub(super) struct ScanCursor {
    next: usize,
}
impl ScanCursor {
    pub(super) const fn new() -> Self {
        Self { next: 0 }
    }
}

impl<T, const N: usize> LeaseSlots<T, N> {
    pub(super) const fn new() -> Self {
        // The stable ABI represents a nonzero one-based slot in u32. This is
        // a backing-storage configuration assertion, not a request failure.
        assert!(N <= u32::MAX as usize);
        Self {
            slots: [const {
                Slot::Vacant {
                    next_generation: NonZeroU32::MIN,
                }
            }; N],
        }
    }

    fn identity(index: usize, generation: NonZeroU32) -> DmaLeaseId {
        let slot =
            u32::try_from(index + 1).expect("configured one-based metadata slot fits the ABI");
        DmaLeaseId::from_parts(slot, generation.get()).expect("slot and generation are nonzero")
    }

    fn index(identity: DmaLeaseId) -> Option<usize> {
        usize::try_from(identity.slot()).ok()?.checked_sub(1)
    }

    pub(super) fn insert(&mut self, owner: T) -> Result<DmaLeaseId, T> {
        let Some((index, generation)) =
            self.slots
                .iter()
                .enumerate()
                .find_map(|(index, slot)| match slot {
                    Slot::Vacant { next_generation } => Some((index, *next_generation)),
                    Slot::Occupied { .. } | Slot::Exhausted => None,
                })
        else {
            return Err(owner);
        };
        self.slots[index] = Slot::Occupied { generation, owner };
        Ok(Self::identity(index, generation))
    }

    pub(super) fn get(&self, identity: DmaLeaseId) -> Option<&T> {
        match self.slots.get(Self::index(identity)?)? {
            Slot::Occupied { generation, owner } if generation.get() == identity.generation() => {
                Some(owner)
            }
            _ => None,
        }
    }

    pub(super) fn get_mut(&mut self, identity: DmaLeaseId) -> Option<&mut T> {
        match self.slots.get_mut(Self::index(identity)?)? {
            Slot::Occupied { generation, owner } if generation.get() == identity.generation() => {
                Some(owner)
            }
            _ => None,
        }
    }

    pub(super) fn remove(&mut self, identity: DmaLeaseId) -> Option<T> {
        let slot = self.slots.get_mut(Self::index(identity)?)?;
        let Slot::Occupied { generation, .. } = slot else {
            return None;
        };
        if generation.get() != identity.generation() {
            return None;
        }
        // Exhausted ABI generations permanently retire this slot. Reuse may
        // never turn a stale capability into authority over another allocation.
        let next = generation
            .get()
            .checked_add(1)
            .and_then(NonZeroU32::new)
            .map_or(Slot::Exhausted, |next_generation| Slot::Vacant {
                next_generation,
            });
        let Slot::Occupied { owner, .. } = core::mem::replace(slot, next) else {
            unreachable!("the exclusively checked slot remained occupied")
        };
        Some(owner)
    }

    pub(super) fn next(&self, cursor: &mut ScanCursor) -> Option<(DmaLeaseId, &T)> {
        for index in cursor.next..N {
            cursor.next = index + 1;
            if let Slot::Occupied { generation, owner } = &self.slots[index] {
                return Some((Self::identity(index, *generation), owner));
            }
        }
        cursor.next = N;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct Owner {
        value: usize,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn owner(value: usize, dropped: &Arc<AtomicUsize>) -> Owner {
        Owner {
            value,
            dropped: Arc::clone(dropped),
        }
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn exhausted_admission_returns_the_exact_owner_and_reuse_revokes_stale_ids() {
        let mut slots = LeaseSlots::<Owner, 2>::new();
        let dropped = Arc::new(AtomicUsize::new(0));
        let first = slots
            .insert(owner(11, &dropped))
            .unwrap_or_else(|_| panic!("fixture admission"));
        let second = slots
            .insert(owner(22, &dropped))
            .unwrap_or_else(|_| panic!("fixture admission"));
        let rejected = slots
            .insert(owner(33, &dropped))
            .err()
            .expect("full storage rejects admission");
        assert_eq!(rejected.value, 33);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert_eq!(slots.get(first).unwrap().value, 11);
        let returned = slots
            .remove(first)
            .expect("retirement returns the first owner");
        assert_eq!(returned.value, 11);
        let reused = slots
            .insert(rejected)
            .unwrap_or_else(|_| panic!("retry admission"));
        assert_eq!(first.slot(), reused.slot());
        assert_ne!(first.generation(), reused.generation());
        assert!(slots.get(first).is_none());
        assert!(slots.get_mut(first).is_none());
        assert!(slots.remove(first).is_none());
        assert_eq!(slots.get(second).unwrap().value, 22);
        assert_eq!(slots.get(reused).unwrap().value, 33);
        drop(returned);
        drop(slots);
        assert_eq!(dropped.load(Ordering::Relaxed), 3);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn exhausted_generation_cannot_wrap_and_a_scan_does_not_revisit_reused_slots() {
        let mut slots = LeaseSlots::<usize, 2>::new();
        slots.slots[0] = Slot::Occupied {
            generation: NonZeroU32::MAX,
            owner: 7,
        };
        let final_id = LeaseSlots::<usize, 2>::identity(0, NonZeroU32::MAX);
        assert_eq!(slots.remove(final_id), Some(7));
        assert!(slots.get(final_id).is_none());
        let second = slots.insert(8).expect("remaining slot admission");
        assert_ne!(second.slot(), final_id.slot());
        assert_eq!(slots.insert(9), Err(9));
        let mut cursor = ScanCursor::new();
        assert_eq!(slots.next(&mut cursor), Some((second, &8)));
        assert_eq!(slots.remove(second), Some(8));
        let reused = slots.insert(9).expect("reuse remaining slot");
        assert!(slots.next(&mut cursor).is_none());
        assert_eq!(slots.get(reused), Some(&9));
        let foreign = DmaLeaseId::from_parts(3, 1).unwrap();
        assert!(slots.get(foreign).is_none());
        assert!(slots.get_mut(foreign).is_none());
        assert!(slots.remove(foreign).is_none());
        assert_eq!(LeaseSlots::<usize, 0>::new().insert(10), Err(10));
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn mixed_admission_and_retirement_match_an_independent_live_owner_model() {
        let mut slots = LeaseSlots::<usize, 7>::new();
        let mut live = alloc::vec::Vec::new();
        let mut history = alloc::vec::Vec::new();
        let mut random = 91_u32;
        for value in 0..2000 {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            if random & 3 == 0 && !live.is_empty() {
                let index = random as usize % live.len();
                let (identity, expected) = live.swap_remove(index);
                assert_eq!(slots.remove(identity), Some(expected));
                history.push(identity);
            } else {
                match slots.insert(value) {
                    Ok(identity) => {
                        assert!(live.len() < 7);
                        assert!(live.iter().all(
                            |&(other, _): &(DmaLeaseId, usize)| other.slot() != identity.slot()
                        ));
                        live.push((identity, value));
                    }
                    Err(returned) => {
                        assert_eq!(returned, value);
                        assert_eq!(live.len(), 7);
                    }
                }
            }
            for &(identity, expected) in &live {
                assert_eq!(slots.get(identity), Some(&expected));
            }
            for &retired in &history {
                assert!(slots.get(retired).is_none());
            }
            let mut cursor = ScanCursor::new();
            let mut observed = 0;
            // LOOP_PROOF: mode=condition; reason=The cursor visits each finite metadata slot once and stops at the configured capacity.;
            while let Some((identity, owner)) = slots.next(&mut cursor) {
                assert!(live.contains(&(identity, *owner)));
                observed += 1;
            }
            assert_eq!(observed, live.len());
        }
    }
}
