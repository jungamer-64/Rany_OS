use crate::io::iommu::common::dma::page_table_pool::{
    PageTablePool, TableRetirement, publish_table, take_unlinked_table,
};
use crate::io::iommu::common::tables::{PT_ENTRIES, PageTableScope, SlPte};
use crate::io::iommu::types::PteFormat;

pub(super) fn cached_table_is_zeroed() {
    let pool = PageTablePool::new(1, 4);
    let table = pool.acquire(Some(0)).expect("cache fixture table");
    let physical = table.phys();
    // SAFETY: this unpublished owner exclusively covers all table entries.
    unsafe {
        table
            .ptr()
            .as_ptr()
            .write(SlPte::mapping(physical, true, true))
    };
    pool.release(table);
    let reused = pool.acquire(Some(0)).expect("cached table acquisition");
    assert_eq!(reused.phys(), physical);
    // LOOP_PROOF: mode=bounded; reason=The owned page table contains exactly PT_ENTRIES entries.;
    for index in 0..PT_ENTRIES {
        // SAFETY: the exclusive owner retains the entire unpublished table.
        assert_eq!(unsafe { (*reused.ptr().as_ptr().add(index)).0 }, 0);
    }
    assert_eq!(pool.stats().hits, 1);
    assert_eq!(pool.stats().misses, 1);
}

pub(super) fn retirement_cohort_excludes_later_unlinks() {
    let pool = PageTablePool::new(1, 4);
    let first = pool.acquire(Some(0)).expect("first retirement table");
    let first_physical = first.phys();
    let second = pool.acquire(Some(0)).expect("later retirement table");
    let second_physical = second.phys();
    publish_table(first);
    publish_table(second);
    let mut pending = TableRetirement::default();
    pending.reserve(2).expect("retirement admission");
    // SAFETY: neither retained fixture has a parent or a hardware user.
    pending.push(unsafe { take_unlinked_table(first_physical) }.expect("first owner transfer"));
    // SAFETY: the same detached address is only observed; it cannot mint an owner.
    assert!(unsafe { take_unlinked_table(first_physical) }.is_none());
    let first_cohort = pending.take_pending();
    assert!(!first_cohort.is_empty());
    assert!(!pending.has_pending());
    pending.reserve(1).expect("later retirement admission");
    // SAFETY: the second table was also never linked or hardware-visible.
    pending.push(unsafe { take_unlinked_table(second_physical) }.expect("later owner transfer"));
    assert_eq!(pool.cached_count(0), 0);
    // A failed invalidation retains first_cohort with its completion owner.
    // A later retry can complete it without acquiring the later pending table.
    assert!(pending.has_pending());
    // SAFETY: these unpublished roots have no translation-cache users. This
    // completion consumes only the original detached cohort.
    unsafe { first_cohort.release(&pool) };
    assert_eq!(pool.cached_count(0), 1);
    let first_returned = pool.acquire(Some(0)).expect("first cohort's returned RAM");
    assert_eq!(first_returned.phys(), first_physical);
    assert!(pending.has_pending());
    let later_cohort = pending.take_pending();
    assert!(!later_cohort.is_empty());
    // SAFETY: the later capture also has no hardware or CPU borrowers.
    unsafe { later_cohort.release(&pool) };
    let later_returned = pool.acquire(Some(0)).expect("later cohort's returned RAM");
    assert_eq!(later_returned.phys(), second_physical);
    assert!(!pending.has_pending());
}

pub(super) fn attached_rollback_retains_ram_until_completion() {
    let data = crate::mm::phys::frame_allocator::alloc_frame().expect("rollback fixture data RAM");
    let pool = PageTablePool::new(1, 4);
    let pending = crate::sync::PoisonLock::new(TableRetirement::default());
    let mut parent = SlPte::new();
    let physical;
    {
        let mut scope = PageTableScope::new_with_pool(pool.clone(), Some(0), &pending)
            .expect("rollback table admission");
        physical = scope.phys();
        // SAFETY: the scope exclusively owns all entries. The retained stack
        // parent and data RAM never enter a hardware context or another domain.
        unsafe {
            scope.ptr().write(SlPte::mapping(data.as_u64(), true, true));
            scope.attach_to_parent(&mut parent, 0, PteFormat::Intel, 1);
        }
        assert!(parent.is_present());
    }
    assert!(!parent.is_present());
    assert_eq!(pool.cached_count(0), 0);
    let unrelated = pool
        .acquire(Some(0))
        .expect("table before rollback completion");
    assert_ne!(unrelated.phys(), physical);
    let completed = {
        let mut pending = pending.lock().expect("local retirement owner");
        pending.take_pending()
    };
    // SAFETY: rollback detached the exclusively retained stack parent.
    // Neither the parent nor its data RAM was ever hardware-visible.
    unsafe { completed.release(&pool) };
    let reused = pool
        .acquire(Some(0))
        .expect("table after rollback completion");
    assert_eq!(reused.phys(), physical);
    // LOOP_PROOF: mode=bounded; reason=The retained page contains exactly PT_ENTRIES entries.;
    for index in 0..PT_ENTRIES {
        // SAFETY: the exclusive returned owner covers all table entries.
        assert_eq!(unsafe { (*reused.ptr().as_ptr().add(index)).0 }, 0);
    }
    drop((reused, unrelated));
    data.release();
}
