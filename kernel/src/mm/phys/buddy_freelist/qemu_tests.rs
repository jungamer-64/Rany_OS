use super::*;

pub fn migrate_type_fallback_smoke() -> bool {
    let fallbacks = MigrateType::Movable.fallback_order();
    fallbacks.contains(&MigrateType::Reclaimable) && fallbacks.contains(&MigrateType::Unmovable)
}

pub fn frame_to_color_smoke() -> bool {
    frame_to_color(0) == 0
        && frame_to_color(64) == 0
        && frame_to_color(1) == 1
        && frame_to_color(63) == 63
}

pub fn page_flags_smoke() -> bool {
    let mut flags = PageFlags::NONE;
    if flags.contains(PageFlags::FREE) {
        return false;
    }

    flags.insert(PageFlags::FREE);
    if !flags.contains(PageFlags::FREE) {
        return false;
    }

    flags.insert(PageFlags::ZEROED);
    if !flags.contains(PageFlags::FREE) {
        return false;
    }
    if !flags.contains(PageFlags::ZEROED) {
        return false;
    }

    flags.remove(PageFlags::FREE);
    !flags.contains(PageFlags::FREE) && flags.contains(PageFlags::ZEROED)
}

pub fn frames_to_order_smoke() -> bool {
    FreeListBuddyAllocator::frames_to_order(0).is_none()
        && FreeListBuddyAllocator::frames_to_order(1) == Some(0)
        && FreeListBuddyAllocator::frames_to_order(3) == Some(2)
        && FreeListBuddyAllocator::frames_to_order(512) == Some(9)
}

pub fn allocate_from_empty_smoke() -> bool {
    let Ok(loan) = crate::mm::phys::frame_allocator::alloc_contiguous_frames(1) else {
        return false;
    };
    let mut pool = match FreeListBuddyAllocator::from_allocation(loan) {
        Ok(pool) => pool,
        Err(error) => {
            error.allocation.release();
            return false;
        }
    };
    let Ok(child) = pool.allocate(0, MigrateType::Movable) else {
        return false;
    };
    let exhausted = matches!(
        pool.allocate(0, MigrateType::Movable),
        Err(FrameAllocError::Exhausted)
    );
    let returned = pool.deallocate(child).is_ok();
    let reclaimed = match pool.into_allocation() {
        Ok(loan) => {
            loan.release();
            true
        }
        Err(_) => false,
    };
    exhausted && returned && reclaimed
}
