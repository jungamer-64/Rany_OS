use super::*;

pub fn migrate_type_fallback_smoke() -> bool {
    let fallbacks = MigrateType::Movable.fallback_order();
    fallbacks.contains(&MigrateType::Reclaimable)
        && fallbacks.contains(&MigrateType::Unmovable)
}

pub fn frame_to_color_smoke() -> bool {
    frame_to_color(0) == 0
        && frame_to_color(64) == 0
        && frame_to_color(1) == 1
        && frame_to_color(63) == 63
}

pub fn page_flags_smoke() -> bool {
    let mut flags = PageFlags::NONE;
    if flags.contains(PageFlags::FREE) { return false; }

    flags.insert(PageFlags::FREE);
    if !flags.contains(PageFlags::FREE) { return false; }

    flags.insert(PageFlags::ZEROED);
    if !flags.contains(PageFlags::FREE) { return false; }
    if !flags.contains(PageFlags::ZEROED) { return false; }

    flags.remove(PageFlags::FREE);
    !flags.contains(PageFlags::FREE) && flags.contains(PageFlags::ZEROED)
}

pub fn frames_to_order_smoke() -> bool {
    FreeListBuddyAllocator::frames_to_order(0) == 0
        && FreeListBuddyAllocator::frames_to_order(1) == 0
        && FreeListBuddyAllocator::frames_to_order(2) == 1
        && FreeListBuddyAllocator::frames_to_order(3) == 2
        && FreeListBuddyAllocator::frames_to_order(4) == 2
        && FreeListBuddyAllocator::frames_to_order(5) == 3
        && FreeListBuddyAllocator::frames_to_order(512) == 9
}

pub fn allocate_from_empty_smoke() -> bool {
    let mut allocator = FreeListBuddyAllocator::new();
    let result = allocator.allocate(0, MigrateType::Movable);
    result.is_none()
}
