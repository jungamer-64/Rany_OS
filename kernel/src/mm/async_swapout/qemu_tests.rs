use super::*;

const BUFFER_POOL_4K_DEFAULT_CAPACITY: usize = 128;
const BUFFER_POOL_2M_DEFAULT_CAPACITY: usize = 16;

pub fn wave7_buffer_pool_4k_basic_smoke() -> bool {
    buffer_pool_4k_clear();
    buffer_pool_4k_set_capacity(2);

    let (local_hits0, hits0, misses0, occ0) = buffer_pool_4k_extended_stats();
    if local_hits0 != 0 || hits0 != 0 || misses0 != 0 || occ0 != 0 {
        buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    let b1 = buffer_pool_get_4k();
    let b2 = buffer_pool_get_4k();
    if b1.len() != crate::mm::PAGE_SIZE_4K || b2.len() != crate::mm::PAGE_SIZE_4K {
        buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    let (_, _, misses1, _) = buffer_pool_4k_extended_stats();
    if misses1.saturating_sub(misses0) < 2 {
        buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    buffer_pool_put_4k(b1);
    buffer_pool_put_4k(b2);

    let b3 = buffer_pool_get_4k();
    let b4 = buffer_pool_get_4k();
    let (local_hits2, hits2, _, occ2) = buffer_pool_4k_extended_stats();
    let ok = b3.len() == crate::mm::PAGE_SIZE_4K
        && b4.len() == crate::mm::PAGE_SIZE_4K
        && local_hits2.saturating_add(hits2) >= 1
        && occ2 <= 2;

    buffer_pool_put_4k(b3);
    buffer_pool_put_4k(b4);
    buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
    buffer_pool_4k_clear();
    ok
}

pub fn wave7_buffer_pool_2m_basic_smoke() -> bool {
    buffer_pool_2m_clear();
    buffer_pool_2m_set_capacity(2);

    let (hits0, misses0, occ0) = buffer_pool_2m_stats();
    if hits0 != 0 || misses0 != 0 || occ0 != 0 {
        buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    let b1 = buffer_pool_get_2m();
    let b2 = buffer_pool_get_2m();
    if b1.len() != crate::mm::PAGE_SIZE_2M || b2.len() != crate::mm::PAGE_SIZE_2M {
        buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    let (_, misses1, _) = buffer_pool_2m_stats();
    if misses1.saturating_sub(misses0) < 2 {
        buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    buffer_pool_put_2m(b1);
    buffer_pool_put_2m(b2);

    let b3 = buffer_pool_get_2m();
    let b4 = buffer_pool_get_2m();
    let (hits2, _, occ2) = buffer_pool_2m_stats();
    let ok = b3.len() == crate::mm::PAGE_SIZE_2M
        && b4.len() == crate::mm::PAGE_SIZE_2M
        && hits2 >= 1
        && occ2 <= 2;

    buffer_pool_put_2m(b3);
    buffer_pool_put_2m(b4);
    buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
    buffer_pool_2m_clear();
    ok
}
