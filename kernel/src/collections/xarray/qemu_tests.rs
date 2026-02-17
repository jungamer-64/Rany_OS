use super::*;

pub fn xarray_empty_smoke() -> bool {
    let xa: XArray<u32> = XArray::new();
    xa.is_empty()
        && xa.len() == 0
        && xa.load(0).is_none()
        && xa.load(100).is_none()
}

pub fn xarray_store_load_smoke() -> bool {
    let mut xa: XArray<u32> = XArray::new();

    if xa.store(0, 42) != None { return false; }
    if xa.len() != 1 { return false; }
    if xa.load(0) != Some(&42) { return false; }

    // 上書き
    if xa.store(0, 100) != Some(42) { return false; }
    xa.len() == 1 && xa.load(0) == Some(&100)
}

pub fn xarray_sparse_smoke() -> bool {
    let mut xa: XArray<u32> = XArray::new();

    xa.store(0, 1);
    xa.store(100, 2);
    xa.store(10000, 3);

    xa.len() == 3
        && xa.load(0) == Some(&1)
        && xa.load(50).is_none()
        && xa.load(100) == Some(&2)
        && xa.load(5000).is_none()
        && xa.load(10000) == Some(&3)
}

pub fn xarray_erase_smoke() -> bool {
    let mut xa: XArray<u32> = XArray::new();

    xa.store(10, 42);
    if xa.len() != 1 { return false; }

    if xa.erase(10) != Some(42) { return false; }
    if xa.len() != 0 { return false; }
    if xa.load(10).is_some() { return false; }

    xa.erase(10).is_none()
}

pub fn xarray_large_indices_smoke() -> bool {
    let mut xa: XArray<u32> = XArray::new();

    let indices: [usize; 7] = [0, 63, 64, 4095, 4096, 262143, 262144];

    for (i, &idx) in indices.iter().enumerate() {
        xa.store(idx, i as u32);
    }

    if xa.len() != indices.len() { return false; }

    for (i, &idx) in indices.iter().enumerate() {
        if xa.load(idx) != Some(&(i as u32)) { return false; }
    }
    true
}

pub fn xarray_iter_smoke() -> bool {
    let mut xa: XArray<u32> = XArray::new();

    xa.store(5, 50);
    xa.store(10, 100);
    xa.store(15, 150);

    let collected: alloc::vec::Vec<(usize, u32)> = xa.iter().map(|(i, v)| (i, *v)).collect();
    collected == alloc::vec![(5, 50), (10, 100), (15, 150)]
}

pub fn xarray_load_mut_smoke() -> bool {
    let mut xa: XArray<u32> = XArray::new();

    xa.store(0, 100);

    if let Some(v) = xa.load_mut(0) {
        *v = 200;
    }

    xa.load(0) == Some(&200)
}

pub fn xarray_marks_smoke() -> bool {
    let mut xa: XArray<u32> = XArray::new();

    xa.store(0, 100);
    xa.store(1, 200);

    if xa.has_mark(0, XA_MARK_0) { return false; }
    if xa.has_mark(1, XA_MARK_1) { return false; }

    if !xa.set_mark(0, XA_MARK_0) { return false; }
    if !xa.set_mark(1, XA_MARK_1) { return false; }

    if !xa.has_mark(0, XA_MARK_0) { return false; }
    if !xa.has_mark(1, XA_MARK_1) { return false; }
    if xa.has_mark(0, XA_MARK_1) { return false; }

    if !xa.clear_mark(0, XA_MARK_0) { return false; }
    !xa.has_mark(0, XA_MARK_0)
}

pub fn xarray_usize_basic_smoke() -> bool {
    let mut xa = XArrayUsize::new();

    if !xa.is_empty() { return false; }

    xa.store(0, 42);
    xa.store(10, 100);

    if xa.len() != 2 { return false; }
    if xa.load(0) != Some(42) { return false; }
    if xa.load(10) != Some(100) { return false; }
    if xa.load(5).is_some() { return false; }

    if xa.erase(0) != Some(42) { return false; }
    if xa.load(0).is_some() { return false; }
    xa.len() == 1
}

pub fn xarray_usize_marks_smoke() -> bool {
    let mut xa = XArrayUsize::new();

    xa.store(0, 100);

    if xa.has_mark(0, XA_MARK_0) { return false; }
    xa.set_mark(0, XA_MARK_0);
    if !xa.has_mark(0, XA_MARK_0) { return false; }

    xa.clear_mark(0, XA_MARK_0);
    !xa.has_mark(0, XA_MARK_0)
}

pub fn xarray_usize_zero_value_smoke() -> bool {
    let mut xa = XArrayUsize::new();

    xa.store(0, 0);
    xa.load(0) == Some(0) && xa.len() == 1
}
