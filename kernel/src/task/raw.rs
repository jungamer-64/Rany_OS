use alloc::sync::Arc;
use alloc::boxed::Box;

/// Small helper utilities for dealing with raw pointer conversions to Arc/Box.
///
/// These helpers wrap unsafe conversions and centralize their use so that
/// call sites are smaller and the safety requirements are documented in one place.
///
/// # Safety
/// - `arc_from_raw` requires that `ptr` was returned from `Arc::into_raw` and is a
///   valid pointer for type `T`.
/// - `box_from_raw` requires that `ptr` was returned from `Box::into_raw` and is a
///   valid pointer for type `T`.
///
/// These functions are thin wrappers over the standard-library `unsafe` functions.
#[inline]
pub unsafe fn arc_from_raw<T>(ptr: *const T) -> Arc<T> {
    Arc::from_raw(ptr)
}

#[inline]
pub unsafe fn box_from_raw<T>(ptr: *mut T) -> Box<T> {
    Box::from_raw(ptr)
}
