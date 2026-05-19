use alloc::boxed::Box;
/// Small helper utilities for dealing with raw pointer conversions to Box.
///
/// These helpers wrap unsafe conversions and centralize their use so that
/// call sites are smaller and the safety requirements are documented in one place.
///
/// # Safety
/// - `box_from_raw` requires that `ptr` was returned from `Box::into_raw` and is a
///   valid pointer for type `T`.
///
/// These functions are thin wrappers over the standard-library `unsafe` functions.
#[inline]
pub unsafe fn box_from_raw<T>(ptr: *mut T) -> Box<T> {
    unsafe { Box::from_raw(ptr) }
}
