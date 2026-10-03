//! Value validity at typed zero-fill and device-write boundaries. Storage
//! ownership alone does not make arbitrary bytes a valid Rust value.

/// A value whose all-zero representation is valid, including nested fields.
/// Copy values have no destruction obligation for an implicit zero value.
///
/// # Safety
/// Every initialized all-zero instance must satisfy Rust validity and the
/// type's own invariants. References and nonzero-constrained values do not
/// qualify. Padding may exist; zero-fill initializes it without reading it.
pub unsafe trait Zeroable: Copy {}

/// An element that may be read or overwritten as bytes by a device.
///
/// # Safety
/// Every bit pattern must be valid, with no padding, references, pointers,
/// ownership capabilities or address-dependent invariants. Every byte of an
/// ordinary initialized value must be initialized. Device writes cannot create
/// a destructor obligation or invalidate another object. Translation completion
/// and CPU/device access exclusion remain the mapping owner's responsibility.
pub unsafe trait DmaElement: Zeroable + Send + Sync + 'static {}

macro_rules! byte_values {
    ($($ty:ty),+ $(,)?) => {$ (
        // SAFETY: scalar integers and IEEE floating-point values have no padding;
        // all bit patterns, including zero and NaNs, are valid Rust values.
        unsafe impl Zeroable for $ty {}
        // SAFETY: these scalars carry no pointer, ownership or address invariant.
        unsafe impl DmaElement for $ty {}
    )+};
}
byte_values!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);

// SAFETY: zero represents false and the NUL Unicode scalar respectively.
unsafe impl Zeroable for bool {}
// SAFETY: U+0000 is a valid char. Other bit patterns need not be valid.
unsafe impl Zeroable for char {}

// SAFETY: zeroing an array zeroes every element, whose validity is guaranteed.
unsafe impl<T: Zeroable, const N: usize> Zeroable for [T; N] {}
// SAFETY: arrays introduce no padding between elements and inherit element
// validity, initialized bytes and absence of pointer/ownership invariants.
unsafe impl<T: DmaElement, const N: usize> DmaElement for [T; N] {}
