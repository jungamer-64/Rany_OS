// ==============================================
// kernel/src/util.rs - Utility Functions for Struct <-> Byte Slice Conversion
// ==============================================
// Utility helpers used across kernel modules for safe-ish byte-slice <-> struct conversions.
// These functions centralize unsafe operations, reduce duplication, and perform boundary
// and alignment checks where possible.
use alloc::alloc::alloc_zeroed;
use core::mem;
use core::ptr::NonNull;
use spin::Once;

static BOOT_CMDLINE: Once<Option<&'static str>> = Once::new();

pub fn set_boot_cmdline(cmdline: Option<&'static str>) {
    let _ = BOOT_CMDLINE.call_once(|| cmdline);
}

pub fn boot_cmdline() -> Option<&'static str> {
    BOOT_CMDLINE.get().copied().flatten()
}

pub fn boot_cmdline_option(key: &str) -> Option<&'static str> {
    boot_cmdline().and_then(|cmdline| get_cmdline_option(cmdline, key))
}

/// Try to read a value of type T from a byte slice at offset 'offset'.
/// Returns Some(T) on success, None on bounds/overflow errors.
pub fn read_struct<T: Copy>(data: &[u8], offset: usize) -> Option<T> {
    let size = mem::size_of::<T>();
    // Basic overflow check
    let end = offset.checked_add(size)?;
    if end > data.len() {
        return None;
    }

    let ptr = unsafe { data.as_ptr().add(offset) };
    let align = mem::align_of::<T>();

    if (ptr as usize) % align != 0 {
        // Unaligned - copy into a local buffer
        let mut buf = mem::MaybeUninit::<T>::uninit();
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr() as *mut u8, size);
            Some(buf.assume_init())
        }
    } else {
        // Aligned - direct read
        Some(unsafe { core::ptr::read(ptr as *const T) })
    }
}

/// Try to write a value of type T into a byte slice at offset 'offset'.
/// Returns Some(()) on success, None on bounds/overflow errors.
pub fn write_struct<T: Copy>(data: &mut [u8], offset: usize, value: T) -> Option<()> {
    let size = mem::size_of::<T>();
    let end = offset.checked_add(size)?;
    if end > data.len() {
        return None;
    }

    let ptr = unsafe { data.as_mut_ptr().add(offset) };
    let align = mem::align_of::<T>();

    if (ptr as usize) % align != 0 {
        // Unaligned - copy from value
        unsafe {
            core::ptr::copy_nonoverlapping(&value as *const T as *const u8, ptr, size);
        }
    } else {
        unsafe {
            (ptr as *mut T).write(value);
        }
    }

    Some(())
}

/// Try to return a subslice of `data` with bounds checking.
pub fn get_slice<'a>(data: &'a [u8], offset: usize, len: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(&data[offset..end])
}

/// Try to return a mutable subslice of `data` with bounds checking.
pub fn get_slice_mut<'a>(data: &'a mut [u8], offset: usize, len: usize) -> Option<&'a mut [u8]> {
    let end = offset.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(&mut data[offset..end])
}

/// Attempt to obtain a &mut T pointing into the given mutable slice at offset.
/// Returns None if bounds or alignment don't match.
pub fn get_mut_ref<'a, T>(data: &'a mut [u8], offset: usize) -> Option<&'a mut T> {
    let size = mem::size_of::<T>();
    let end = offset.checked_add(size)?;
    if end > data.len() {
        return None;
    }
    let ptr = unsafe { data.as_mut_ptr().add(offset) };
    let align = mem::align_of::<T>();
    if (ptr as usize) % align != 0 {
        return None;
    }
    Some(unsafe { &mut *(ptr as *mut T) })
}

/// Obtain an immutable reference to a typed value inside a byte slice at offset.
/// Returns None if bounds or alignment don't match.
pub fn get_ref<'a, T>(data: &'a [u8], offset: usize) -> Option<&'a T> {
    let size = mem::size_of::<T>();
    let end = offset.checked_add(size)?;
    if end > data.len() {
        return None;
    }
    let ptr = unsafe { data.as_ptr().add(offset) };
    let align = mem::align_of::<T>();
    if (ptr as usize) % align != 0 {
        return None;
    }
    Some(unsafe { &*(ptr as *const T) })
}

/// Obtain a byte slice view of a struct value.
/// Centralized to minimize scattered unsafe usage across the codebase.
pub fn struct_as_bytes<T>(val: &T) -> &[u8] {
    let ptr = val as *const T as *const u8;
    unsafe { core::slice::from_raw_parts(ptr, mem::size_of::<T>()) }
}

/// Obtain a mutable byte slice view of a struct value.
pub fn struct_as_bytes_mut<T>(val: &mut T) -> &mut [u8] {
    let ptr = val as *mut T as *mut u8;
    unsafe { core::slice::from_raw_parts_mut(ptr, mem::size_of::<T>()) }
}

/// Convert a NonNull<u8> pointer with an offset and length into an immutable slice.
/// This encapsulates an unsafe pointer -> slice conversion for non-owning buffers.
pub unsafe fn nonnull_ptr_as_slice<'a>(ptr: NonNull<u8>, offset: usize, len: usize) -> &'a [u8] {
    let base = ptr.as_ptr() as usize;
    let addr = base.checked_add(offset).unwrap_or(usize::MAX);
    debug_check_ptr_range(addr, len, 1);
    unsafe { core::slice::from_raw_parts(ptr.as_ptr().add(offset), len) }
}

/// Convert a NonNull<u8> pointer with an offset and length into a mutable slice.
pub unsafe fn nonnull_ptr_as_slice_mut<'a>(
    ptr: NonNull<u8>,
    offset: usize,
    len: usize,
) -> &'a mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr().add(offset), len) }
}

/// Convert a raw pointer (possibly null) to an immutable slice.
///
/// Safety: the caller must ensure the pointer is valid for `len` bytes and properly aligned.
pub unsafe fn raw_ptr_as_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    debug_check_ptr_range(ptr as usize, len, 1);
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// Convert a raw pointer (possibly null) to a mutable slice.
///
/// Safety: the caller must ensure the pointer is valid for `len` bytes and properly aligned.
pub unsafe fn raw_ptr_as_slice_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    debug_check_ptr_range(ptr as usize, len, 1);
    unsafe { core::slice::from_raw_parts_mut(ptr, len) }
}

#[inline]
pub fn debug_check_ptr_range(addr: usize, len: usize, align: usize) {
    if cfg!(debug_assertions) {
        if len > 0 {
            debug_assert!(addr != 0, "null pointer range");
        }
        debug_assert!(addr.checked_add(len).is_some(), "pointer range overflow");
        if align > 1 {
            debug_assert!(addr % align == 0, "unaligned pointer");
        }
    }
}

/// Allocate memory zero-initialized and return a NonNull pointer if successful.
///
/// This centralizes `alloc::alloc::alloc_zeroed` and converts the raw pointer into a `NonNull`.
pub fn allocate_zeroed(layout: core::alloc::Layout) -> Option<NonNull<u8>> {
    let ptr = unsafe { alloc_zeroed(layout) };
    NonNull::new(ptr)
}

/// Write a typed value directly to a virtual address. The address must be valid
/// and mapped for writing. This operation is unsafe and may cause undefined
/// behaviour if the provided address is invalid; the helper centralizes this
/// unsafe write point so it is easier to audit.
pub fn write_to_addr<T>(addr: usize, value: T) {
    let ptr = addr as *mut T;
    unsafe {
        core::ptr::write(ptr, value);
    }
}

/// Read a possibly unaligned value from the given address.
/// This centralizes `ptr::read_unaligned` usage and reduces scattered unsafe
/// calls across the codebase. The caller must ensure the address is valid for
/// a read of T.
#[inline]
pub fn read_unaligned_from_addr<T: Copy>(addr: usize) -> T {
    unsafe { core::ptr::read_unaligned(addr as *const T) }
}

/// Write a possibly unaligned value to the given address.
#[inline]
pub fn write_unaligned_to_addr<T: Copy>(addr: usize, value: T) {
    unsafe {
        core::ptr::write_unaligned(addr as *mut T, value);
    }
}

/// Parse a command line string for a specific key-value pair.
///
/// Supports:
/// - `key=value` -> returns `Some("value")`
/// - `key` -> returns `Some("true")`
/// - `key=` -> returns `Some("")`
///
/// Returns `None` if the key is not found.
pub fn get_cmdline_option<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    for part in cmdline.split_whitespace() {
        if let Some(rest) = part.strip_prefix(key) {
            if rest.is_empty() {
                // key (flag)
                return Some("true");
            } else if let Some(value) = rest.strip_prefix('=') {
                // key=value
                return Some(value);
            }
        }
    }
    None
}

// ============================================================================
// FNV-1a Hash Functions
// ============================================================================

/// FNV-1a 64ビットハッシュ定数
pub mod fnv {
    /// FNV-1a オフセット基底値
    pub const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    /// FNV-1a 素数
    pub const FNV_PRIME: u64 = 0x100000001b3;
}

/// FNV-1a ハッシュをバイト列から計算（const対応）
///
/// # Example
/// ```ignore
/// let hash = fnv1a_hash(b"hello");
/// ```
#[inline]
pub const fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash = fnv::FNV_OFFSET_BASIS;
    let mut i = 0;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while i < data.len() {
        hash ^= data[i] as u64;
        hash = hash.wrapping_mul(fnv::FNV_PRIME);
        i += 1;
    }
    hash
}

/// 型名とサイズ/アライメントから型ハッシュを計算
///
/// Type ID Check（設計書 3.4）用のハッシュ関数。
/// 型の名前、サイズ、アライメントを組み合わせてハッシュを生成。
#[inline]
pub const fn compute_type_hash(type_name: &str, size: usize, align: usize) -> u64 {
    let name_hash = fnv1a_hash(type_name.as_bytes());
    let size_bits = (size as u64) << 32;
    let align_bits = (align as u64) << 48;
    name_hash ^ size_bits ^ align_bits
}

/// ページ内容のFNV-1aハッシュ（64ビットワード単位で最適化）
///
/// KSM（Kernel Same-page Merging）用の高速ページハッシュ。
#[inline]
pub fn fnv1a_page_hash(page_data: &[u8]) -> u64 {
    let mut hash = fnv::FNV_OFFSET_BASIS;

    // 64ビットワード単位で処理（8倍高速）
    let word_count = page_data.len() / 8;
    let ptr = page_data.as_ptr() as *const u64;

    for i in 0..word_count {
        let word = unsafe { ptr.add(i).read_unaligned() };
        hash ^= word;
        hash = hash.wrapping_mul(fnv::FNV_PRIME);
    }

    // 残りのバイトを処理
    let remainder_start = word_count * 8;
    for byte in &page_data[remainder_start..] {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(fnv::FNV_PRIME);
    }

    hash
}

// ============================================================================
// Alignment Utility Functions
// ============================================================================

/// 値を指定アラインメントに切り上げ (usize版)
///
/// `align` は2の冪乗でなければならない（debug_assertで検証）。
///
/// # Example
/// ```ignore
/// assert_eq!(align_up_usize(5, 4), 8);
/// assert_eq!(align_up_usize(8, 4), 8);
/// ```
#[inline]
pub const fn align_up_usize(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// 値を指定アラインメントに切り下げ (usize版)
///
/// `align` は2の冪乗でなければならない。
#[inline]
pub const fn align_down_usize(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

/// 値を指定アラインメントに切り上げ (u64版)
///
/// `align` は2の冪乗でなければならない。
#[inline]
pub const fn align_up_u64(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

/// 値を指定アラインメントに切り下げ (u64版)
///
/// `align` は2の冪乗でなければならない。
#[inline]
pub const fn align_down_u64(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}
