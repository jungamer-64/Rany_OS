// ============================================================================
// kernel_api/src/ipc.rs - Public IPC metadata and zero-copy foundations
// ============================================================================

use alloc::vec::Vec;
use core::alloc::Layout;
use core::fmt;
use core::mem::{self, ManuallyDrop};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};

use crate::abi::driver::{AbiRRefDropFn, AbiRRefRaw};
use crate::service::kernel;
use crate::{KapiError, KapiResult};

pub use crate::types_impl::ChannelHandle;

/// Stable identifier for a protection domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DomainId(u64);

impl DomainId {
    pub const KERNEL: Self = Self(0);

    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Hash value for ABI/type compatibility checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TypeHash(u64);

impl TypeHash {
    pub const fn new(hash: u64) -> Self {
        Self(hash)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub const fn is_compatible(self, other: TypeHash) -> bool {
        self.0 == other.0
    }
}

pub trait TypeIdHash {
    const TYPE_HASH: TypeHash;

    fn type_name() -> &'static str {
        core::any::type_name::<Self>()
    }

    fn type_hash(&self) -> TypeHash {
        Self::TYPE_HASH
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeHashError {
    HashMismatch {
        expected: TypeHash,
        actual: TypeHash,
    },
    VersionMismatch,
}

impl fmt::Display for TypeHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "Type hash mismatch: expected 0x{:016X}, got 0x{:016X}",
                    expected.value(),
                    actual.value()
                )
            }
            Self::VersionMismatch => write!(f, "Type version mismatch"),
        }
    }
}

pub const fn fnv1a_hash(bytes: &[u8]) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325u64;
    let mut index = 0;
    while index < bytes.len() {
        state ^= bytes[index] as u64;
        state = state.wrapping_mul(0x0100_0000_01b3);
        index += 1;
    }
    state
}

const fn mix_u64(value: u64) -> u64 {
    value.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(13)
}

pub const fn compute_simple_type_hash(type_name: &str, size: usize, align: usize) -> TypeHash {
    let name_hash = fnv1a_hash(type_name.as_bytes());
    TypeHash::new(name_hash ^ mix_u64(size as u64) ^ mix_u64((align as u64) << 1))
}

/// # Errors
///
/// Returns an error if the supplied representation violates the required invariants.
pub fn verify_type_hash<T: TypeIdHash + ?Sized>(expected: TypeHash) -> Result<(), TypeHashError> {
    let actual = T::TYPE_HASH;
    if expected.is_compatible(actual) {
        Ok(())
    } else {
        Err(TypeHashError::HashMismatch { expected, actual })
    }
}

impl TypeIdHash for u8 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("u8", 1, 1);
}
impl TypeIdHash for u16 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("u16", 2, 2);
}
impl TypeIdHash for u32 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("u32", 4, 4);
}
impl TypeIdHash for u64 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("u64", 8, 8);
}
impl TypeIdHash for i8 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("i8", 1, 1);
}
impl TypeIdHash for i16 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("i16", 2, 2);
}
impl TypeIdHash for i32 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("i32", 4, 4);
}
impl TypeIdHash for i64 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("i64", 8, 8);
}
impl TypeIdHash for bool {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("bool", 1, 1);
}
impl<T: TypeIdHash, const N: usize> TypeIdHash for [T; N] {
    const TYPE_HASH: TypeHash =
        TypeHash::new(T::TYPE_HASH.value() ^ fnv1a_hash(b"array") ^ (N as u64));
}
impl<T: TypeIdHash> TypeIdHash for [T] {
    const TYPE_HASH: TypeHash = TypeHash::new(T::TYPE_HASH.value() ^ fnv1a_hash(b"slice"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawPartsError {
    TypeMismatch,
    SizeMismatch,
    NullPointer,
    MissingDropFn,
}

#[derive(Debug)]
pub enum RRefError {
    Kernel(KapiError),
    RawParts(RawPartsError),
    TypeHash(TypeHashError),
}

impl From<KapiError> for RRefError {
    fn from(value: KapiError) -> Self {
        Self::Kernel(value)
    }
}

impl From<RawPartsError> for RRefError {
    fn from(value: RawPartsError) -> Self {
        Self::RawParts(value)
    }
}

impl From<TypeHashError> for RRefError {
    fn from(value: TypeHashError) -> Self {
        Self::TypeHash(value)
    }
}

/// Type-erased ownership record for Exchange Heap / IPC plumbing.
#[derive(Debug, Clone, Copy)]
pub struct RRefRawParts {
    ptr: NonNull<u8>,
    owner: DomainId,
    meta: usize,
    size: usize,
    align: usize,
    type_hash: TypeHash,
    drop_fn: AbiRRefDropFn,
}

unsafe impl Send for RRefRawParts {}
unsafe impl Sync for RRefRawParts {}

impl RRefRawParts {
    pub const unsafe fn from_components(
        ptr: NonNull<u8>,
        owner: DomainId,
        meta: usize,
        size: usize,
        align: usize,
        type_hash: TypeHash,
        drop_fn: AbiRRefDropFn,
    ) -> Self {
        Self {
            ptr,
            owner,
            meta,
            size,
            align,
            type_hash,
            drop_fn,
        }
    }

    pub fn owner(&self) -> DomainId {
        self.owner
    }

    pub fn type_hash(&self) -> TypeHash {
        self.type_hash
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn align(&self) -> usize {
        self.align
    }

    pub fn metadata(&self) -> usize {
        self.meta
    }

    pub fn into_components(
        self,
    ) -> (
        NonNull<u8>,
        DomainId,
        usize,
        usize,
        usize,
        TypeHash,
        AbiRRefDropFn,
    ) {
        (
            self.ptr,
            self.owner,
            self.meta,
            self.size,
            self.align,
            self.type_hash,
            self.drop_fn,
        )
    }

    pub fn into_abi(self) -> AbiRRefRaw {
        AbiRRefRaw {
            ptr: self.ptr.as_ptr(),
            owner: self.owner.as_u64(),
            meta: self.meta,
            size: self.size,
            align: self.align,
            type_hash: self.type_hash.value(),
            drop_fn: Some(self.drop_fn),
            reserved: [0; 2],
        }
    }

    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
    pub fn from_abi(raw: AbiRRefRaw) -> Result<Self, RawPartsError> {
        let ptr = NonNull::new(raw.ptr).ok_or(RawPartsError::NullPointer)?;
        let drop_fn = raw.drop_fn.ok_or(RawPartsError::MissingDropFn)?;
        Ok(Self {
            ptr,
            owner: DomainId::new(raw.owner),
            meta: raw.meta,
            size: raw.size,
            align: raw.align.max(1),
            type_hash: TypeHash::new(raw.type_hash),
            drop_fn,
        })
    }

    pub unsafe fn drop_erased(self) {
        unsafe {
            (self.drop_fn)(
                self.ptr.as_ptr(),
                self.owner.as_u64(),
                self.meta,
                self.size,
                self.align,
            );
        }
    }
}

pub struct RRef<T: ?Sized> {
    data: NonNull<u8>,
    ptr: NonNull<T>,
    owner: DomainId,
    meta: usize,
    size: usize,
    align: usize,
    type_hash: TypeHash,
    drop_fn: AbiRRefDropFn,
}

unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}

impl<T: ?Sized> RRef<T> {
    pub fn owner(&self) -> DomainId {
        self.owner
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or cannot be completed.
    pub fn move_to(mut self, new_owner: DomainId) -> Result<Self, RRefError> {
        kernel::instance().exchange_transfer_raw(self.data, self.owner, new_owner)?;
        self.owner = new_owner;
        Ok(self)
    }

    pub fn into_raw_parts(self) -> RRefRawParts {
        let this = ManuallyDrop::new(self);
        unsafe {
            RRefRawParts::from_components(
                this.data,
                this.owner,
                this.meta,
                this.size,
                this.align,
                this.type_hash,
                this.drop_fn,
            )
        }
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the receiver cannot accept the operation.
    pub fn send(self, channel: ChannelHandle) -> Result<(), RRefError> {
        let raw = self.into_raw_parts();
        kernel::instance().ipc_send_raw(channel, raw.into_abi())?;
        Ok(())
    }
}

impl<T: ?Sized> Drop for RRef<T> {
    fn drop(&mut self) {
        unsafe {
            (self.drop_fn)(
                self.data.as_ptr(),
                self.owner.as_u64(),
                self.meta,
                self.size,
                self.align,
            );
        }
    }
}

impl<T: ?Sized> Deref for RRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for RRef<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

fn alloc_exchange(size: usize, align: usize) -> Result<(NonNull<u8>, DomainId), RRefError> {
    Ok(kernel::instance().exchange_alloc_raw(size, align)?)
}

unsafe extern "C" fn drop_sized<T>(
    ptr: *mut u8,
    owner: u64,
    _meta: usize,
    size: usize,
    align: usize,
) {
    unsafe {
        ptr::drop_in_place(ptr.cast::<T>());
        if let Some(ptr) = NonNull::new(ptr) {
            let _ = kernel::instance().exchange_dealloc_raw(ptr, DomainId::new(owner), size, align);
        }
    }
}

unsafe extern "C" fn drop_slice<T>(
    ptr: *mut u8,
    owner: u64,
    len: usize,
    size: usize,
    align: usize,
) {
    unsafe {
        ptr::drop_in_place(ptr::slice_from_raw_parts_mut(ptr.cast::<T>(), len));
        if let Some(ptr) = NonNull::new(ptr) {
            let _ = kernel::instance().exchange_dealloc_raw(ptr, DomainId::new(owner), size, align);
        }
    }
}

impl<T: TypeIdHash + 'static> RRef<T> {
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(value: T) -> Result<Self, RRefError> {
        let layout = Layout::new::<T>();
        let (data, owner) = alloc_exchange(layout.size(), layout.align())?;
        unsafe {
            data.cast::<T>().as_ptr().write(value);
        }
        Ok(Self {
            data,
            ptr: data.cast(),
            owner,
            meta: 0,
            size: layout.size(),
            align: layout.align(),
            type_hash: T::TYPE_HASH,
            drop_fn: drop_sized::<T>,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
    pub unsafe fn from_raw_parts(raw: RRefRawParts) -> Result<Self, RRefError> {
        verify_type_hash::<T>(raw.type_hash())?;
        if raw.size() != mem::size_of::<T>() || raw.align() != mem::align_of::<T>() {
            return Err(RawPartsError::SizeMismatch.into());
        }
        let (data, owner, meta, size, align, type_hash, drop_fn) = raw.into_components();
        if meta != 0 {
            return Err(RawPartsError::SizeMismatch.into());
        }
        Ok(Self {
            data,
            ptr: data.cast(),
            owner,
            meta,
            size,
            align,
            type_hash,
            drop_fn,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required state cannot be read.
    pub fn recv(channel: ChannelHandle) -> Result<Self, RRefError> {
        let raw = kernel::instance().ipc_recv_raw(channel)?;
        let parts = RRefRawParts::from_abi(raw)?;
        match unsafe { Self::from_raw_parts(parts) } {
            Ok(value) => Ok(value),
            Err(err) => {
                unsafe { parts.drop_erased() };
                Err(err)
            }
        }
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    pub fn into_inner(self) -> Result<T, RRefError> {
        let this = ManuallyDrop::new(self);
        let value = unsafe { this.ptr.as_ptr().read() };
        kernel::instance().exchange_dealloc_raw(this.data, this.owner, this.size, this.align)?;
        Ok(value)
    }
}

impl<T: TypeIdHash + Copy + 'static> RRef<[T]> {
    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
    pub fn from_slice_copy(values: &[T]) -> Result<Self, RRefError> {
        let size = mem::size_of_val(values);
        let align = mem::align_of::<T>();
        let (data, owner) = alloc_exchange(size.max(1), align.max(1))?;
        if !values.is_empty() {
            unsafe {
                ptr::copy_nonoverlapping(values.as_ptr(), data.cast::<T>().as_ptr(), values.len());
            }
        }
        let slice_ptr = ptr::slice_from_raw_parts_mut(data.cast::<T>().as_ptr(), values.len());
        Ok(Self {
            data,
            ptr: unsafe { NonNull::new_unchecked(slice_ptr) },
            owner,
            meta: values.len(),
            size,
            align,
            type_hash: <[T] as TypeIdHash>::TYPE_HASH,
            drop_fn: drop_slice::<T>,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
    pub fn from_vec(values: Vec<T>) -> Result<Self, RRefError> {
        Self::from_slice_copy(&values)
    }

    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
    pub unsafe fn from_raw_parts(raw: RRefRawParts) -> Result<Self, RRefError> {
        verify_type_hash::<[T]>(raw.type_hash())?;
        if raw.align() != mem::align_of::<T>() {
            return Err(RawPartsError::SizeMismatch.into());
        }
        let len = raw.metadata();
        let expected_size = mem::size_of::<T>().saturating_mul(len);
        if raw.size() != expected_size {
            return Err(RawPartsError::SizeMismatch.into());
        }
        let (data, owner, meta, size, align, type_hash, drop_fn) = raw.into_components();
        let slice_ptr = ptr::slice_from_raw_parts_mut(data.cast::<T>().as_ptr(), len);
        Ok(Self {
            data,
            ptr: unsafe { NonNull::new_unchecked(slice_ptr) },
            owner,
            meta,
            size,
            align,
            type_hash,
            drop_fn,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required state cannot be read.
    pub fn recv(channel: ChannelHandle) -> Result<Self, RRefError> {
        let raw = kernel::instance().ipc_recv_raw(channel)?;
        let parts = RRefRawParts::from_abi(raw)?;
        match unsafe { Self::from_raw_parts(parts) } {
            Ok(value) => Ok(value),
            Err(err) => {
                unsafe { parts.drop_erased() };
                Err(err)
            }
        }
    }
}

impl<T> RRef<[T]> {
    pub fn len(&self) -> usize {
        self.meta
    }

    pub fn is_empty(&self) -> bool {
        self.meta == 0
    }
}

pub fn current_domain() -> DomainId {
    kernel::instance().ipc_current_domain()
}

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub fn create_channel() -> KapiResult<(ChannelHandle, ChannelHandle)> {
    kernel::instance().ipc_create_channel()
}

/// # Errors
///
/// Returns an error if the resource is invalid, still in use, or cannot be released.
pub fn close_channel(channel: ChannelHandle) -> KapiResult<()> {
    kernel::instance().ipc_close(channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn noop_drop(
        _ptr: *mut u8,
        _owner: u64,
        _meta: usize,
        _size: usize,
        _align: usize,
    ) {
    }

    #[test]
    fn raw_parts_abi_round_trip_preserves_metadata() {
        let parts = unsafe {
            RRefRawParts::from_components(
                NonNull::dangling(),
                DomainId::new(7),
                13,
                64,
                8,
                TypeHash::new(0xdead_beef),
                noop_drop,
            )
        };

        let abi = parts.into_abi();
        let restored = RRefRawParts::from_abi(abi).expect("abi round trip should succeed");
        assert_eq!(restored.owner(), DomainId::new(7));
        assert_eq!(restored.metadata(), 13);
        assert_eq!(restored.size(), 64);
        assert_eq!(restored.align(), 8);
        assert_eq!(restored.type_hash(), TypeHash::new(0xdead_beef));
    }

    #[test]
    fn slice_type_hash_verification_accepts_slice_impl() {
        assert!(verify_type_hash::<[u8]>(<[u8] as TypeIdHash>::TYPE_HASH).is_ok());
    }
}
