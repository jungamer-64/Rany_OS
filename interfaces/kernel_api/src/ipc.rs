// ============================================================================
// kernel_api/src/ipc.rs - Public IPC metadata and zero-copy foundations
// ============================================================================

use core::fmt;
use core::ptr::NonNull;

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

pub fn verify_type_hash<T: TypeIdHash>(expected: TypeHash) -> Result<(), TypeHashError> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawPartsError {
    TypeMismatch,
    SizeMismatch,
}

/// Type-erased ownership record for future Exchange Heap / quarantine plumbing.
#[derive(Debug, Clone, Copy)]
pub struct RRefRawParts {
    ptr: NonNull<u8>,
    owner: DomainId,
    meta: usize,
    #[cfg(debug_assertions)]
    size: usize,
    #[cfg(debug_assertions)]
    type_hash: TypeHash,
    drop_fn: unsafe fn(NonNull<u8>, DomainId, usize),
}

unsafe impl Send for RRefRawParts {}
unsafe impl Sync for RRefRawParts {}

impl RRefRawParts {
    pub const unsafe fn from_components(
        ptr: NonNull<u8>,
        owner: DomainId,
        meta: usize,
        drop_fn: unsafe fn(NonNull<u8>, DomainId, usize),
        #[cfg(debug_assertions)] size: usize,
        #[cfg(debug_assertions)] type_hash: TypeHash,
    ) -> Self {
        Self {
            ptr,
            owner,
            meta,
            #[cfg(debug_assertions)]
            size,
            #[cfg(debug_assertions)]
            type_hash,
            drop_fn,
        }
    }

    pub fn owner(&self) -> DomainId {
        self.owner
    }

    pub fn into_components(
        self,
    ) -> (
        NonNull<u8>,
        DomainId,
        usize,
        unsafe fn(NonNull<u8>, DomainId, usize),
    ) {
        (self.ptr, self.owner, self.meta, self.drop_fn)
    }

    pub unsafe fn drop_erased(self) {
        unsafe { (self.drop_fn)(self.ptr, self.owner, self.meta) };
    }
}
