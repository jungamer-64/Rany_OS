//! ABI dependency records emitted into `.rany_type_id`. Linkers may concatenate
//! independently emitted fragments; each fragment carries its own header/count.

use crate::ipc::fnv1a_hash;

pub const ENTRY_NAME_LEN: usize = 64;
pub const ENTRY_SIZE: usize = 78;
pub const HEADER_SIZE: usize = 12;
pub const MAGIC: [u8; 4] = *b"RTID";
pub const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy)]
pub struct DependencySpec {
    pub name: &'static str,
    pub hash: u64,
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

#[repr(C)]
pub struct TypeIdSection<const N: usize> {
    pub header: [u8; HEADER_SIZE],
    pub entries: [[u8; ENTRY_SIZE]; N],
}

pub const fn dependency(
    name: &'static str,
    hash: u64,
    major: u16,
    minor: u16,
    patch: u16,
) -> DependencySpec {
    DependencySpec {
        name,
        hash,
        major,
        minor,
        patch,
    }
}

const fn encode_entry(dep: DependencySpec) -> [u8; ENTRY_SIZE] {
    let mut entry = [0u8; ENTRY_SIZE];
    let bytes = dep.name.as_bytes();
    // Invalid static declarations must fail during metadata emission, rather
    // than silently changing the interface identity by truncating its name.
    assert!(!bytes.is_empty() && bytes.len() <= ENTRY_NAME_LEN);
    let mut i = 0usize;
    // LOOP_PROOF: mode=bounded; reason=Index increases once per name byte and cannot exceed the fixed name field or input length.;
    while i < bytes.len() && i < ENTRY_NAME_LEN {
        assert!(bytes[i] != 0);
        entry[i] = bytes[i];
        i += 1;
    }

    let hash = dep.hash.to_le_bytes();
    let mut j = 0usize;
    // LOOP_PROOF: mode=bounded; reason=Index increases once per hash byte and is bounded by the eight-byte encoded hash.;
    while j < hash.len() {
        entry[64 + j] = hash[j];
        j += 1;
    }

    let major = dep.major.to_le_bytes();
    let minor = dep.minor.to_le_bytes();
    let patch = dep.patch.to_le_bytes();
    entry[72] = major[0];
    entry[73] = major[1];
    entry[74] = minor[0];
    entry[75] = minor[1];
    entry[76] = patch[0];
    entry[77] = patch[1];
    entry
}

/// Encode one fragment without truncating interface identity.
///
/// # Panics
/// Rejects empty, NUL-containing or longer than 64-byte names, and counts that
/// cannot fit in the wire header. Static metadata emission evaluates this at
/// compile time, so invalid declarations cannot produce a loadable artifact.
pub const fn build_section<const N: usize>(deps: [DependencySpec; N]) -> TypeIdSection<N> {
    assert!(N <= u32::MAX as usize);
    let mut entries = [[0u8; ENTRY_SIZE]; N];
    let mut i = 0usize;
    // LOOP_PROOF: mode=bounded; reason=Index increases once per dependency and is bounded by the immutable const-generic array extent.;
    while i < N {
        entries[i] = encode_entry(deps[i]);
        i += 1;
    }

    TypeIdSection {
        header: [
            MAGIC[0],
            MAGIC[1],
            MAGIC[2],
            MAGIC[3],
            FORMAT_VERSION.to_le_bytes()[0],
            FORMAT_VERSION.to_le_bytes()[1],
            FORMAT_VERSION.to_le_bytes()[2],
            FORMAT_VERSION.to_le_bytes()[3],
            (N as u32).to_le_bytes()[0],
            (N as u32).to_le_bytes()[1],
            (N as u32).to_le_bytes()[2],
            (N as u32).to_le_bytes()[3],
        ],
        entries,
    }
}

// Dependency names select the interface; the tracked foreign declarations
// supply the protocol fingerprint for both cell emission and kernel admission.
pub const MEMORY_ALLOCATOR_INTERFACE: DependencySpec = dependency(
    "MemoryAllocatorInterface",
    fnv1a_hash(b"MemoryAllocatorInterface") ^ crate::abi::driver::DRIVER_TYPE_HASH,
    1,
    0,
    0,
);
pub const TASK_SCHEDULER_INTERFACE: DependencySpec = dependency(
    "TaskSchedulerInterface",
    fnv1a_hash(b"TaskSchedulerInterface") ^ crate::abi::driver::DRIVER_TYPE_HASH,
    1,
    0,
    0,
);
pub const IPC_INTERFACE: DependencySpec = dependency(
    "IpcInterface",
    fnv1a_hash(b"IpcInterface") ^ crate::abi::driver::DRIVER_TYPE_HASH,
    1,
    0,
    0,
);
pub const KERNEL_API_INTERFACE: DependencySpec = dependency(
    "KernelApiInterface",
    fnv1a_hash(b"KernelApiInterface") ^ crate::abi::driver::DRIVER_TYPE_HASH,
    1,
    0,
    0,
);
pub const DRIVER_EXPORTS_INTERFACE: DependencySpec = dependency(
    "DriverExportsInterface",
    fnv1a_hash(b"DriverExportsInterface") ^ crate::abi::driver::DRIVER_TYPE_HASH,
    1,
    0,
    0,
);
