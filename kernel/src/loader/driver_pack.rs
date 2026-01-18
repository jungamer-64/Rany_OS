// ============================================================================
// src/loader/driver_pack.rs - Driver Pack (manifest + ELF + signature)
// ============================================================================
#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

use super::signature::{self, CellSignature};
use super::sha256;
use super::LoadError;
use crate::util::{get_slice, read_struct};

pub const DRIVER_PACK_MAGIC: [u8; 8] = *b"EXDRV\0\0\0";
pub const DRIVER_PACK_VERSION: u32 = 1;
pub const DRIVER_MANIFEST_VERSION: u32 = 1;
pub const DRIVER_PACK_SIGNATURE_MAGIC: [u8; 8] = *b"EXDRSIG\0";
pub const DRIVER_PACK_SIGNATURE_VERSION: u32 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverPackHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub header_size: u32,
    pub manifest_offset: u32,
    pub manifest_size: u32,
    pub elf_offset: u32,
    pub elf_size: u32,
    pub signature_offset: u32,
    pub signature_size: u32,
}

pub mod manifest_flags {
    pub const CONTAINS_UNSAFE: u32 = 1 << 0;
}

pub mod required_caps {
    pub const DMA: u64 = 1 << 0;
    pub const MMIO: u64 = 1 << 1;
    pub const IRQ: u64 = 1 << 2;
    pub const IO_PORTS: u64 = 1 << 3;
    pub const PCI_CONFIG: u64 = 1 << 4;
    pub const IOMMU: u64 = 1 << 5;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverManifestV1 {
    pub abi_version: u32,
    pub abi_size: u32,
    pub flags: u32,
    pub name_len: u16,
    pub _reserved0: u16,
    pub name: [u8; 32],
    pub driver_version: u64,
    pub driver_abi_version: u32,
    pub kernel_api_min_version: u32,
    pub required_caps: u64,
    pub pci_vendor_id: u16,
    pub pci_device_id: u16,
    pub pci_class: u8,
    pub pci_subclass: u8,
    pub pci_prog_if: u8,
    pub _reserved1: u8,
    pub _reserved2: [u64; 4],
}

impl DriverManifestV1 {
    pub fn name_str(&self) -> &str {
        let len = core::cmp::min(self.name_len as usize, self.name.len());
        let raw = &self.name[..len];
        let trimmed = raw.split(|b| *b == 0).next().unwrap_or(raw);
        core::str::from_utf8(trimmed).unwrap_or("")
    }

    pub fn contains_unsafe(&self) -> bool {
        (self.flags & manifest_flags::CONTAINS_UNSAFE) != 0
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverPackSignature {
    pub magic: [u8; 8],
    pub version: u32,
    pub flags: u32,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug)]
pub struct DriverPack<'a> {
    pub header: DriverPackHeader,
    pub manifest: DriverManifestV1,
    pub manifest_bytes: &'a [u8],
    pub elf: &'a [u8],
    pub signature: Option<DriverPackSignature>,
}

pub fn is_driver_pack(data: &[u8]) -> bool {
    read_struct::<DriverPackHeader>(data, 0)
        .map(|h| h.magic == DRIVER_PACK_MAGIC)
        .unwrap_or(false)
}

pub fn parse_driver_pack(data: &[u8]) -> Result<DriverPack<'_>, LoadError> {
    let header: DriverPackHeader = read_struct(data, 0)
        .ok_or_else(|| LoadError::InvalidFormat("Driver pack header missing".into()))?;

    if header.magic != DRIVER_PACK_MAGIC {
        return Err(LoadError::InvalidFormat("Driver pack magic mismatch".into()));
    }
    if header.version != DRIVER_PACK_VERSION {
        return Err(LoadError::InvalidFormat("Driver pack version mismatch".into()));
    }

    let min_header = core::mem::size_of::<DriverPackHeader>() as u32;
    if header.header_size < min_header {
        return Err(LoadError::InvalidFormat("Driver pack header too small".into()));
    }

    let manifest_bytes = get_slice(
        data,
        header.manifest_offset as usize,
        header.manifest_size as usize,
    )
    .ok_or_else(|| LoadError::InvalidFormat("Driver pack manifest out of range".into()))?;

    if manifest_bytes.len() < core::mem::size_of::<DriverManifestV1>() {
        return Err(LoadError::InvalidFormat("Driver pack manifest too small".into()));
    }

    let manifest: DriverManifestV1 = read_struct(manifest_bytes, 0)
        .ok_or_else(|| LoadError::InvalidFormat("Driver pack manifest parse failed".into()))?;

    if manifest.abi_version != DRIVER_MANIFEST_VERSION {
        return Err(LoadError::InvalidFormat("Driver manifest version mismatch".into()));
    }

    let min_manifest = core::mem::size_of::<DriverManifestV1>() as u32;
    if manifest.abi_size < min_manifest {
        return Err(LoadError::InvalidFormat("Driver manifest size too small".into()));
    }

    let elf = get_slice(
        data,
        header.elf_offset as usize,
        header.elf_size as usize,
    )
    .ok_or_else(|| LoadError::InvalidFormat("Driver pack ELF out of range".into()))?;

    let signature = if header.signature_size == 0 {
        None
    } else {
        let sig_bytes = get_slice(
            data,
            header.signature_offset as usize,
            header.signature_size as usize,
        )
        .ok_or_else(|| LoadError::InvalidFormat("Driver pack signature out of range".into()))?;

        if sig_bytes.len() < core::mem::size_of::<DriverPackSignature>() {
            return Err(LoadError::InvalidFormat("Driver pack signature too small".into()));
        }

        let sig: DriverPackSignature = read_struct(sig_bytes, 0)
            .ok_or_else(|| LoadError::InvalidFormat("Driver pack signature parse failed".into()))?;
        Some(sig)
    };

    Ok(DriverPack {
        header,
        manifest,
        manifest_bytes,
        elf,
        signature,
    })
}

pub fn verify_driver_pack(pack: &DriverPack<'_>) -> Result<bool, LoadError> {
    let signature = match pack.signature {
        Some(sig) => sig,
        None => {
            log::info!("[DRIVER_PACK] Warning: unsigned driver pack (dev mode)");
            return Ok(false);
        }
    };

    if signature.magic != DRIVER_PACK_SIGNATURE_MAGIC {
        return Err(LoadError::InvalidSignature);
    }
    if signature.version != DRIVER_PACK_SIGNATURE_VERSION {
        return Err(LoadError::InvalidSignature);
    }

    let mut signed = Vec::with_capacity(pack.manifest_bytes.len() + pack.elf.len());
    signed.extend_from_slice(pack.manifest_bytes);
    signed.extend_from_slice(pack.elf);

    let hash = sha256::compute(&signed);
    let cell_sig = CellSignature {
        version: 1,
        contains_unsafe: pack.manifest.contains_unsafe(),
        uses_framework_only: true,
        compiler_version: String::from("pack"),
        build_timestamp: 0,
        hash,
        signature: signature.signature.to_vec(),
        public_key: signature.public_key,
    };

    if !signature::verify_signature(&cell_sig, &signed) {
        return Err(LoadError::InvalidSignature);
    }

    Ok(true)
}
