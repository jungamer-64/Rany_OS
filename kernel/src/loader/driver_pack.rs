// ============================================================================
// src/loader/driver_pack.rs - Driver Pack (manifest + ELF + signature)
// ============================================================================
#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

use super::LoadError;
use super::signature::{self, CellSignature};
use crate::crypto::sha256;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverPackPciSelector {
    ExactDevice {
        vendor_id: u16,
        device_id: u16,
    },
    ClassCode {
        vendor_id: Option<u16>,
        class: u8,
        subclass: u8,
        prog_if: u8,
    },
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

    pub const fn has_pci_selector(&self) -> bool {
        self.pci_vendor_id != 0
            || self.pci_device_id != 0
            || self.pci_class != 0
            || self.pci_subclass != 0
            || self.pci_prog_if != 0
    }

    pub fn pci_selector(&self) -> Result<Option<DriverPackPciSelector>, &'static str> {
        let has_vendor = self.pci_vendor_id != 0;
        let has_device = self.pci_device_id != 0;
        let has_class = self.pci_class != 0;
        let has_subclass = self.pci_subclass != 0;
        let has_prog_if = self.pci_prog_if != 0;

        if !(has_vendor || has_device || has_class || has_subclass || has_prog_if) {
            return Ok(None);
        }

        if has_vendor && has_device && !(has_class || has_subclass || has_prog_if) {
            return Ok(Some(DriverPackPciSelector::ExactDevice {
                vendor_id: self.pci_vendor_id,
                device_id: self.pci_device_id,
            }));
        }

        if has_device {
            return Err("PCI device selector requires vendor_id + device_id only");
        }

        if has_class && has_subclass {
            return Ok(Some(DriverPackPciSelector::ClassCode {
                vendor_id: has_vendor.then_some(self.pci_vendor_id),
                class: self.pci_class,
                subclass: self.pci_subclass,
                prog_if: self.pci_prog_if,
            }));
        }

        Err(
            "PCI class selector requires class + subclass (vendor_id optional; prog_if may be 0x00)",
        )
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
    let header = validate_driver_pack_header(data)?;
    let (manifest, manifest_bytes) = parse_manifest_section(data, &header)?;
    let elf = parse_elf_section(data, &header)?;
    let signature = parse_signature_section(data, &header)?;

    Ok(DriverPack {
        header,
        manifest,
        manifest_bytes,
        elf,
        signature,
    })
}

fn validate_driver_pack_header(data: &[u8]) -> Result<DriverPackHeader, LoadError> {
    let header: DriverPackHeader = read_struct(data, 0)
        .ok_or_else(|| LoadError::InvalidFormat("Driver pack header missing".into()))?;

    if header.magic != DRIVER_PACK_MAGIC {
        return Err(LoadError::InvalidFormat(
            "Driver pack magic mismatch".into(),
        ));
    }
    if header.version != DRIVER_PACK_VERSION {
        return Err(LoadError::InvalidFormat(
            "Driver pack version mismatch".into(),
        ));
    }

    let min_header = core::mem::size_of::<DriverPackHeader>() as u32;
    if header.header_size < min_header {
        return Err(LoadError::InvalidFormat(
            "Driver pack header too small".into(),
        ));
    }

    Ok(header)
}

fn parse_manifest_section<'a>(
    data: &'a [u8],
    header: &DriverPackHeader,
) -> Result<(DriverManifestV1, &'a [u8]), LoadError> {
    let manifest_bytes = get_slice(
        data,
        header.manifest_offset as usize,
        header.manifest_size as usize,
    )
    .ok_or_else(|| LoadError::InvalidFormat("Driver pack manifest out of range".into()))?;

    if manifest_bytes.len() < core::mem::size_of::<DriverManifestV1>() {
        return Err(LoadError::InvalidFormat(
            "Driver pack manifest too small".into(),
        ));
    }

    let manifest: DriverManifestV1 = read_struct(manifest_bytes, 0)
        .ok_or_else(|| LoadError::InvalidFormat("Driver pack manifest parse failed".into()))?;

    if manifest.abi_version != DRIVER_MANIFEST_VERSION {
        return Err(LoadError::InvalidFormat(
            "Driver manifest version mismatch".into(),
        ));
    }

    let min_manifest = core::mem::size_of::<DriverManifestV1>() as u32;
    if manifest.abi_size < min_manifest {
        return Err(LoadError::InvalidFormat(
            "Driver manifest size too small".into(),
        ));
    }

    Ok((manifest, manifest_bytes))
}

fn parse_elf_section<'a>(data: &'a [u8], header: &DriverPackHeader) -> Result<&'a [u8], LoadError> {
    get_slice(data, header.elf_offset as usize, header.elf_size as usize)
        .ok_or_else(|| LoadError::InvalidFormat("Driver pack ELF out of range".into()))
}

fn parse_signature_section(
    data: &[u8],
    header: &DriverPackHeader,
) -> Result<Option<DriverPackSignature>, LoadError> {
    if header.signature_size == 0 {
        return Ok(None);
    }

    let sig_bytes = get_slice(
        data,
        header.signature_offset as usize,
        header.signature_size as usize,
    )
    .ok_or_else(|| LoadError::InvalidFormat("Driver pack signature out of range".into()))?;

    if sig_bytes.len() < core::mem::size_of::<DriverPackSignature>() {
        return Err(LoadError::InvalidFormat(
            "Driver pack signature too small".into(),
        ));
    }

    let sig: DriverPackSignature = read_struct(sig_bytes, 0)
        .ok_or_else(|| LoadError::InvalidFormat("Driver pack signature parse failed".into()))?;
    Ok(Some(sig))
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

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn build_unsigned_driver_pack(
    name: &str,
    elf: &[u8],
    kernel_api_min_version: u32,
) -> Vec<u8> {
    build_unsigned_driver_pack_with_manifest(
        name,
        elf,
        DRIVER_ABI_VERSION as u32,
        kernel_api_min_version,
        None,
    )
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn build_unsigned_driver_pack_with_versions(
    name: &str,
    elf: &[u8],
    driver_abi_version: u32,
    kernel_api_min_version: u32,
) -> Vec<u8> {
    build_unsigned_driver_pack_with_manifest(
        name,
        elf,
        driver_abi_version,
        kernel_api_min_version,
        None,
    )
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn build_unsigned_driver_pack_with_manifest(
    name: &str,
    elf: &[u8],
    driver_abi_version: u32,
    kernel_api_min_version: u32,
    pci_selector: Option<DriverPackPciSelector>,
) -> Vec<u8> {
    use core::mem::size_of;

    fn copy_repr_c<T>(dst: &mut Vec<u8>, value: &T) {
        let bytes = unsafe {
            core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
        };
        dst.extend_from_slice(bytes);
    }

    let mut name_bytes = [0u8; 32];
    let raw_name = name.as_bytes();
    let name_len = core::cmp::min(raw_name.len(), name_bytes.len());
    name_bytes[..name_len].copy_from_slice(&raw_name[..name_len]);

    let header_size = size_of::<DriverPackHeader>() as u32;
    let manifest_size = size_of::<DriverManifestV1>() as u32;
    let manifest_offset = header_size;
    let elf_offset = manifest_offset + manifest_size;

    let header = DriverPackHeader {
        magic: DRIVER_PACK_MAGIC,
        version: DRIVER_PACK_VERSION,
        header_size,
        manifest_offset,
        manifest_size,
        elf_offset,
        elf_size: elf.len() as u32,
        signature_offset: 0,
        signature_size: 0,
    };

    let (pci_vendor_id, pci_device_id, pci_class, pci_subclass, pci_prog_if) = match pci_selector {
        Some(DriverPackPciSelector::ExactDevice {
            vendor_id,
            device_id,
        }) => (vendor_id, device_id, 0, 0, 0),
        Some(DriverPackPciSelector::ClassCode {
            vendor_id,
            class,
            subclass,
            prog_if,
        }) => (vendor_id.unwrap_or(0), 0, class, subclass, prog_if),
        None => (0, 0, 0, 0, 0),
    };

    let manifest = DriverManifestV1 {
        abi_version: DRIVER_MANIFEST_VERSION,
        abi_size: manifest_size,
        flags: 0,
        name_len: name_len as u16,
        _reserved0: 0,
        name: name_bytes,
        driver_version: 0,
        driver_abi_version,
        kernel_api_min_version,
        required_caps: 0,
        pci_vendor_id,
        pci_device_id,
        pci_class,
        pci_subclass,
        pci_prog_if,
        _reserved1: 0,
        _reserved2: [0; 4],
    };

    let mut pack = Vec::with_capacity(header_size as usize + manifest_size as usize + elf.len());
    copy_repr_c(&mut pack, &header);
    copy_repr_c(&mut pack, &manifest);
    pack.extend_from_slice(elf);
    pack
}

#[cfg(any(test, feature = "qemu-test-export"))]
use kernel_api::abi::driver::DRIVER_ABI_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn manifest_accepts_exact_vendor_device_selector() {
        let manifest = DriverManifestV1 {
            abi_version: DRIVER_MANIFEST_VERSION,
            abi_size: core::mem::size_of::<DriverManifestV1>() as u32,
            flags: 0,
            name_len: 0,
            _reserved0: 0,
            name: [0; 32],
            driver_version: 0,
            driver_abi_version: DRIVER_ABI_VERSION as u32,
            kernel_api_min_version: 0,
            required_caps: 0,
            pci_vendor_id: 0x8086,
            pci_device_id: 0x1234,
            pci_class: 0,
            pci_subclass: 0,
            pci_prog_if: 0,
            _reserved1: 0,
            _reserved2: [0; 4],
        };

        assert_eq!(
            manifest.pci_selector(),
            Ok(Some(DriverPackPciSelector::ExactDevice {
                vendor_id: 0x8086,
                device_id: 0x1234,
            }))
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn manifest_accepts_vendor_qualified_class_selector() {
        let manifest = DriverManifestV1 {
            abi_version: DRIVER_MANIFEST_VERSION,
            abi_size: core::mem::size_of::<DriverManifestV1>() as u32,
            flags: 0,
            name_len: 0,
            _reserved0: 0,
            name: [0; 32],
            driver_version: 0,
            driver_abi_version: DRIVER_ABI_VERSION as u32,
            kernel_api_min_version: 0,
            required_caps: 0,
            pci_vendor_id: 0x8086,
            pci_device_id: 0,
            pci_class: 0x04,
            pci_subclass: 0x03,
            pci_prog_if: 0x00,
            _reserved1: 0,
            _reserved2: [0; 4],
        };

        assert_eq!(
            manifest.pci_selector(),
            Ok(Some(DriverPackPciSelector::ClassCode {
                vendor_id: Some(0x8086),
                class: 0x04,
                subclass: 0x03,
                prog_if: 0x00,
            }))
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn manifest_rejects_partial_class_selector() {
        let manifest = DriverManifestV1 {
            abi_version: DRIVER_MANIFEST_VERSION,
            abi_size: core::mem::size_of::<DriverManifestV1>() as u32,
            flags: 0,
            name_len: 0,
            _reserved0: 0,
            name: [0; 32],
            driver_version: 0,
            driver_abi_version: DRIVER_ABI_VERSION as u32,
            kernel_api_min_version: 0,
            required_caps: 0,
            pci_vendor_id: 0,
            pci_device_id: 0,
            pci_class: 0x04,
            pci_subclass: 0,
            pci_prog_if: 0,
            _reserved1: 0,
            _reserved2: [0; 4],
        };

        assert!(manifest.pci_selector().is_err());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn manifest_rejects_vendor_only_selector() {
        let manifest = DriverManifestV1 {
            abi_version: DRIVER_MANIFEST_VERSION,
            abi_size: core::mem::size_of::<DriverManifestV1>() as u32,
            flags: 0,
            name_len: 0,
            _reserved0: 0,
            name: [0; 32],
            driver_version: 0,
            driver_abi_version: DRIVER_ABI_VERSION as u32,
            kernel_api_min_version: 0,
            required_caps: 0,
            pci_vendor_id: 0x8086,
            pci_device_id: 0,
            pci_class: 0,
            pci_subclass: 0,
            pci_prog_if: 0,
            _reserved1: 0,
            _reserved2: [0; 4],
        };

        assert!(manifest.pci_selector().is_err());
    }
}
