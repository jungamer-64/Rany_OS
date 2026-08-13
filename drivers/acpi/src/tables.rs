use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{AcpiError, AcpiErrorKind};

const SDT_HEADER_LEN: usize = 36;
const RSDP_V1_LEN: usize = 20;
const RSDP_V2_LEN: usize = 36;
const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ROOT_TABLES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableSignature([u8; 4]);

impl TableSignature {
    pub const APIC: Self = Self(*b"APIC");
    pub const DMAR: Self = Self(*b"DMAR");
    pub const DSDT: Self = Self(*b"DSDT");
    pub const FACP: Self = Self(*b"FACP");
    pub const MCFG: Self = Self(*b"MCFG");
    pub const NFIT: Self = Self(*b"NFIT");
    pub const SRAT: Self = Self(*b"SRAT");
    pub const SSDT: Self = Self(*b"SSDT");
    pub const IVRS: Self = Self(*b"IVRS");

    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(self) -> [u8; 4] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdtHeader {
    pub signature: TableSignature,
    pub length: u32,
    pub revision: u8,
    pub oem_revision: u32,
}

impl SdtHeader {
    fn parse(bytes: &[u8]) -> Result<Self, AcpiError> {
        if bytes.len() < SDT_HEADER_LEN {
            return Err(AcpiError::new(
                AcpiErrorKind::InvalidLength,
                "ACPI SDT header is truncated",
            ));
        }
        let signature = TableSignature::new(bytes[0..4].try_into().map_err(|_| {
            AcpiError::new(AcpiErrorKind::InvalidSignature, "missing SDT signature")
        })?);
        Ok(Self {
            signature,
            length: read_u32(bytes, 4)?,
            revision: bytes[8],
            oem_revision: read_u32(bytes, 24)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AcpiTable {
    physical_address: u64,
    header: SdtHeader,
    bytes: Arc<[u8]>,
}

impl AcpiTable {
    pub const fn physical_address(&self) -> u64 {
        self.physical_address
    }

    pub const fn header(&self) -> SdtHeader {
        self.header
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn owned_bytes(&self) -> Arc<[u8]> {
        self.bytes.clone()
    }

    pub fn body(&self) -> &[u8] {
        self.bytes.get(SDT_HEADER_LEN..).unwrap_or_default()
    }
}

/// Physical-memory reader used only while building the owned table catalog.
///
/// # Safety
///
/// Implementations must reject unmapped or overflowing physical ranges and
/// must not return bytes from memory that may disappear during the read.
pub unsafe trait AcpiMemory: Sync {
    /// Copies one physical range into owned memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the physical range is invalid or unreadable.
    ///
    /// # Safety
    ///
    /// The caller must ensure the requested physical address denotes firmware
    /// memory that may be read for `length` bytes at this boot phase.
    unsafe fn read(&self, physical_address: u64, length: usize) -> Result<Vec<u8>, AcpiError>;
}

#[derive(Debug, Clone, Copy)]
pub struct HhdmAcpiMemory {
    offset: u64,
}

impl HhdmAcpiMemory {
    pub const fn new(offset: u64) -> Self {
        Self { offset }
    }
}

// SAFETY: the implementation performs checked HHDM address translation and
// copies the requested range before returning it.
unsafe impl AcpiMemory for HhdmAcpiMemory {
    unsafe fn read(&self, physical_address: u64, length: usize) -> Result<Vec<u8>, AcpiError> {
        if physical_address == 0 || length == 0 || length > MAX_TABLE_BYTES {
            return Err(AcpiError::new(
                AcpiErrorKind::InvalidAddress,
                "ACPI physical range is empty or exceeds the table limit",
            ));
        }
        let virtual_address = physical_address.checked_add(self.offset).ok_or_else(|| {
            AcpiError::new(
                AcpiErrorKind::InvalidAddress,
                "ACPI HHDM translation overflowed",
            )
        })?;
        let _ = virtual_address.checked_add(length as u64).ok_or_else(|| {
            AcpiError::new(
                AcpiErrorKind::InvalidAddress,
                "ACPI mapped range overflowed",
            )
        })?;
        let source = unsafe { core::slice::from_raw_parts(virtual_address as *const u8, length) };
        Ok(source.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct TableCatalog {
    revision: u8,
    tables: Arc<[AcpiTable]>,
}

impl TableCatalog {
    /// Copies and validates the complete RSDT/XSDT table catalog.
    ///
    /// # Safety
    ///
    /// `rsdp_address` must identify firmware memory readable through `memory`.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid RSDP/root/table checksums, malformed
    /// lengths, unreadable mappings, or unreasonable table counts.
    pub unsafe fn load(memory: &impl AcpiMemory, rsdp_address: u64) -> Result<Self, AcpiError> {
        let rsdp_prefix = unsafe { memory.read(rsdp_address, RSDP_V2_LEN)? };
        if rsdp_prefix.get(0..8) != Some(b"RSD PTR ") {
            return Err(AcpiError::new(
                AcpiErrorKind::InvalidSignature,
                "RSDP signature does not match",
            ));
        }
        validate_checksum(&rsdp_prefix[..RSDP_V1_LEN], None)?;
        let revision = rsdp_prefix[15];
        let (root_address, entry_width, root_signature) = if revision >= 2 {
            let rsdp_length = read_u32(&rsdp_prefix, 20)? as usize;
            if !(RSDP_V2_LEN..=MAX_TABLE_BYTES).contains(&rsdp_length) {
                return Err(AcpiError::new(
                    AcpiErrorKind::InvalidLength,
                    "extended RSDP length is invalid",
                ));
            }
            let rsdp = unsafe { memory.read(rsdp_address, rsdp_length)? };
            validate_checksum(&rsdp, None)?;
            (read_u64(&rsdp, 24)?, 8usize, *b"XSDT")
        } else {
            (u64::from(read_u32(&rsdp_prefix, 16)?), 4usize, *b"RSDT")
        };

        let root = unsafe { read_table(memory, root_address)? };
        if root.header.signature.bytes() != root_signature {
            return Err(AcpiError::table(
                AcpiErrorKind::InvalidSignature,
                root.header.signature.bytes(),
                "root table signature does not match RSDP revision",
            ));
        }
        let entries = root.body();
        if !entries.len().is_multiple_of(entry_width) {
            return Err(AcpiError::table(
                AcpiErrorKind::InvalidLength,
                root_signature,
                "root table entry region is misaligned",
            ));
        }
        let table_count = entries.len() / entry_width;
        if table_count > MAX_ROOT_TABLES {
            return Err(AcpiError::new(
                AcpiErrorKind::CapacityExceeded,
                "ACPI root table count exceeds the catalog limit",
            ));
        }

        let mut tables = Vec::with_capacity(table_count + 1);
        for entry in entries.chunks_exact(entry_width) {
            let address = if entry_width == 8 {
                read_u64(entry, 0)?
            } else {
                u64::from(read_u32(entry, 0)?)
            };
            if address == 0 {
                continue;
            }
            let table = unsafe { read_table(memory, address)? };
            tables.push(table);
        }

        if let Some(fadt) = tables
            .iter()
            .find(|table| table.header.signature == TableSignature::FACP)
        {
            let dsdt_address = fadt_dsdt_address(fadt.bytes())?;
            if dsdt_address != 0 {
                let dsdt = unsafe { read_table(memory, dsdt_address)? };
                if dsdt.header.signature != TableSignature::DSDT {
                    return Err(AcpiError::table(
                        AcpiErrorKind::InvalidSignature,
                        dsdt.header.signature.bytes(),
                        "FADT DSDT pointer does not reference a DSDT",
                    ));
                }
                tables.push(dsdt);
            }
        }

        Ok(Self {
            revision,
            tables: tables.into(),
        })
    }

    pub const fn revision(&self) -> u8 {
        self.revision
    }

    pub fn tables(&self) -> &[AcpiTable] {
        &self.tables
    }

    pub fn first(&self, signature: TableSignature) -> Option<&AcpiTable> {
        self.tables
            .iter()
            .find(|table| table.header.signature == signature)
    }

    pub fn matching(&self, signature: TableSignature) -> impl Iterator<Item = &AcpiTable> + '_ {
        self.tables
            .iter()
            .filter(move |table| table.header.signature == signature)
    }

    /// Parses all MADT processor entries without truncating x2APIC IDs.
    ///
    /// # Errors
    ///
    /// Returns an error when MADT is missing or structurally malformed.
    pub fn firmware_cpus(&self) -> Result<Vec<FirmwareCpuEntry>, AcpiError> {
        parse_madt(self.required(TableSignature::APIC)?.bytes()).map(|madt| madt.cpus)
    }

    /// Parses all MADT I/O APIC entries.
    ///
    /// # Errors
    ///
    /// Returns an error when MADT is missing or structurally malformed.
    pub fn io_apics(&self) -> Result<Vec<IoApicEntry>, AcpiError> {
        parse_madt(self.required(TableSignature::APIC)?.bytes()).map(|madt| madt.io_apics)
    }

    /// Parses all MADT interrupt-source overrides.
    ///
    /// # Errors
    ///
    /// Returns an error when MADT is missing or structurally malformed.
    pub fn interrupt_overrides(&self) -> Result<Vec<InterruptOverride>, AcpiError> {
        parse_madt(self.required(TableSignature::APIC)?.bytes()).map(|madt| madt.overrides)
    }

    /// Resolves the effective local APIC MMIO base from MADT.
    ///
    /// # Errors
    ///
    /// Returns an error when MADT is missing or structurally malformed.
    pub fn local_apic_address(&self) -> Result<u64, AcpiError> {
        parse_madt(self.required(TableSignature::APIC)?.bytes()).map(|madt| madt.local_apic_address)
    }

    /// Parses enabled and disabled SRAT processor affinities.
    ///
    /// # Errors
    ///
    /// Returns an error when a present SRAT is structurally malformed.
    pub fn numa_cpu_affinity(&self) -> Result<Vec<NumaCpuAffinity>, AcpiError> {
        let Some(srat) = self.first(TableSignature::SRAT) else {
            return Ok(Vec::new());
        };
        parse_srat(srat.bytes()).map(|parsed| parsed.0)
    }

    /// Parses SRAT memory affinities and hotplug capability flags.
    ///
    /// # Errors
    ///
    /// Returns an error when a present SRAT is structurally malformed.
    pub fn numa_memory_affinity(&self) -> Result<Vec<NumaMemoryAffinity>, AcpiError> {
        let Some(srat) = self.first(TableSignature::SRAT) else {
            return Ok(Vec::new());
        };
        parse_srat(srat.bytes()).map(|parsed| parsed.1)
    }

    /// Parses PCIe configuration-space allocations from MCFG.
    ///
    /// # Errors
    ///
    /// Returns an error when a present MCFG is structurally malformed.
    pub fn mcfg_allocations(&self) -> Result<Vec<McfgAllocation>, AcpiError> {
        let Some(mcfg) = self.first(TableSignature::MCFG) else {
            return Ok(Vec::new());
        };
        parse_mcfg(mcfg.bytes())
    }

    fn required(&self, signature: TableSignature) -> Result<&AcpiTable, AcpiError> {
        self.first(signature).ok_or_else(|| {
            AcpiError::table(
                AcpiErrorKind::MissingTable,
                signature.bytes(),
                "required ACPI table is missing",
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareCpuEntry {
    pub firmware_uid: u32,
    pub apic_id: u32,
    pub enabled: bool,
    pub online_capable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicEntry {
    pub id: u8,
    pub address: u32,
    pub global_interrupt_base: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptOverride {
    pub bus: u8,
    pub source: u8,
    pub global_interrupt: u32,
    pub flags: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaCpuAffinity {
    pub apic_id: u32,
    pub proximity_domain: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaMemoryAffinity {
    pub base: u64,
    pub length: u64,
    pub proximity_domain: u32,
    pub enabled: bool,
    pub hotpluggable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McfgAllocation {
    pub base_address: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

#[derive(Debug)]
struct ParsedMadt {
    local_apic_address: u64,
    cpus: Vec<FirmwareCpuEntry>,
    io_apics: Vec<IoApicEntry>,
    overrides: Vec<InterruptOverride>,
}

fn parse_madt(bytes: &[u8]) -> Result<ParsedMadt, AcpiError> {
    if bytes.len() < 44 {
        return Err(table_length_error(
            *b"APIC",
            "MADT fixed header is truncated",
        ));
    }
    let mut parsed = ParsedMadt {
        local_apic_address: u64::from(read_u32(bytes, 36)?),
        cpus: Vec::new(),
        io_apics: Vec::new(),
        overrides: Vec::new(),
    };
    let mut offset = 44usize;
    while offset < bytes.len() {
        let entry_type = *bytes
            .get(offset)
            .ok_or_else(|| table_length_error(*b"APIC", "MADT entry type is missing"))?;
        let length = usize::from(
            *bytes
                .get(offset + 1)
                .ok_or_else(|| table_length_error(*b"APIC", "MADT entry length is missing"))?,
        );
        if length < 2
            || offset
                .checked_add(length)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(table_length_error(*b"APIC", "MADT entry is malformed"));
        }
        let entry = &bytes[offset..offset + length];
        match entry_type {
            0 if length >= 8 => {
                let flags = read_u32(entry, 4)?;
                parsed.cpus.push(FirmwareCpuEntry {
                    firmware_uid: u32::from(entry[2]),
                    apic_id: u32::from(entry[3]),
                    enabled: flags & 1 != 0,
                    online_capable: flags & 2 != 0,
                });
            }
            1 if length >= 12 => parsed.io_apics.push(IoApicEntry {
                id: entry[2],
                address: read_u32(entry, 4)?,
                global_interrupt_base: read_u32(entry, 8)?,
            }),
            2 if length >= 10 => parsed.overrides.push(InterruptOverride {
                bus: entry[2],
                source: entry[3],
                global_interrupt: read_u32(entry, 4)?,
                flags: read_u16(entry, 8)?,
            }),
            5 if length >= 12 => parsed.local_apic_address = read_u64(entry, 4)?,
            9 if length >= 16 => {
                let flags = read_u32(entry, 8)?;
                parsed.cpus.push(FirmwareCpuEntry {
                    firmware_uid: read_u32(entry, 12)?,
                    apic_id: read_u32(entry, 4)?,
                    enabled: flags & 1 != 0,
                    online_capable: flags & 2 != 0,
                });
            }
            _ => {}
        }
        offset += length;
    }
    Ok(parsed)
}

fn parse_srat(bytes: &[u8]) -> Result<(Vec<NumaCpuAffinity>, Vec<NumaMemoryAffinity>), AcpiError> {
    if bytes.len() < 48 {
        return Err(table_length_error(
            *b"SRAT",
            "SRAT fixed header is truncated",
        ));
    }
    let mut cpus = Vec::new();
    let mut memory = Vec::new();
    let mut offset = 48usize;
    while offset < bytes.len() {
        let entry_type = bytes[offset];
        let length = usize::from(
            *bytes
                .get(offset + 1)
                .ok_or_else(|| table_length_error(*b"SRAT", "SRAT entry length is missing"))?,
        );
        if length < 2
            || offset
                .checked_add(length)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(table_length_error(*b"SRAT", "SRAT entry is malformed"));
        }
        let entry = &bytes[offset..offset + length];
        match entry_type {
            0 if length >= 16 => {
                let proximity = u32::from(entry[2])
                    | (u32::from(entry[9]) << 8)
                    | (u32::from(entry[10]) << 16)
                    | (u32::from(entry[11]) << 24);
                cpus.push(NumaCpuAffinity {
                    apic_id: u32::from(entry[3]),
                    proximity_domain: proximity,
                    enabled: read_u32(entry, 4)? & 1 != 0,
                });
            }
            1 if length >= 40 => {
                let flags = read_u32(entry, 28)?;
                memory.push(NumaMemoryAffinity {
                    proximity_domain: read_u32(entry, 2)?,
                    base: read_u64(entry, 8)?,
                    length: read_u64(entry, 16)?,
                    enabled: flags & 1 != 0,
                    hotpluggable: flags & 2 != 0,
                });
            }
            2 if length >= 24 => cpus.push(NumaCpuAffinity {
                proximity_domain: read_u32(entry, 4)?,
                apic_id: read_u32(entry, 8)?,
                enabled: read_u32(entry, 12)? & 1 != 0,
            }),
            _ => {}
        }
        offset += length;
    }
    Ok((cpus, memory))
}

fn parse_mcfg(bytes: &[u8]) -> Result<Vec<McfgAllocation>, AcpiError> {
    if bytes.len() < 44 || !(bytes.len() - 44).is_multiple_of(16) {
        return Err(table_length_error(
            *b"MCFG",
            "MCFG allocation region is malformed",
        ));
    }
    bytes[44..]
        .as_chunks::<16>()
        .0
        .iter()
        .map(|entry| {
            Ok(McfgAllocation {
                base_address: read_u64(entry, 0)?,
                segment: read_u16(entry, 8)?,
                start_bus: entry[10],
                end_bus: entry[11],
            })
        })
        .collect()
}

unsafe fn read_table(
    memory: &impl AcpiMemory,
    physical_address: u64,
) -> Result<AcpiTable, AcpiError> {
    let header_bytes = unsafe { memory.read(physical_address, SDT_HEADER_LEN)? };
    let header = SdtHeader::parse(&header_bytes)?;
    let length = header.length as usize;
    if !(SDT_HEADER_LEN..=MAX_TABLE_BYTES).contains(&length) {
        return Err(AcpiError::table(
            AcpiErrorKind::InvalidLength,
            header.signature.bytes(),
            "ACPI table length is outside the accepted range",
        ));
    }
    let bytes = unsafe { memory.read(physical_address, length)? };
    validate_checksum(&bytes, Some(header.signature.bytes()))?;
    Ok(AcpiTable {
        physical_address,
        header,
        bytes: bytes.into(),
    })
}

fn fadt_dsdt_address(bytes: &[u8]) -> Result<u64, AcpiError> {
    if bytes.len() < 44 {
        return Err(table_length_error(
            *b"FACP",
            "FADT is too short for DSDT pointer",
        ));
    }
    let legacy = u64::from(read_u32(bytes, 40)?);
    if bytes.len() >= 148 {
        let extended = read_u64(bytes, 140)?;
        if extended != 0 {
            return Ok(extended);
        }
    }
    Ok(legacy)
}

fn validate_checksum(bytes: &[u8], signature: Option<[u8; 4]>) -> Result<(), AcpiError> {
    if bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0 {
        return Ok(());
    }
    match signature {
        Some(signature) => Err(AcpiError::table(
            AcpiErrorKind::InvalidChecksum,
            signature,
            "ACPI table checksum failed",
        )),
        None => Err(AcpiError::new(
            AcpiErrorKind::InvalidChecksum,
            "RSDP checksum failed",
        )),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AcpiError> {
    let value = bytes.get(offset..offset + 2).ok_or_else(|| {
        AcpiError::new(AcpiErrorKind::InvalidLength, "ACPI u16 field is truncated")
    })?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AcpiError> {
    let value = bytes.get(offset..offset + 4).ok_or_else(|| {
        AcpiError::new(AcpiErrorKind::InvalidLength, "ACPI u32 field is truncated")
    })?;
    Ok(u32::from_le_bytes(value.try_into().map_err(|_| {
        AcpiError::new(AcpiErrorKind::InvalidLength, "ACPI u32 field is malformed")
    })?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AcpiError> {
    let value = bytes.get(offset..offset + 8).ok_or_else(|| {
        AcpiError::new(AcpiErrorKind::InvalidLength, "ACPI u64 field is truncated")
    })?;
    Ok(u64::from_le_bytes(value.try_into().map_err(|_| {
        AcpiError::new(AcpiErrorKind::InvalidLength, "ACPI u64 field is malformed")
    })?))
}

fn table_length_error(signature: [u8; 4], detail: &'static str) -> AcpiError {
    AcpiError::table(AcpiErrorKind::InvalidLength, signature, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[checksum_offset] = 0u8.wrapping_sub(sum);
    }

    #[test]
    fn madt_preserves_full_x2apic_destination() {
        let mut bytes = alloc::vec![0u8; 60];
        bytes[0..4].copy_from_slice(b"APIC");
        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        bytes[44] = 9;
        bytes[45] = 16;
        bytes[48..52].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&1u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&7u32.to_le_bytes());
        checksum(&mut bytes, 9);

        let parsed = parse_madt(&bytes).unwrap();
        assert_eq!(parsed.cpus[0].apic_id, 0x1234_5678);
    }

    #[test]
    fn malformed_madt_entry_is_typed_error() {
        let mut bytes = alloc::vec![0u8; 46];
        bytes[0..4].copy_from_slice(b"APIC");
        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[44] = 9;
        bytes[45] = 1;
        checksum(&mut bytes, 9);
        assert_eq!(
            parse_madt(&bytes).unwrap_err().kind,
            AcpiErrorKind::InvalidLength
        );
    }
}
