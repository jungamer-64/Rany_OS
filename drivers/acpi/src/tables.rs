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

    /// Parses the SCI interrupt and fixed GPE register blocks from the FADT.
    ///
    /// # Errors
    ///
    /// Returns an error when the FADT is missing, a register descriptor is
    /// truncated or malformed, or the described GPE number space exceeds the
    /// AML `_Exx`/`_Lxx` namespace.
    pub fn fixed_events(&self) -> Result<FixedEventDescription, AcpiError> {
        parse_fadt_fixed_events(self.required(TableSignature::FACP)?.bytes())
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

    /// Parses NFIT system-physical-address ranges.
    ///
    /// # Errors
    ///
    /// Returns an error when a present NFIT contains a truncated structure,
    /// a reserved zero range index, or an overflowing physical range.
    pub fn nfit_spa_ranges(&self) -> Result<Vec<NfitSpaRange>, AcpiError> {
        let Some(nfit) = self.first(TableSignature::NFIT) else {
            return Ok(Vec::new());
        };
        parse_nfit_spa_ranges(nfit.bytes())
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

/// Address space used by an ACPI Generic Address Structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericAddressSpace {
    SystemMemory,
    SystemIo,
    Other(u8),
}

impl From<u8> for GenericAddressSpace {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::SystemMemory,
            1 => Self::SystemIo,
            value => Self::Other(value),
        }
    }
}

/// Access width encoded by an ACPI Generic Address Structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterAccessSize {
    Undefined,
    Byte,
    Word,
    Dword,
    Qword,
}

impl RegisterAccessSize {
    fn parse(value: u8) -> Result<Self, AcpiError> {
        match value {
            0 => Ok(Self::Undefined),
            1 => Ok(Self::Byte),
            2 => Ok(Self::Word),
            3 => Ok(Self::Dword),
            4 => Ok(Self::Qword),
            _ => Err(table_encoding_error(
                *b"FACP",
                "FADT Generic Address Structure has a reserved access size",
            )),
        }
    }
}

/// Validated ACPI Generic Address Structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericAddress {
    pub address_space: GenericAddressSpace,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: RegisterAccessSize,
    pub address: u64,
}

/// One fixed GPE status/enable register pair described by the FADT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpeRegisterBlock {
    pub address: GenericAddress,
    /// Bytes in one half of the block. Status occupies the first half and
    /// enable registers occupy the second half.
    pub register_bytes: u8,
    pub base_number: u16,
}

impl GpeRegisterBlock {
    pub const fn number_count(self) -> u16 {
        self.register_bytes as u16 * 8
    }
}

/// Fixed-event hardware needed by the SCI dispatch path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedEventDescription {
    pub sci_interrupt: u16,
    pub gpe_blocks: Vec<GpeRegisterBlock>,
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
    pub polarity: InterruptPolarity,
    pub trigger_mode: InterruptTriggerMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptPolarity {
    ConformsToBus,
    ActiveHigh,
    ActiveLow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptTriggerMode {
    ConformsToBus,
    Edge,
    Level,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfitSpaKind {
    ByteAddressablePersistentMemory,
    Other([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfitSpaRange {
    pub index: u16,
    pub proximity_domain: Option<u32>,
    pub kind: NfitSpaKind,
    pub base: u64,
    pub length: u64,
    pub memory_attributes: u64,
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
            2 if length >= 10 => {
                let flags = read_u16(entry, 8)?;
                parsed.overrides.push(InterruptOverride {
                    bus: entry[2],
                    source: entry[3],
                    global_interrupt: read_u32(entry, 4)?,
                    polarity: parse_interrupt_polarity(flags)?,
                    trigger_mode: parse_interrupt_trigger(flags)?,
                });
            }
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

fn parse_interrupt_polarity(flags: u16) -> Result<InterruptPolarity, AcpiError> {
    match flags & 0b11 {
        0 => Ok(InterruptPolarity::ConformsToBus),
        1 => Ok(InterruptPolarity::ActiveHigh),
        3 => Ok(InterruptPolarity::ActiveLow),
        _ => Err(table_encoding_error(
            *b"APIC",
            "MADT interrupt override uses a reserved polarity encoding",
        )),
    }
}

fn parse_interrupt_trigger(flags: u16) -> Result<InterruptTriggerMode, AcpiError> {
    match (flags >> 2) & 0b11 {
        0 => Ok(InterruptTriggerMode::ConformsToBus),
        1 => Ok(InterruptTriggerMode::Edge),
        3 => Ok(InterruptTriggerMode::Level),
        _ => Err(table_encoding_error(
            *b"APIC",
            "MADT interrupt override uses a reserved trigger encoding",
        )),
    }
}

fn parse_nfit_spa_ranges(bytes: &[u8]) -> Result<Vec<NfitSpaRange>, AcpiError> {
    const NFIT_FIXED_LEN: usize = 40;
    const SPA_RANGE_MIN_LEN: usize = 56;
    const PERSISTENT_MEMORY_GUID: [u8; 16] = [
        0x79, 0xd3, 0xf0, 0x66, 0xf3, 0xb4, 0x74, 0x40, 0xac, 0x43, 0x0d, 0x33, 0x18, 0xb7, 0x8c,
        0xdb,
    ];

    if bytes.len() < NFIT_FIXED_LEN {
        return Err(table_length_error(
            *b"NFIT",
            "NFIT fixed header is truncated",
        ));
    }

    let mut ranges = Vec::new();
    let mut offset = NFIT_FIXED_LEN;
    while offset < bytes.len() {
        let structure_type = read_u16(bytes, offset)?;
        let length = usize::from(read_u16(bytes, offset + 2)?);
        let end = offset
            .checked_add(length)
            .ok_or_else(|| table_length_error(*b"NFIT", "NFIT structure length overflowed"))?;
        if length < 4 || end > bytes.len() {
            return Err(table_length_error(
                *b"NFIT",
                "NFIT structure is truncated or has an invalid length",
            ));
        }

        if structure_type == 0 {
            if length < SPA_RANGE_MIN_LEN {
                return Err(table_length_error(
                    *b"NFIT",
                    "NFIT SPA range structure is truncated",
                ));
            }
            let structure = &bytes[offset..end];
            let index = read_u16(structure, 4)?;
            if index == 0 {
                return Err(table_encoding_error(
                    *b"NFIT",
                    "NFIT SPA range uses the reserved zero index",
                ));
            }
            let flags = read_u16(structure, 6)?;
            let guid: [u8; 16] = structure[16..32].try_into().map_err(|_| {
                table_length_error(*b"NFIT", "NFIT SPA range type GUID is truncated")
            })?;
            let base = read_u64(structure, 32)?;
            let length = read_u64(structure, 40)?;
            if length == 0 || base.checked_add(length).is_none() {
                return Err(table_length_error(
                    *b"NFIT",
                    "NFIT SPA range is empty or overflows physical address space",
                ));
            }
            ranges.push(NfitSpaRange {
                index,
                proximity_domain: (flags & (1 << 1) != 0)
                    .then(|| read_u32(structure, 12))
                    .transpose()?,
                kind: if guid == PERSISTENT_MEMORY_GUID {
                    NfitSpaKind::ByteAddressablePersistentMemory
                } else {
                    NfitSpaKind::Other(guid)
                },
                base,
                length,
                memory_attributes: read_u64(structure, 48)?,
            });
        }

        offset = end;
    }

    Ok(ranges)
}

const FADT_SCI_INTERRUPT_OFFSET: usize = 46;
const FADT_GPE0_BLOCK_OFFSET: usize = 80;
const FADT_GPE1_BLOCK_OFFSET: usize = 84;
const FADT_GPE0_LENGTH_OFFSET: usize = 92;
const FADT_GPE1_LENGTH_OFFSET: usize = 93;
const FADT_GPE1_BASE_OFFSET: usize = 94;
const FADT_X_GPE0_BLOCK_OFFSET: usize = 220;
const FADT_X_GPE1_BLOCK_OFFSET: usize = 232;
const GENERIC_ADDRESS_LENGTH: usize = 12;

fn parse_fadt_fixed_events(bytes: &[u8]) -> Result<FixedEventDescription, AcpiError> {
    let sci_interrupt = read_u16(bytes, FADT_SCI_INTERRUPT_OFFSET)?;
    let gpe0_length = *bytes
        .get(FADT_GPE0_LENGTH_OFFSET)
        .ok_or_else(|| table_length_error(*b"FACP", "FADT is too short for GPE0_BLK_LEN"))?;
    let gpe1_length = *bytes
        .get(FADT_GPE1_LENGTH_OFFSET)
        .ok_or_else(|| table_length_error(*b"FACP", "FADT is too short for GPE1_BLK_LEN"))?;
    let gpe1_base = u16::from(
        *bytes
            .get(FADT_GPE1_BASE_OFFSET)
            .ok_or_else(|| table_length_error(*b"FACP", "FADT is too short for GPE1_BASE"))?,
    );

    let mut gpe_blocks = Vec::with_capacity(2);
    if let Some(block) = parse_fadt_gpe_block(
        bytes,
        FADT_GPE0_BLOCK_OFFSET,
        FADT_X_GPE0_BLOCK_OFFSET,
        gpe0_length,
        0,
    )? {
        gpe_blocks.push(block);
    }
    if let Some(block) = parse_fadt_gpe_block(
        bytes,
        FADT_GPE1_BLOCK_OFFSET,
        FADT_X_GPE1_BLOCK_OFFSET,
        gpe1_length,
        gpe1_base,
    )? {
        if let Some(gpe0) = gpe_blocks.first()
            && block.base_number < gpe0.number_count()
        {
            return Err(table_encoding_error(
                *b"FACP",
                "FADT GPE1 number space overlaps GPE0",
            ));
        }
        gpe_blocks.push(block);
    }

    Ok(FixedEventDescription {
        sci_interrupt,
        gpe_blocks,
    })
}

fn parse_fadt_gpe_block(
    bytes: &[u8],
    legacy_address_offset: usize,
    extended_address_offset: usize,
    total_bytes: u8,
    base_number: u16,
) -> Result<Option<GpeRegisterBlock>, AcpiError> {
    if total_bytes == 0 {
        return Ok(None);
    }
    if !total_bytes.is_multiple_of(2) {
        return Err(table_encoding_error(
            *b"FACP",
            "FADT GPE register block length must contain equal status and enable halves",
        ));
    }

    let register_bytes = total_bytes / 2;
    let number_count = u16::from(register_bytes) * 8;
    if base_number
        .checked_add(number_count)
        .is_none_or(|end| end > 256)
    {
        return Err(AcpiError::table(
            AcpiErrorKind::CapacityExceeded,
            *b"FACP",
            "FADT GPE block exceeds the AML event-method number space",
        ));
    }

    let extended = bytes
        .get(extended_address_offset..extended_address_offset + GENERIC_ADDRESS_LENGTH)
        .map(parse_generic_address)
        .transpose()?;
    let address = match extended {
        Some(address) if address.address != 0 => {
            if address.bit_offset != 0 {
                return Err(table_encoding_error(
                    *b"FACP",
                    "FADT GPE register block has a non-zero bit offset",
                ));
            }
            let expected_width = total_bytes.checked_mul(8).ok_or_else(|| {
                AcpiError::table(
                    AcpiErrorKind::CapacityExceeded,
                    *b"FACP",
                    "FADT GPE register width exceeds Generic Address Structure capacity",
                )
            })?;
            if address.bit_width != 0 && address.bit_width != expected_width {
                return Err(table_encoding_error(
                    *b"FACP",
                    "FADT GPE Generic Address Structure width disagrees with block length",
                ));
            }
            address
        }
        _ => {
            let address = u64::from(read_u32(bytes, legacy_address_offset)?);
            if address == 0 {
                return Err(AcpiError::table(
                    AcpiErrorKind::InvalidAddress,
                    *b"FACP",
                    "FADT declares a GPE register block without an address",
                ));
            }
            GenericAddress {
                address_space: GenericAddressSpace::SystemIo,
                bit_width: 0,
                bit_offset: 0,
                access_size: RegisterAccessSize::Byte,
                address,
            }
        }
    };

    Ok(Some(GpeRegisterBlock {
        address,
        register_bytes,
        base_number,
    }))
}

fn parse_generic_address(bytes: &[u8]) -> Result<GenericAddress, AcpiError> {
    if bytes.len() != GENERIC_ADDRESS_LENGTH {
        return Err(table_length_error(
            *b"FACP",
            "FADT Generic Address Structure is truncated",
        ));
    }
    Ok(GenericAddress {
        address_space: GenericAddressSpace::from(bytes[0]),
        bit_width: bytes[1],
        bit_offset: bytes[2],
        access_size: RegisterAccessSize::parse(bytes[3])?,
        address: read_u64(bytes, 4)?,
    })
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

fn table_encoding_error(signature: [u8; 4], detail: &'static str) -> AcpiError {
    AcpiError::table(AcpiErrorKind::InvalidEncoding, signature, detail)
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

    #[test]
    fn fadt_prefers_extended_gpe_registers_and_preserves_sparse_numbering() {
        let mut bytes = alloc::vec![0u8; 244];
        bytes[0..4].copy_from_slice(b"FACP");
        bytes[FADT_SCI_INTERRUPT_OFFSET..FADT_SCI_INTERRUPT_OFFSET + 2]
            .copy_from_slice(&9u16.to_le_bytes());
        bytes[FADT_GPE0_BLOCK_OFFSET..FADT_GPE0_BLOCK_OFFSET + 4]
            .copy_from_slice(&0x1020u32.to_le_bytes());
        bytes[FADT_GPE1_BLOCK_OFFSET..FADT_GPE1_BLOCK_OFFSET + 4]
            .copy_from_slice(&0x1040u32.to_le_bytes());
        bytes[FADT_GPE0_LENGTH_OFFSET] = 8;
        bytes[FADT_GPE1_LENGTH_OFFSET] = 4;
        bytes[FADT_GPE1_BASE_OFFSET] = 64;
        bytes[FADT_X_GPE0_BLOCK_OFFSET] = 1;
        bytes[FADT_X_GPE0_BLOCK_OFFSET + 1] = 64;
        bytes[FADT_X_GPE0_BLOCK_OFFSET + 3] = 1;
        bytes[FADT_X_GPE0_BLOCK_OFFSET + 4..FADT_X_GPE0_BLOCK_OFFSET + 12]
            .copy_from_slice(&0x2020u64.to_le_bytes());

        let fixed = parse_fadt_fixed_events(&bytes).unwrap();
        assert_eq!(fixed.sci_interrupt, 9);
        assert_eq!(fixed.gpe_blocks.len(), 2);
        assert_eq!(
            fixed.gpe_blocks[0],
            GpeRegisterBlock {
                address: GenericAddress {
                    address_space: GenericAddressSpace::SystemIo,
                    bit_width: 64,
                    bit_offset: 0,
                    access_size: RegisterAccessSize::Byte,
                    address: 0x2020,
                },
                register_bytes: 4,
                base_number: 0,
            }
        );
        assert_eq!(fixed.gpe_blocks[1].base_number, 64);
        assert_eq!(fixed.gpe_blocks[1].address.address, 0x1040);
    }

    #[test]
    fn fadt_rejects_overlapping_gpe_number_spaces() {
        let mut bytes = alloc::vec![0u8; 95];
        bytes[FADT_GPE0_BLOCK_OFFSET..FADT_GPE0_BLOCK_OFFSET + 4]
            .copy_from_slice(&0x1020u32.to_le_bytes());
        bytes[FADT_GPE1_BLOCK_OFFSET..FADT_GPE1_BLOCK_OFFSET + 4]
            .copy_from_slice(&0x1040u32.to_le_bytes());
        bytes[FADT_GPE0_LENGTH_OFFSET] = 8;
        bytes[FADT_GPE1_LENGTH_OFFSET] = 4;
        bytes[FADT_GPE1_BASE_OFFSET] = 16;

        assert_eq!(
            parse_fadt_fixed_events(&bytes).unwrap_err().kind,
            AcpiErrorKind::InvalidEncoding
        );
    }

    #[test]
    fn madt_rejects_reserved_interrupt_override_encoding() {
        let mut bytes = alloc::vec![0u8; 54];
        bytes[0..4].copy_from_slice(b"APIC");
        bytes[44] = 2;
        bytes[45] = 10;
        bytes[52..54].copy_from_slice(&0b10u16.to_le_bytes());

        assert_eq!(
            parse_madt(&bytes).unwrap_err().kind,
            AcpiErrorKind::InvalidEncoding
        );
    }

    #[test]
    fn nfit_identifies_only_the_persistent_memory_guid() {
        let mut bytes = alloc::vec![0u8; 96];
        bytes[0..4].copy_from_slice(b"NFIT");
        bytes[40..42].copy_from_slice(&0u16.to_le_bytes());
        bytes[42..44].copy_from_slice(&56u16.to_le_bytes());
        bytes[44..46].copy_from_slice(&7u16.to_le_bytes());
        bytes[46..48].copy_from_slice(&(1u16 << 1).to_le_bytes());
        bytes[52..56].copy_from_slice(&3u32.to_le_bytes());
        bytes[56..72].copy_from_slice(&[
            0x79, 0xd3, 0xf0, 0x66, 0xf3, 0xb4, 0x74, 0x40, 0xac, 0x43, 0x0d, 0x33, 0x18, 0xb7,
            0x8c, 0xdb,
        ]);
        bytes[72..80].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x20_0000u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&0x8008u64.to_le_bytes());

        assert_eq!(
            parse_nfit_spa_ranges(&bytes).unwrap(),
            [NfitSpaRange {
                index: 7,
                proximity_domain: Some(3),
                kind: NfitSpaKind::ByteAddressablePersistentMemory,
                base: 0x1_0000_0000,
                length: 0x20_0000,
                memory_attributes: 0x8008,
            }]
        );
    }

    #[test]
    fn nfit_rejects_truncated_spa_structure() {
        let mut bytes = alloc::vec![0u8; 44];
        bytes[0..4].copy_from_slice(b"NFIT");
        bytes[40..42].copy_from_slice(&0u16.to_le_bytes());
        bytes[42..44].copy_from_slice(&56u16.to_le_bytes());

        assert_eq!(
            parse_nfit_spa_ranges(&bytes).unwrap_err().kind,
            AcpiErrorKind::InvalidLength
        );
    }
}
