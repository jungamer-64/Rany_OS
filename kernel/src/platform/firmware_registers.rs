//! Firmware declarations admit register ranges before deferred execution.
//! Fixed registers and overlapping AML regions borrow the same retained bank.
//! Interrupt-safe serialization covers read/modify/write operations, not polls.

use crate::sync::IrqMutex;
use acpi_driver::AmlError;
use acpi_driver::aml::{AmlObject, OperationRegionHandler, OperationRegionSpace};
use acpi_driver::power::{FixedRegister, PowerRegisterDescription};
use acpi_driver::{AcpiRuntime, FixedEventDescription, GenericAddress, GenericAddressSpace};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegisterError {
    InvalidRange,
    UnsupportedSpace,
    NotDeclared,
    ResourceConflict,
    MetadataAllocation,
    Io(hal::IoPortError),
    Memory(kernel_api::mmio::MmioAcquireError),
    Access(hal::MmioAccessError),
}

#[derive(Clone, Copy)]
struct Span {
    space: GenericAddressSpace,
    base: u64,
    end: u64,
}

impl Span {
    fn new(space: GenericAddressSpace, base: u64, length: u64) -> Result<Self, RegisterError> {
        if length == 0 {
            return Err(RegisterError::InvalidRange);
        }
        let end = base
            .checked_add(length)
            .ok_or(RegisterError::InvalidRange)?;
        if space == GenericAddressSpace::SystemIo && (base == 0 || end > 0x1_0000) {
            return Err(RegisterError::InvalidRange);
        }
        Ok(Self { space, base, end })
    }
    fn contains(self, other: Self) -> bool {
        self.space == other.space && self.base <= other.base && other.end <= self.end
    }
}

/// Only this module can construct a claim, from the immutable runtime catalog
/// and namespace. MMIO admission separately checks RAM, cache policy and claims.
pub(crate) struct FirmwareMemoryClaim {
    runtime: &'static AcpiRuntime,
    span: Span,
}
impl FirmwareMemoryClaim {
    pub(crate) fn range(&self) -> (u64, usize) {
        (
            self.span.base,
            usize::try_from(self.span.end - self.span.base)
                .expect("firmware memory span was validated against usize"),
        )
    }
    pub(crate) fn retained_source(&self) -> &'static (dyn Send + Sync) {
        self.runtime
    }
}

enum RegisterBacking {
    Io(hal::IoPortRange),
    Memory(hal::MappedMmio),
    Unavailable(RegisterError),
}
struct BankRegion {
    span: Span,
    backing: RegisterBacking,
}

pub(crate) struct FirmwareRegisters {
    _runtime: &'static AcpiRuntime,
    declarations: Vec<Span>,
    regions: IrqMutex<Vec<BankRegion>>,
}

/// A retained read capability for the FADT's free-running PM counter. Its
/// register bank and width were admitted before publication; it cannot write
/// power registers or recover their owner's wider authority.
pub(crate) struct FirmwareTimer {
    bank: &'static FirmwareRegisters,
    address: GenericAddress,
    mask: u32,
}

impl FirmwareTimer {
    pub(crate) fn mask(&self) -> u32 {
        self.mask
    }

    pub(crate) fn read(&self) -> u32 {
        self.bank
            .read(self.address, 4)
            .expect("the immutable firmware bank retains this admitted counter") as u32
            & self.mask
    }
}

impl FirmwareRegisters {
    pub(crate) fn timer(
        &'static self,
        power: &PowerRegisterDescription,
    ) -> Result<Option<FirmwareTimer>, RegisterError> {
        let Some(register) = power.timer else {
            return Ok(None);
        };
        let address = fixed_address(register, 0);
        self.validate(address, 4)?;
        Ok(Some(FirmwareTimer {
            bank: self,
            address,
            mask: if power.timer_32bit {
                u32::MAX
            } else {
                0x00ff_ffff
            },
        }))
    }

    pub(crate) fn acquire(
        runtime: &'static AcpiRuntime,
        fixed: &FixedEventDescription,
        power: Option<&PowerRegisterDescription>,
    ) -> Result<Self, RegisterError> {
        let namespace_count = runtime
            .namespace()
            .map_or(0, |namespace| namespace.iter().count());
        let mut declarations = Vec::new();
        declarations
            .try_reserve_exact(
                namespace_count
                    .checked_add(10)
                    .ok_or(RegisterError::MetadataAllocation)?,
            )
            .map_err(|_| RegisterError::MetadataAllocation)?;
        // LOOP_PROOF: mode=bounded; reason=The FADT describes at most two finite GPE blocks.;
        for block in &fixed.gpe_blocks {
            declarations.push(Span::new(
                block.address.address_space,
                block.address.address,
                u64::from(block.register_bytes) * 2,
            )?);
        }
        if let Some(power) = power {
            // LOOP_PROOF: mode=bounded; reason=The decoded fixed power description contains at most eight ranges.;
            for block in power.ranges() {
                let address = block.address();
                declarations.push(Span::new(
                    address.address_space,
                    address.address,
                    u64::from(block.bytes()),
                )?);
            }
        }
        if let Some(namespace) = runtime.namespace() {
            // LOOP_PROOF: mode=bounded; reason=The immutable AML namespace has a finite object count.;
            for (_, object) in namespace.iter() {
                if let AmlObject::OperationRegion(region) = object {
                    let space = match region.space {
                        OperationRegionSpace::SystemIo => GenericAddressSpace::SystemIo,
                        OperationRegionSpace::SystemMemory => GenericAddressSpace::SystemMemory,
                        _ => continue,
                    };
                    let Ok(span) = Span::new(space, region.offset, region.length) else {
                        continue;
                    };
                    // Architecture registers belong to their platform driver,
                    // not to an AML byte-address declaration. Unsupported AML
                    // regions remain inaccessible without disabling other work.
                    if architecture_io_conflict(span) {
                        continue;
                    }
                    declarations.push(span);
                }
            }
        }
        for span in &declarations {
            if architecture_io_conflict(*span)
                && !power.is_some_and(|description| {
                    description.reset.is_some_and(|(reset, _)| {
                        reset.address().address_space == GenericAddressSpace::SystemIo
                            && reset.address().address == 0xcf9
                            && reset.bytes() == 1
                            && span.base == 0xcf9
                            && span.end == 0xcfa
                    })
                })
            {
                return Err(RegisterError::ResourceConflict);
            }
        }
        let mut merged = Vec::new();
        merged
            .try_reserve_exact(declarations.len())
            .map_err(|_| RegisterError::MetadataAllocation)?;
        merged.extend(declarations.iter().copied());
        merged.sort_unstable_by_key(|span| (space_key(span.space), span.base));
        let mut count = 0usize;
        // LOOP_PROOF: mode=bounded; reason=Each immutable declaration is visited once while overlapping ranges are merged in place.;
        for index in 0..merged.len() {
            let span = merged[index];
            if count != 0
                && merged[count - 1].space == span.space
                && span.base < merged[count - 1].end
            {
                merged[count - 1].end = merged[count - 1].end.max(span.end);
            } else {
                merged[count] = span;
                count += 1;
            }
        }
        merged.truncate(count);
        let mut regions = Vec::new();
        regions
            .try_reserve_exact(count)
            .map_err(|_| RegisterError::MetadataAllocation)?;
        // LOOP_PROOF: mode=bounded; reason=Each merged firmware register span receives one retained backing or a typed admission failure.;
        for span in merged {
            let backing = match span.space {
                GenericAddressSpace::SystemIo => {
                    let base = u16::try_from(span.base).map_err(|_| RegisterError::InvalidRange)?;
                    let length = u16::try_from(span.end - span.base)
                        .map_err(|_| RegisterError::InvalidRange)?;
                    // SAFETY: this bank is constructed once from firmware-owned
                    // fixed registers and immutable OperationRegion declarations.
                    // Overlaps share one range, architecture-owned ports are
                    // excluded, all accesses hold its IRQ lock, and the platform
                    // has no firmware-register reassignment path. RESET_REG's
                    // CF9 byte command does not alias CF8/CFC PCI operations.
                    match unsafe { hal::IoPortRange::from_raw_parts(base, length) } {
                        Ok(ports) => RegisterBacking::Io(ports),
                        Err(error) => RegisterBacking::Unavailable(RegisterError::Io(error)),
                    }
                }
                GenericAddressSpace::SystemMemory => {
                    usize::try_from(span.end - span.base)
                        .map_err(|_| RegisterError::InvalidRange)?;
                    let claim = FirmwareMemoryClaim { runtime, span };
                    match crate::resource_registry::mmio::acquire_firmware_registers(&claim) {
                        Ok(mapping) => RegisterBacking::Memory(mapping),
                        Err(error) => RegisterBacking::Unavailable(RegisterError::Memory(error)),
                    }
                }
                _ => RegisterBacking::Unavailable(RegisterError::UnsupportedSpace),
            };
            regions.push(BankRegion { span, backing });
        }
        Ok(Self {
            _runtime: runtime,
            declarations,
            regions: IrqMutex::new(regions),
        })
    }

    pub(crate) fn validate(
        &self,
        address: GenericAddress,
        bytes: usize,
    ) -> Result<(), RegisterError> {
        self.access(address, bytes, |backing, offset| {
            validate_access(backing, offset, bytes)
        })
    }

    pub(crate) fn read(&self, address: GenericAddress, bytes: usize) -> Result<u64, RegisterError> {
        self.access(address, bytes, |backing, offset| {
            read(backing, offset, bytes)
        })
    }
    pub(crate) fn write(
        &self,
        address: GenericAddress,
        bytes: usize,
        value: u64,
    ) -> Result<(), RegisterError> {
        if bytes < 8 && value >= (1u64 << (bytes * 8)) {
            return Err(RegisterError::InvalidRange);
        }
        self.access(address, bytes, |backing, offset| {
            write(backing, offset, bytes, value)
        })
    }
    pub(crate) fn modify(
        &self,
        address: GenericAddress,
        bytes: usize,
        update: impl FnOnce(u64) -> u64,
    ) -> Result<(), RegisterError> {
        self.access(address, bytes, |backing, offset| {
            let value = update(read(backing, offset, bytes)?);
            write(backing, offset, bytes, value)
        })
    }

    fn access<R>(
        &self,
        address: GenericAddress,
        bytes: usize,
        action: impl FnOnce(&RegisterBacking, usize) -> Result<R, RegisterError>,
    ) -> Result<R, RegisterError> {
        if !matches!(bytes, 1 | 2 | 4 | 8) {
            return Err(RegisterError::InvalidRange);
        }
        let span = Span::new(address.address_space, address.address, bytes as u64)?;
        if !self
            .declarations
            .iter()
            .any(|declaration| declaration.contains(span))
        {
            return Err(RegisterError::NotDeclared);
        }
        let regions = self.regions.lock();
        let region = regions
            .iter()
            .find(|region| region.span.contains(span))
            .ok_or(RegisterError::NotDeclared)?;
        if let RegisterBacking::Unavailable(error) = &region.backing {
            return Err(*error);
        }
        let offset = usize::try_from(span.base - region.span.base)
            .map_err(|_| RegisterError::InvalidRange)?;
        action(&region.backing, offset)
    }

    fn aml_address(
        &self,
        space: OperationRegionSpace,
        base: u64,
        length: u64,
        offset: u64,
        width: u8,
    ) -> Result<(GenericAddress, usize), AmlError> {
        let space = match space {
            OperationRegionSpace::SystemIo => GenericAddressSpace::SystemIo,
            OperationRegionSpace::SystemMemory => GenericAddressSpace::SystemMemory,
            _ => {
                return Err(AmlError::operation_region(
                    "AML address space is unsupported",
                ));
            }
        };
        let declaration = Span::new(space, base, length).map_err(aml_error)?;
        if architecture_io_conflict(declaration) {
            return Err(aml_error(RegisterError::ResourceConflict));
        }
        // Exact immutable declaration identity is checked before attenuation.
        if !self
            .declarations
            .iter()
            .any(|entry| entry.space == space && entry.base == base && entry.end == declaration.end)
        {
            return Err(AmlError::operation_region(
                "AML region is not retained by the firmware register owner",
            ));
        }
        if !matches!(width, 8 | 16 | 32 | 64) {
            return Err(aml_error(RegisterError::InvalidRange));
        }
        let bytes = usize::from(width / 8);
        if offset
            .checked_add(bytes as u64)
            .is_none_or(|end| end > length)
        {
            return Err(aml_error(RegisterError::InvalidRange));
        }
        let address = base
            .checked_add(offset)
            .ok_or_else(|| aml_error(RegisterError::InvalidRange))?;
        Ok((
            GenericAddress {
                address_space: space,
                address,
                bit_width: width,
                bit_offset: 0,
                access_size: acpi_driver::RegisterAccessSize::Undefined,
            },
            bytes,
        ))
    }
}

impl OperationRegionHandler for FirmwareRegisters {
    fn read(
        &self,
        space: OperationRegionSpace,
        base: u64,
        length: u64,
        offset: u64,
        width: u8,
    ) -> Result<u64, AmlError> {
        let (address, bytes) = self.aml_address(space, base, length, offset, width)?;
        self.read(address, bytes).map_err(aml_error)
    }
    fn write(
        &self,
        space: OperationRegionSpace,
        base: u64,
        length: u64,
        offset: u64,
        width: u8,
        value: u64,
    ) -> Result<(), AmlError> {
        let (address, bytes) = self.aml_address(space, base, length, offset, width)?;
        self.write(address, bytes, value).map_err(aml_error)
    }
}

pub(crate) fn fixed_address(register: FixedRegister, offset: usize) -> GenericAddress {
    let mut address = register.address();
    address.address = address
        .address
        .checked_add(offset as u64)
        .expect("fixed register offset was bounded during admission");
    address
}

// Fixed PC register assignments are external hardware coordinates. Firmware
// cannot reassign PIC, PIT, RTC, 8042, legacy IDE, UART or PCI configuration
// access to an AML worker. RESET_REG at CF9 is a separate byte command in the
// chipset protocol, whereas the PCI owner emits only CF8/CFC dword operations.
fn architecture_io_conflict(span: Span) -> bool {
    if span.space != GenericAddressSpace::SystemIo {
        return false;
    }
    const PLATFORM_RANGES: &[(u64, u64)] = &[
        (0x00, 0x22),
        (0x40, 0x44),
        (0x60, 0x62),
        (0x64, 0x65),
        (0x70, 0x72),
        (0x80, 0x90),
        (0xc0, 0xe0),
        (0xa0, 0xa2),
        (0xf4, 0xf8),
        (0x170, 0x178),
        (0x1f0, 0x1f8),
        (0x278, 0x280),
        (0x2e8, 0x2f0),
        (0x2f8, 0x300),
        (0x376, 0x377),
        (0x378, 0x380),
        (0x3e8, 0x3f0),
        (0x3f6, 0x3f7),
        (0x3f8, 0x400),
        (0xcf8, 0xd00),
    ];
    PLATFORM_RANGES
        .iter()
        .any(|&(base, end)| span.base < end && base < span.end)
}

fn validate_access(
    backing: &RegisterBacking,
    offset: usize,
    bytes: usize,
) -> Result<(), RegisterError> {
    match backing {
        RegisterBacking::Io(ports) => {
            let offset = u16::try_from(offset).map_err(|_| RegisterError::InvalidRange)?;
            match bytes {
                1 => {
                    ports.port::<u8>(offset).map_err(RegisterError::Io)?;
                }
                2 => {
                    ports.port::<u16>(offset).map_err(RegisterError::Io)?;
                }
                4 => {
                    ports.port::<u32>(offset).map_err(RegisterError::Io)?;
                }
                _ => return Err(RegisterError::UnsupportedSpace),
            }
        }
        RegisterBacking::Memory(mapping) => match bytes {
            1 => {
                mapping
                    .region()
                    .read_only::<u8>(offset)
                    .map_err(RegisterError::Access)?;
            }
            2 => {
                mapping
                    .region()
                    .read_only::<u16>(offset)
                    .map_err(RegisterError::Access)?;
            }
            4 => {
                mapping
                    .region()
                    .read_only::<u32>(offset)
                    .map_err(RegisterError::Access)?;
            }
            8 => {
                mapping
                    .region()
                    .read_only::<u64>(offset)
                    .map_err(RegisterError::Access)?;
            }
            _ => return Err(RegisterError::InvalidRange),
        },
        RegisterBacking::Unavailable(error) => return Err(*error),
    }
    Ok(())
}

fn read(backing: &RegisterBacking, offset: usize, bytes: usize) -> Result<u64, RegisterError> {
    match backing {
        RegisterBacking::Io(ports) => {
            let offset = u16::try_from(offset).map_err(|_| RegisterError::InvalidRange)?;
            match bytes {
                1 => Ok(u64::from(
                    ports.port::<u8>(offset).map_err(RegisterError::Io)?.read(),
                )),
                2 => Ok(u64::from(
                    ports.port::<u16>(offset).map_err(RegisterError::Io)?.read(),
                )),
                4 => Ok(u64::from(
                    ports.port::<u32>(offset).map_err(RegisterError::Io)?.read(),
                )),
                _ => Err(RegisterError::UnsupportedSpace),
            }
        }
        RegisterBacking::Memory(mapping) => match bytes {
            1 => Ok(u64::from(
                mapping
                    .region()
                    .read_only::<u8>(offset)
                    .map_err(RegisterError::Access)?
                    .read(),
            )),
            2 => Ok(u64::from(
                mapping
                    .region()
                    .read_only::<u16>(offset)
                    .map_err(RegisterError::Access)?
                    .read(),
            )),
            4 => Ok(u64::from(
                mapping
                    .region()
                    .read_only::<u32>(offset)
                    .map_err(RegisterError::Access)?
                    .read(),
            )),
            8 => Ok(mapping
                .region()
                .read_only::<u64>(offset)
                .map_err(RegisterError::Access)?
                .read()),
            _ => Err(RegisterError::InvalidRange),
        },
        RegisterBacking::Unavailable(error) => Err(*error),
    }
}
fn write(
    backing: &RegisterBacking,
    offset: usize,
    bytes: usize,
    value: u64,
) -> Result<(), RegisterError> {
    match backing {
        RegisterBacking::Io(ports) => {
            let offset = u16::try_from(offset).map_err(|_| RegisterError::InvalidRange)?;
            match bytes {
                1 => ports
                    .port::<u8>(offset)
                    .map_err(RegisterError::Io)?
                    .write(u8::try_from(value).map_err(|_| RegisterError::InvalidRange)?),
                2 => ports
                    .port::<u16>(offset)
                    .map_err(RegisterError::Io)?
                    .write(u16::try_from(value).map_err(|_| RegisterError::InvalidRange)?),
                4 => ports
                    .port::<u32>(offset)
                    .map_err(RegisterError::Io)?
                    .write(u32::try_from(value).map_err(|_| RegisterError::InvalidRange)?),
                _ => return Err(RegisterError::UnsupportedSpace),
            }
        }
        RegisterBacking::Memory(mapping) => match bytes {
            1 => mapping
                .region()
                .write_only::<u8>(offset)
                .map_err(RegisterError::Access)?
                .write(u8::try_from(value).map_err(|_| RegisterError::InvalidRange)?),
            2 => mapping
                .region()
                .write_only::<u16>(offset)
                .map_err(RegisterError::Access)?
                .write(u16::try_from(value).map_err(|_| RegisterError::InvalidRange)?),
            4 => mapping
                .region()
                .write_only::<u32>(offset)
                .map_err(RegisterError::Access)?
                .write(u32::try_from(value).map_err(|_| RegisterError::InvalidRange)?),
            8 => mapping
                .region()
                .write_only::<u64>(offset)
                .map_err(RegisterError::Access)?
                .write(value),
            _ => return Err(RegisterError::InvalidRange),
        },
        RegisterBacking::Unavailable(error) => return Err(*error),
    }
    Ok(())
}
fn space_key(space: GenericAddressSpace) -> u16 {
    match space {
        GenericAddressSpace::SystemMemory => 0,
        GenericAddressSpace::SystemIo => 1,
        GenericAddressSpace::Other(value) => 256 + u16::from(value),
    }
}
fn aml_error(error: RegisterError) -> AmlError {
    AmlError::operation_region(alloc::format!("firmware register access failed: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_port_width_and_address_domain_are_retained() {
        let grant = Span::new(GenericAddressSpace::SystemIo, 0xfffe, 2).unwrap();
        assert!(grant.contains(Span::new(GenericAddressSpace::SystemIo, 0xffff, 1).unwrap()));
        assert!(Span::new(GenericAddressSpace::SystemIo, 0xffff, 2).is_err());
        assert!(!grant.contains(Span::new(GenericAddressSpace::SystemMemory, 0xfffe, 2).unwrap()));
        assert!(Span::new(GenericAddressSpace::SystemMemory, u64::MAX, 1).is_err());
    }
    #[test]
    fn cpu_firmware_port_is_distinct_from_platform_configuration() {
        assert!(!architecture_io_conflict(
            Span::new(GenericAddressSpace::SystemIo, 0xcd8, 12).unwrap()
        ));
        assert!(architecture_io_conflict(
            Span::new(GenericAddressSpace::SystemIo, 0xcf8, 4).unwrap()
        ));
        assert!(architecture_io_conflict(
            Span::new(GenericAddressSpace::SystemIo, 0x60, 1).unwrap()
        ));
    }
}
