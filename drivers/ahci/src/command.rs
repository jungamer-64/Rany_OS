//! Validated non-NCQ ATA commands and their AHCI wire encoding.
//!
//! Only the port publishes these bytes. In particular, a numeric address is
//! never sufficient to construct a public submission descriptor.

#![forbid(unsafe_code)]

use kernel_api::dma::{DmaDescriptor, DmaDeviceAddress, DmaDirection};

pub(crate) const COMMAND_LIST_BYTES: usize = 1024;
pub(crate) const RECEIVED_FIS_OFFSET: usize = COMMAND_LIST_BYTES;
pub(crate) const COMMAND_TABLE_OFFSET: usize = RECEIVED_FIS_OFFSET + 256;
pub(crate) const COMMAND_TABLE_DWORDS: usize = 36;
/// Required logical size of the port's single, registry-owned metadata region.
pub const PORT_DMA_BYTES: usize = COMMAND_TABLE_OFFSET + COMMAND_TABLE_DWORDS * 4;
const MAX_PRD_BYTES: usize = 1 << 22;
const SECTOR_BYTES: usize = 512;

/// The address width advertised by the HBA's CAP.S64A bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaAddressWidth {
    Bits32,
    Bits64,
}

impl DmaAddressWidth {
    pub(crate) fn validate(
        self,
        address: DmaDeviceAddress,
        bytes: usize,
        alignment: u64,
    ) -> Result<(), CommandError> {
        if !address.get().is_multiple_of(alignment) {
            return Err(CommandError::AddressAlignment);
        }
        let last = address
            .checked_add(bytes.checked_sub(1).ok_or(CommandError::ByteCount)?)
            .ok_or(CommandError::AddressOverflow)?;
        if self == Self::Bits32 && last.get() > u64::from(u32::MAX) {
            return Err(CommandError::AddressWidth);
        }
        Ok(())
    }
}

/// Validation failures have no device effect and do not consume a DMA lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    SectorCount,
    LbaRange,
    ByteCount,
    BufferTooSmall,
    Direction,
    AddressAlignment,
    AddressOverflow,
    AddressWidth,
}

/// A validated ATA data command, independent of any DMA allocation.
///
/// The port serializes non-NCQ commands so that task-file errors cannot be
/// attributed to a different request. One PRD limits each request to 4 MiB;
/// callers must split larger I/O before submission, not truncate its encoding.
#[derive(Clone, Copy, Debug)]
pub struct AtaCommand {
    fis: [u8; 20],
    direction: DmaDirection,
    bytes: usize,
}

impl AtaCommand {
    /// IDENTIFY returns exactly one 512-byte sector.
    pub const fn identify() -> Self {
        let mut fis = [0; 20];
        fis[0] = 0x27;
        fis[1] = 0x80;
        fis[2] = 0xec;
        Self {
            fis,
            direction: DmaDirection::FromDevice,
            bytes: SECTOR_BYTES,
        }
    }

    /// # Errors
    /// Rejects zero/oversized transfers and spans outside the 48-bit LBA space.
    pub fn read(lba: u64, sectors: u32) -> Result<Self, CommandError> {
        Self::data(lba, sectors, DmaDirection::FromDevice)
    }

    /// # Errors
    /// Rejects zero/oversized transfers and spans outside the 48-bit LBA space.
    pub fn write(lba: u64, sectors: u32) -> Result<Self, CommandError> {
        Self::data(lba, sectors, DmaDirection::ToDevice)
    }

    fn data(lba: u64, sectors: u32, direction: DmaDirection) -> Result<Self, CommandError> {
        if sectors == 0 || sectors > (MAX_PRD_BYTES / SECTOR_BYTES) as u32 {
            return Err(CommandError::SectorCount);
        }
        if lba
            .checked_add(u64::from(sectors) - 1)
            .is_none_or(|last| last >= 1 << 48)
        {
            return Err(CommandError::LbaRange);
        }
        let mut fis = [0; 20];
        fis[0] = 0x27;
        fis[1] = 0x80;
        fis[2] = if direction == DmaDirection::ToDevice {
            0x35
        } else {
            0x25
        };
        let address = lba.to_le_bytes();
        fis[4..7].copy_from_slice(&address[..3]);
        fis[7] = 0x40;
        fis[8..11].copy_from_slice(&address[3..6]);
        fis[12..14].copy_from_slice(&(sectors as u16).to_le_bytes());
        Ok(Self {
            fis,
            direction,
            bytes: sectors as usize * SECTOR_BYTES,
        })
    }

    pub const fn byte_count(self) -> usize {
        self.bytes
    }
    pub const fn direction(self) -> DmaDirection {
        self.direction
    }

    pub(crate) fn validate_buffer(
        self,
        bytes: usize,
        direction: DmaDirection,
    ) -> Result<(), CommandError> {
        if bytes < self.bytes {
            return Err(CommandError::BufferTooSmall);
        }
        if direction != self.direction {
            return Err(CommandError::Direction);
        }
        Ok(())
    }

    pub(crate) fn encode(
        self,
        data: &DmaDescriptor<'_>,
        table: DmaDeviceAddress,
        address_width: DmaAddressWidth,
    ) -> Result<EncodedCommand, CommandError> {
        if data.byte_count().get() < self.bytes {
            return Err(CommandError::BufferTooSmall);
        }
        address_width.validate(table, COMMAND_TABLE_DWORDS * 4, 128)?;
        let prd = encode_prd(data.device_address(), self.bytes, address_width)?;
        Ok(self.wire_image(table, prd))
    }

    fn wire_image(self, table: DmaDeviceAddress, prd: [u32; 4]) -> EncodedCommand {
        let mut encoded = EncodedCommand {
            header: [0; 8],
            table: [0; COMMAND_TABLE_DWORDS],
        };
        // AHCI 1.3.1 sections 4.2.2/4.2.3: CFL=5, PRDTL=1, W for host-to-device.
        encoded.header[0] = 5 | (1 << 16);
        if self.direction == DmaDirection::ToDevice {
            encoded.header[0] |= 1 << 6;
        }
        encoded.header[2] = table.get() as u32;
        encoded.header[3] = (table.get() >> 32) as u32;
        for (word, bytes) in encoded.table[..5]
            .iter_mut()
            .zip(self.fis.as_chunks::<4>().0)
        {
            *word = u32::from_le_bytes(*bytes);
        }
        encoded.table[32..].copy_from_slice(&prd);
        encoded
    }
}

pub(crate) struct EncodedCommand {
    pub(crate) header: [u32; 8],
    pub(crate) table: [u32; COMMAND_TABLE_DWORDS],
}

fn encode_prd(
    address: DmaDeviceAddress,
    bytes: usize,
    address_width: DmaAddressWidth,
) -> Result<[u32; 4], CommandError> {
    if bytes == 0 || bytes > MAX_PRD_BYTES || !bytes.is_multiple_of(2) {
        return Err(CommandError::ByteCount);
    }
    address_width.validate(address, bytes, 2)?;
    // DBC is zero-based. No IOC: a PRD interrupt is not a command completion.
    Ok([
        address.get() as u32,
        (address.get() >> 32) as u32,
        0,
        (bytes - 1) as u32,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ata_wire_vector_preserves_full_lba_and_count() {
        let command = AtaCommand::read(0x1234_5678_9abc, 0x123).unwrap();
        assert_eq!(
            command.fis,
            [
                0x27, 0x80, 0x25, 0, 0xbc, 0x9a, 0x78, 0x40, 0x56, 0x34, 0x12, 0, 0x23, 0x01, 0, 0,
                0, 0, 0, 0
            ]
        );
        assert_eq!(command.byte_count(), 0x123 * 512);
        assert_eq!(AtaCommand::write(0, 1).unwrap().fis[2], 0x35);
        assert_eq!(AtaCommand::identify().fis[2], 0xec);
    }

    #[test]
    fn ata_span_and_single_prd_limit_are_checked() {
        assert!(matches!(
            AtaCommand::read(0, 0),
            Err(CommandError::SectorCount)
        ));
        assert!(AtaCommand::read(0, 8192).is_ok());
        assert!(matches!(
            AtaCommand::read(0, 8193),
            Err(CommandError::SectorCount)
        ));
        assert!(AtaCommand::read((1 << 48) - 1, 1).is_ok());
        assert!(matches!(
            AtaCommand::read((1 << 48) - 1, 2),
            Err(CommandError::LbaRange)
        ));
        assert!(matches!(
            AtaCommand::read(u64::MAX, 2),
            Err(CommandError::LbaRange)
        ));
    }

    #[test]
    fn prd_encoding_never_truncates_length_or_address() {
        let address = DmaDeviceAddress::from_abi(0x1234_5678_9000);
        assert_eq!(
            encode_prd(address, 512, DmaAddressWidth::Bits64).unwrap(),
            [0x5678_9000, 0x1234, 0, 511]
        );
        for size in [0, 1, 3, MAX_PRD_BYTES + 2] {
            assert_eq!(
                encode_prd(address, size, DmaAddressWidth::Bits64),
                Err(CommandError::ByteCount)
            );
        }
        assert_eq!(
            encode_prd(address, MAX_PRD_BYTES, DmaAddressWidth::Bits64).unwrap()[3],
            0x3f_ffff
        );
        assert_eq!(
            encode_prd(address, 512, DmaAddressWidth::Bits32),
            Err(CommandError::AddressWidth)
        );
        assert_eq!(
            encode_prd(DmaDeviceAddress::from_abi(3), 2, DmaAddressWidth::Bits64),
            Err(CommandError::AddressAlignment)
        );
        assert_eq!(
            encode_prd(
                DmaDeviceAddress::from_abi(u64::MAX - 1),
                4,
                DmaAddressWidth::Bits64
            ),
            Err(CommandError::AddressOverflow)
        );
        assert_eq!(
            encode_prd(
                DmaDeviceAddress::from_abi(0xffff_fffe),
                4,
                DmaAddressWidth::Bits32
            ),
            Err(CommandError::AddressWidth)
        );
    }

    #[test]
    fn buffer_direction_and_extent_must_match_command() {
        let command = AtaCommand::read(0, 1).unwrap();
        assert_eq!(
            command.validate_buffer(511, DmaDirection::FromDevice),
            Err(CommandError::BufferTooSmall)
        );
        assert_eq!(
            command.validate_buffer(512, DmaDirection::ToDevice),
            Err(CommandError::Direction)
        );
        assert_eq!(
            command.validate_buffer(512, DmaDirection::FromDevice),
            Ok(())
        );
    }

    #[test]
    fn header_and_table_wire_vector_zero_reserved_fields() {
        let image = AtaCommand::write(0x1234, 1).unwrap().wire_image(
            DmaDeviceAddress::from_abi(0x1234_5678_9580),
            [0x1000, 0, 0, 511],
        );
        assert_eq!(
            image.header,
            [0x0001_0045, 0, 0x5678_9580, 0x1234, 0, 0, 0, 0]
        );
        assert_eq!(image.table[..5], [0x0035_8027, 0x4000_1234, 0, 1, 0]);
        assert!(image.table[5..32].iter().all(|&word| word == 0));
        assert_eq!(image.table[32..], [0x1000, 0, 0, 511]);
    }
}
