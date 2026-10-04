//! Block configuration and command admission. Protocol sector coordinates are
//! always 512-byte units, independently of the host's preferred block size.
#![forbid(unsafe_code)]

use kernel_api::abi::driver::{
    AbiBlockCommandKind, AbiBlockCompletion, AbiBlockSubmission, AbiError,
};
use kernel_api::dma::{DmaDeviceAddress, DmaQueueIdentity};

use crate::defs::common_features::{VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1};
use crate::transport::{TransportError, VirtioTransport};

const SECTOR_BYTES: u32 = 512;
const SIZE_MAX: u64 = 1 << 1;
const SEG_MAX: u64 = 1 << 2;
const READ_ONLY: u64 = 1 << 5;
const BLOCK_SIZE: u64 = 1 << 6;
const FLUSH: u64 = 1 << 9;

/// Implemented features for one modern split request queue. Packed rings,
/// indirect descriptors and multiqueue are not part of this command protocol.
pub const BLOCK_SUPPORTED_FEATURES: u64 = VIRTIO_F_VERSION_1
    | VIRTIO_F_ACCESS_PLATFORM
    | SIZE_MAX
    | SEG_MAX
    | READ_ONLY
    | BLOCK_SIZE
    | FLUSH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockConfigurationError {
    Registers(TransportError),
    UnnegotiatedFeatures,
    EmptyCapacity,
    InvalidBlockSize,
    InvalidSegmentLimit,
    ConfigurationChanged,
}

/// A checked host geometry and the limits of one contiguous payload segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockGeometry {
    configuration_generation: u32,
    block_count: u64,
    block_size: u32,
    max_transfer_blocks: u16,
    read_only: bool,
    flush: bool,
}

impl BlockGeometry {
    /// Read one configuration generation after feature negotiation. Changes
    /// during the snapshot are returned to the lifecycle owner for retry.
    ///
    /// # Errors
    /// Rejects incomplete negotiation, unavailable registers, changing
    /// configuration, or geometry that cannot admit a whole host block.
    pub fn read(
        transport: &dyn VirtioTransport,
        negotiated: u64,
    ) -> Result<Self, BlockConfigurationError> {
        if negotiated & VIRTIO_F_VERSION_1 == 0
            || negotiated & !BLOCK_SUPPORTED_FEATURES != 0
            || transport.status() & crate::defs::status::VIRTIO_STATUS_FEATURES_OK == 0
        {
            return Err(BlockConfigurationError::UnnegotiatedFeatures);
        }
        let generation = transport.config_generation();
        let capacity = transport
            .read_config_u64(0)
            .map_err(BlockConfigurationError::Registers)?;
        let block_size = if negotiated & BLOCK_SIZE != 0 {
            transport
                .read_config_u32(20)
                .map_err(BlockConfigurationError::Registers)?
        } else {
            SECTOR_BYTES
        };
        let segment_bytes = if negotiated & SIZE_MAX != 0 {
            transport
                .read_config_u32(8)
                .map_err(BlockConfigurationError::Registers)?
        } else {
            u32::MAX - 1 // the read status byte also contributes to used.len
        };
        if negotiated & SEG_MAX != 0
            && transport
                .read_config_u32(12)
                .map_err(BlockConfigurationError::Registers)?
                == 0
        {
            return Err(BlockConfigurationError::InvalidSegmentLimit);
        }
        if generation != transport.config_generation() {
            return Err(BlockConfigurationError::ConfigurationChanged);
        }
        let mut geometry = Self::from_values(capacity, block_size, segment_bytes, negotiated)?;
        geometry.configuration_generation = generation;
        Ok(geometry)
    }

    fn from_values(
        capacity_sectors: u64,
        block_size: u32,
        segment_bytes: u32,
        features: u64,
    ) -> Result<Self, BlockConfigurationError> {
        if capacity_sectors == 0 {
            return Err(BlockConfigurationError::EmptyCapacity);
        }
        if block_size < SECTOR_BYTES || !block_size.is_power_of_two() {
            return Err(BlockConfigurationError::InvalidBlockSize);
        }
        let block_count = host_block_capacity(capacity_sectors, block_size)?;
        let transfer_blocks =
            (segment_bytes.min(u32::MAX - 1) / block_size).min(u32::from(u16::MAX));
        if transfer_blocks == 0 {
            return Err(BlockConfigurationError::InvalidSegmentLimit);
        }
        Ok(Self {
            configuration_generation: 0,
            block_count,
            block_size,
            max_transfer_blocks: transfer_blocks as u16,
            read_only: features & READ_ONLY != 0,
            flush: features & FLUSH != 0,
        })
    }

    pub const fn block_count(self) -> u64 {
        self.block_count
    }
    pub const fn block_size(self) -> u32 {
        self.block_size
    }
    pub const fn max_transfer_blocks(self) -> u16 {
        self.max_transfer_blocks
    }
    pub const fn read_only(self) -> bool {
        self.read_only
    }
    pub const fn supports_flush(self) -> bool {
        self.flush
    }

    // Capacity can change during operation. The generation is only an index
    // into the device configuration, and a failed snapshot leaves it unchanged.
    pub(crate) fn refresh_capacity(
        &mut self,
        transport: &dyn VirtioTransport,
    ) -> Result<(), BlockConfigurationError> {
        let generation = transport.config_generation();
        if generation == self.configuration_generation {
            return Ok(());
        }
        let capacity = transport
            .read_config_u64(0)
            .map_err(BlockConfigurationError::Registers)?;
        if generation != transport.config_generation() {
            return Err(BlockConfigurationError::ConfigurationChanged);
        }
        self.apply_capacity(generation, capacity)
    }

    fn apply_capacity(
        &mut self,
        generation: u32,
        capacity_sectors: u64,
    ) -> Result<(), BlockConfigurationError> {
        let block_count = host_block_capacity(capacity_sectors, self.block_size)?;
        self.block_count = block_count;
        self.configuration_generation = generation;
        Ok(())
    }

    pub(crate) fn admit(
        self,
        queue: DmaQueueIdentity,
        input: &AbiBlockSubmission,
    ) -> Result<BlockCommand, AbiError> {
        if input.request_id == 0 || input.generation != queue.generation() {
            return Err(AbiError::InvalidParam);
        }
        if input.command == AbiBlockCommandKind::Flush as u32 {
            if !self.flush {
                return Err(AbiError::NotSupported);
            }
            return if input.lba == 0
                && input.blocks == 0
                && input.bytes == 0
                && input.iova == 0
                && input.lease_id == 0
            {
                Ok(BlockCommand::Flush)
            } else {
                Err(AbiError::InvalidParam)
            };
        }
        let direction = match input.command {
            value if value == AbiBlockCommandKind::Read as u32 => BlockDirection::Read,
            value if value == AbiBlockCommandKind::Write as u32 => BlockDirection::Write,
            _ => return Err(AbiError::NotSupported),
        };
        if direction == BlockDirection::Write && self.read_only {
            return Err(AbiError::PermissionDenied);
        }
        let bytes = u32::from(input.blocks)
            .checked_mul(self.block_size)
            .ok_or(AbiError::InvalidSize)?;
        if input.blocks == 0
            || input.blocks > self.max_transfer_blocks
            || input
                .lba
                .checked_add(u64::from(input.blocks))
                .is_none_or(|end| end > self.block_count)
            || input.bytes != bytes as usize
            || input.iova == 0
            || input.lease_id == 0
            || input.iova.checked_add(u64::from(bytes)).is_none()
        {
            return Err(AbiError::InvalidParam);
        }
        let sector = SectorOffset::from_host_block(input.lba, self.block_size)?;
        Ok(BlockCommand::Transfer {
            direction,
            sector,
            bytes,
            address: DmaDeviceAddress::from_abi(input.iova),
        })
    }
}

fn host_block_capacity(
    capacity_sectors: u64,
    block_size: u32,
) -> Result<u64, BlockConfigurationError> {
    if capacity_sectors == 0 {
        return Err(BlockConfigurationError::EmptyCapacity);
    }
    let sectors_per_block = u64::from(block_size / SECTOR_BYTES);
    if !capacity_sectors.is_multiple_of(sectors_per_block) {
        return Err(BlockConfigurationError::InvalidBlockSize);
    }
    Ok(capacity_sectors / sectors_per_block)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockDirection {
    Read,
    Write,
}

/// The wire coordinate cannot be confused with the host's logical block index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SectorOffset(u64);

impl SectorOffset {
    fn from_host_block(block: u64, block_size: u32) -> Result<Self, AbiError> {
        block
            .checked_mul(u64::from(block_size / SECTOR_BYTES))
            .map(Self)
            .ok_or(AbiError::InvalidAddress)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BlockCommand {
    Transfer {
        direction: BlockDirection,
        sector: SectorOffset,
        bytes: u32,
        address: DmaDeviceAddress,
    },
    Flush,
}

impl BlockCommand {
    pub(crate) fn wire_header(&self) -> (u32, u64) {
        match self {
            Self::Transfer {
                direction: BlockDirection::Read,
                sector,
                ..
            } => (0, sector.0),
            Self::Transfer {
                direction: BlockDirection::Write,
                sector,
                ..
            } => (1, sector.0),
            Self::Flush => (4, 0),
        }
    }

    pub(crate) fn payload(&self) -> Option<(DmaDeviceAddress, u32, bool)> {
        match self {
            Self::Transfer {
                direction,
                bytes,
                address,
                ..
            } => Some((*address, *bytes, *direction == BlockDirection::Read)),
            Self::Flush => None,
        }
    }
}

/// An accepted operation's terminal route metadata. It neither owns nor grants
/// access to the payload mapping retained by the block service host.
#[derive(Debug)]
pub struct BlockNotification {
    pub(crate) slot: usize,
    request_id: u64,
    lease_id: u64,
    generation: u64,
    payload_bytes: usize,
    expected_written: u32,
}

impl BlockNotification {
    pub(crate) fn new(slot: usize, input: &AbiBlockSubmission, command: &BlockCommand) -> Self {
        let expected_written = match command.payload() {
            Some((_, bytes, true)) => bytes + 1,
            _ => 1,
        };
        Self {
            slot,
            request_id: input.request_id,
            lease_id: input.lease_id,
            generation: input.generation,
            payload_bytes: input.bytes,
            expected_written,
        }
    }

    /// Identity for the host's reset reconciliation, without fabricating a used
    /// entry or a DMA completion witness.
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub const fn lease_id(&self) -> u64 {
        self.lease_id
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn complete(self, written: u32, status: u8) -> AbiBlockCompletion {
        let status = match status {
            0 if written == self.expected_written => AbiError::Success,
            2 if written != 0 => AbiError::NotSupported,
            _ => AbiError::IoError,
        };
        AbiBlockCompletion {
            request_id: self.request_id,
            lease_id: self.lease_id,
            generation: self.generation,
            status: status as i32,
            bytes: if status == AbiError::Success {
                self.payload_bytes
            } else {
                0
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_api::abi::driver::PackedPciLocation;

    extern "C" fn activate(_: *mut core::ffi::c_void) -> i32 {
        AbiError::Success as i32
    }

    fn queue() -> DmaQueueIdentity {
        DmaQueueIdentity::new(PackedPciLocation::new(0, 0, 4, 0), 0, 37)
            .expect("fixture names one registered queue")
    }

    fn input() -> AbiBlockSubmission {
        AbiBlockSubmission {
            request_id: 19,
            command: AbiBlockCommandKind::Read as u32,
            lba: 2,
            blocks: 2,
            bytes: 8192,
            iova: 0x200000,
            lease_id: 11,
            generation: 37,
            activation: core::ptr::null_mut(),
            activate,
        }
    }

    #[test]
    fn host_blocks_convert_to_fixed_wire_sectors() {
        let geometry =
            BlockGeometry::from_values(8192, 4096, 65536, FLUSH).expect("fixture geometry");
        assert_eq!(geometry.block_count(), 1024);
        assert_eq!(geometry.max_transfer_blocks(), 16);
        let command = geometry.admit(queue(), &input()).expect("two whole blocks");
        assert_eq!(command.wire_header(), (0, 16));
        assert_eq!(
            command.payload(),
            Some((DmaDeviceAddress::from_abi(0x200000), 8192, true))
        );
        let default =
            BlockGeometry::from_values(8192, 512, u32::MAX, 0).expect("512-byte geometry");
        assert_eq!(default.block_count(), 8192);
    }

    #[test]
    fn capacity_extent_and_generation_are_admitted_before_activation() {
        let geometry = BlockGeometry::from_values(8192, 4096, 65536, 0).expect("fixture geometry");
        let mut submission = input();
        submission.lba = 1023;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::InvalidParam)
        );
        submission.lba = u64::MAX;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::InvalidParam)
        );
        submission = input();
        submission.iova = u64::MAX - 4095;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::InvalidParam)
        );
        submission = input();
        submission.generation += 1;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::InvalidParam)
        );
        submission = input();
        submission.blocks = 17;
        submission.bytes = 69632;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::InvalidParam)
        );
        submission.blocks = 0;
        submission.bytes = 0;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::InvalidParam)
        );
    }

    #[test]
    fn read_only_and_flush_have_distinct_protocols() {
        let geometry = BlockGeometry::from_values(8192, 4096, 65536, READ_ONLY | FLUSH)
            .expect("fixture geometry");
        let mut submission = input();
        submission.command = AbiBlockCommandKind::Write as u32;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::PermissionDenied)
        );
        submission.command = AbiBlockCommandKind::Flush as u32;
        submission.lba = 0;
        submission.blocks = 0;
        submission.bytes = 0;
        submission.iova = 0;
        submission.lease_id = 0;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Ok(BlockCommand::Flush)
        );
        submission.iova = 1;
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::InvalidParam)
        );
        submission.iova = 0;
        let without_flush =
            BlockGeometry::from_values(8192, 4096, 65536, 0).expect("fixture geometry");
        assert_eq!(
            without_flush.admit(queue(), &submission),
            Err(AbiError::NotSupported)
        );
    }

    #[test]
    fn invalid_geometry_and_segment_limits_cannot_register() {
        assert_eq!(
            BlockGeometry::from_values(0, 512, 4096, 0),
            Err(BlockConfigurationError::EmptyCapacity)
        );
        assert_eq!(
            BlockGeometry::from_values(8192, 768, 4096, 0),
            Err(BlockConfigurationError::InvalidBlockSize)
        );
        assert_eq!(
            BlockGeometry::from_values(8193, 4096, 65536, 0),
            Err(BlockConfigurationError::InvalidBlockSize)
        );
        assert_eq!(
            BlockGeometry::from_values(8192, 4096, 2048, 0),
            Err(BlockConfigurationError::InvalidSegmentLimit)
        );
    }

    #[test]
    fn shrinking_capacity_changes_admission_without_resetting_units() {
        let mut geometry =
            BlockGeometry::from_values(8192, 4096, 65536, 0).expect("fixture geometry");
        let mut submission = input();
        submission.lba = 510;
        assert!(geometry.admit(queue(), &submission).is_ok());
        geometry.apply_capacity(9, 4088).expect("511 whole blocks");
        assert_eq!(geometry.block_count(), 511);
        assert_eq!(geometry.block_size(), 4096);
        assert_eq!(
            geometry.admit(queue(), &submission),
            Err(AbiError::InvalidParam)
        );
        assert_eq!(
            geometry.apply_capacity(10, 4089),
            Err(BlockConfigurationError::InvalidBlockSize)
        );
        assert_eq!(geometry.configuration_generation, 9);
        assert_eq!(geometry.block_count(), 511);
    }

    #[test]
    fn completion_excludes_status_and_never_reports_partial_success() {
        let geometry = BlockGeometry::from_values(8192, 4096, 65536, 0).expect("fixture geometry");
        let submission = input();
        let command = geometry
            .admit(queue(), &submission)
            .expect("fixture transfer");
        let done = BlockNotification::new(3, &submission, &command).complete(8193, 0);
        assert_eq!(done.bytes, 8192);
        assert_eq!(done.status, AbiError::Success as i32);
        assert_eq!(
            (done.request_id, done.lease_id, done.generation),
            (19, 11, 37)
        );
        let truncated = BlockNotification::new(3, &submission, &command).complete(4097, 0);
        assert_eq!(truncated.status, AbiError::IoError as i32);
        assert_eq!(truncated.bytes, 0);
        assert_eq!(
            BlockNotification::new(3, &submission, &command)
                .complete(1, 2)
                .status,
            AbiError::NotSupported as i32
        );
        assert_eq!(
            BlockNotification::new(3, &submission, &command)
                .complete(0, 0)
                .status,
            AbiError::IoError as i32
        );
    }
}
