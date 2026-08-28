//! Pure ATAPI packet and response codecs.
//!
//! This module deliberately owns no registers or DMA memory. An eventual
//! SATAPI transport must submit these bytes through the same `AhciPort` lease
//! protocol as SATA commands; byte slices and heap addresses are never device
//! addresses.

#![forbid(unsafe_code)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Logical block size commonly used by data CDs and DVDs.
pub const CD_SECTOR_SIZE: u32 = 2048;
/// Sector size used by raw CD audio reads.
pub const CD_AUDIO_SECTOR_SIZE: u32 = 2352;

/// Failure while decoding an ATAPI response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtapiParseError {
    /// The response does not contain the complete fixed or declared span.
    Truncated,
    /// A declared variable-length response is not a sequence of full records.
    MalformedLength,
    /// Capacity for decoded records could not be reserved.
    Capacity,
}

/// SCSI operation codes carried by an ATA PACKET command.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiOpcode {
    TestUnitReady = 0x00,
    RequestSense = 0x03,
    Inquiry = 0x12,
    ModeSense6 = 0x1A,
    StartStopUnit = 0x1B,
    PreventAllow = 0x1E,
    ReadCapacity = 0x25,
    Read10 = 0x28,
    ReadTocPmaAtip = 0x43,
    GetConfiguration = 0x46,
    GetEventStatus = 0x4A,
    ReadDiscInfo = 0x51,
    ModeSense10 = 0x5A,
    Read12 = 0xA8,
    ReadCd = 0xBE,
}

/// One validated twelve-byte SCSI command descriptor block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScsiCdb12([u8; 12]);

impl ScsiCdb12 {
    /// Builds TEST UNIT READY.
    pub const fn test_unit_ready() -> Self {
        Self::with_opcode(ScsiOpcode::TestUnitReady)
    }

    /// Builds INQUIRY with the requested response size.
    pub const fn inquiry(allocation_length: u8) -> Self {
        let mut bytes = Self::with_opcode(ScsiOpcode::Inquiry).0;
        bytes[4] = allocation_length;
        Self(bytes)
    }

    /// Builds REQUEST SENSE with the requested response size.
    pub const fn request_sense(allocation_length: u8) -> Self {
        let mut bytes = Self::with_opcode(ScsiOpcode::RequestSense).0;
        bytes[4] = allocation_length;
        Self(bytes)
    }

    /// Builds READ CAPACITY (10).
    pub const fn read_capacity() -> Self {
        Self::with_opcode(ScsiOpcode::ReadCapacity)
    }

    /// Builds READ (10).
    pub const fn read10(lba: u32, block_count: u16) -> Self {
        let mut bytes = Self::with_opcode(ScsiOpcode::Read10).0;
        let lba = lba.to_be_bytes();
        bytes[2] = lba[0];
        bytes[3] = lba[1];
        bytes[4] = lba[2];
        bytes[5] = lba[3];
        let blocks = block_count.to_be_bytes();
        bytes[7] = blocks[0];
        bytes[8] = blocks[1];
        Self(bytes)
    }

    /// Builds READ (12).
    pub const fn read12(lba: u32, block_count: u32) -> Self {
        let mut bytes = Self::with_opcode(ScsiOpcode::Read12).0;
        let lba = lba.to_be_bytes();
        bytes[2] = lba[0];
        bytes[3] = lba[1];
        bytes[4] = lba[2];
        bytes[5] = lba[3];
        let blocks = block_count.to_be_bytes();
        bytes[6] = blocks[0];
        bytes[7] = blocks[1];
        bytes[8] = blocks[2];
        bytes[9] = blocks[3];
        Self(bytes)
    }

    /// Builds READ TOC/PMA/ATIP.
    pub const fn read_toc(format: TocFormat, track: u8, allocation_length: u16) -> Self {
        let mut bytes = Self::with_opcode(ScsiOpcode::ReadTocPmaAtip).0;
        bytes[1] = (format as u8) << 1;
        bytes[6] = track;
        let allocation_length = allocation_length.to_be_bytes();
        bytes[7] = allocation_length[0];
        bytes[8] = allocation_length[1];
        Self(bytes)
    }

    /// Builds START STOP UNIT.
    pub const fn start_stop_unit(start: bool, load_eject: bool) -> Self {
        let mut bytes = Self::with_opcode(ScsiOpcode::StartStopUnit).0;
        bytes[4] = (start as u8) | ((load_eject as u8) << 1);
        Self(bytes)
    }

    /// Builds GET CONFIGURATION for one starting feature.
    pub const fn get_configuration(feature: u16, allocation_length: u16) -> Self {
        let mut bytes = Self::with_opcode(ScsiOpcode::GetConfiguration).0;
        bytes[1] = 0x02;
        let feature = feature.to_be_bytes();
        bytes[2] = feature[0];
        bytes[3] = feature[1];
        let allocation_length = allocation_length.to_be_bytes();
        bytes[7] = allocation_length[0];
        bytes[8] = allocation_length[1];
        Self(bytes)
    }

    /// Returns the exact bytes to place in an AHCI ATAPI command table.
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    const fn with_opcode(opcode: ScsiOpcode) -> Self {
        let mut bytes = [0; 12];
        bytes[0] = opcode as u8;
        Self(bytes)
    }
}

/// Format field for READ TOC/PMA/ATIP.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TocFormat {
    FormattedToc = 0,
    MultiSession = 1,
    RawToc = 2,
    Pma = 3,
    Atip = 4,
    CdText = 5,
}

/// Peripheral type decoded from INQUIRY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtapiDeviceType {
    DirectAccess,
    SequentialAccess,
    CdDvd,
    OpticalMemory,
    MediaChanger,
    Unknown(u8),
}

impl AtapiDeviceType {
    const fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::DirectAccess,
            0x01 => Self::SequentialAccess,
            0x05 => Self::CdDvd,
            0x07 => Self::OpticalMemory,
            0x08 => Self::MediaChanger,
            _ => Self::Unknown(code),
        }
    }
}

/// Validated standard INQUIRY response fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InquiryResponse {
    device_type: AtapiDeviceType,
    removable: bool,
    vendor: [u8; 8],
    product: [u8; 16],
    revision: [u8; 4],
}

impl InquiryResponse {
    /// Decodes the fixed 36-byte standard INQUIRY prefix.
    ///
    /// # Errors
    /// Returns `Truncated` unless all fixed fields are present.
    pub fn parse(bytes: &[u8]) -> Result<Self, AtapiParseError> {
        let prefix = bytes.get(..36).ok_or(AtapiParseError::Truncated)?;
        let mut vendor = [0; 8];
        vendor.copy_from_slice(&prefix[8..16]);
        let mut product = [0; 16];
        product.copy_from_slice(&prefix[16..32]);
        let mut revision = [0; 4];
        revision.copy_from_slice(&prefix[32..36]);
        Ok(Self {
            device_type: AtapiDeviceType::from_code(prefix[0] & 0x1f),
            removable: prefix[1] & 0x80 != 0,
            vendor,
            product,
            revision,
        })
    }

    pub const fn device_type(&self) -> AtapiDeviceType {
        self.device_type
    }

    pub const fn is_removable(&self) -> bool {
        self.removable
    }

    pub fn vendor_string(&self) -> String {
        String::from_utf8_lossy(&self.vendor).trim().to_string()
    }

    pub fn product_string(&self) -> String {
        String::from_utf8_lossy(&self.product).trim().to_string()
    }

    pub fn revision_string(&self) -> String {
        String::from_utf8_lossy(&self.revision).trim().to_string()
    }
}

/// Validated READ CAPACITY (10) response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadCapacityResponse {
    last_lba: u32,
    block_length: u32,
}

impl ReadCapacityResponse {
    /// Decodes the complete eight-byte response.
    ///
    /// # Errors
    /// Returns `Truncated` unless both integers are present.
    pub fn parse(bytes: &[u8]) -> Result<Self, AtapiParseError> {
        let bytes = bytes.get(..8).ok_or(AtapiParseError::Truncated)?;
        Ok(Self {
            last_lba: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            block_length: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }

    pub const fn last_lba(&self) -> u32 {
        self.last_lba
    }

    pub const fn block_length(&self) -> u32 {
        self.block_length
    }

    pub const fn total_blocks(&self) -> u64 {
        self.last_lba as u64 + 1
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_blocks() * self.block_length as u64
    }
}

/// Decoded fixed-format sense key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenseKey {
    NoSense,
    RecoveredError,
    NotReady,
    MediumError,
    HardwareError,
    IllegalRequest,
    UnitAttention,
    DataProtect,
    BlankCheck,
    VendorSpecific,
    CopyAborted,
    AbortedCommand,
    Obsolete,
    VolumeOverflow,
    Miscompare,
    Reserved,
}

impl SenseKey {
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x0 => Self::NoSense,
            0x1 => Self::RecoveredError,
            0x2 => Self::NotReady,
            0x3 => Self::MediumError,
            0x4 => Self::HardwareError,
            0x5 => Self::IllegalRequest,
            0x6 => Self::UnitAttention,
            0x7 => Self::DataProtect,
            0x8 => Self::BlankCheck,
            0x9 => Self::VendorSpecific,
            0xa => Self::CopyAborted,
            0xb => Self::AbortedCommand,
            0xc => Self::Obsolete,
            0xd => Self::VolumeOverflow,
            0xe => Self::Miscompare,
            _ => Self::Reserved,
        }
    }
}

/// Fields needed to classify a fixed-format REQUEST SENSE response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SenseData {
    key: SenseKey,
    asc: u8,
    ascq: u8,
}

impl SenseData {
    /// Decodes the fixed fields through ASCQ.
    ///
    /// # Errors
    /// Returns `Truncated` unless bytes 0 through 13 are present.
    pub fn parse(bytes: &[u8]) -> Result<Self, AtapiParseError> {
        let bytes = bytes.get(..14).ok_or(AtapiParseError::Truncated)?;
        Ok(Self {
            key: SenseKey::from_code(bytes[2] & 0x0f),
            asc: bytes[12],
            ascq: bytes[13],
        })
    }

    pub const fn sense_key(&self) -> SenseKey {
        self.key
    }

    pub const fn asc_ascq(&self) -> (u8, u8) {
        (self.asc, self.ascq)
    }

    pub const fn error_description(&self) -> &'static str {
        match (self.key, self.asc, self.ascq) {
            (SenseKey::NoSense, _, _) => "No sense",
            (SenseKey::NotReady, 0x04, 0x01) => "Becoming ready",
            (SenseKey::NotReady, 0x04, 0x02) => "Need START command",
            (SenseKey::NotReady, 0x3a, _) => "Medium not present",
            (SenseKey::MediumError, _, _) => "Medium error",
            (SenseKey::HardwareError, _, _) => "Hardware error",
            (SenseKey::IllegalRequest, _, _) => "Illegal request",
            (SenseKey::UnitAttention, 0x28, _) => "Medium changed",
            (SenseKey::UnitAttention, 0x29, _) => "Reset occurred",
            (SenseKey::DataProtect, _, _) => "Data protect",
            (SenseKey::AbortedCommand, _, _) => "Aborted command",
            _ => "Unknown error",
        }
    }
}

/// One validated TOC track descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TocTrackDescriptor {
    adr_control: u8,
    track_number: u8,
    track_start: u32,
}

impl TocTrackDescriptor {
    fn parse(bytes: &[u8]) -> Result<Self, AtapiParseError> {
        let bytes = bytes.get(..8).ok_or(AtapiParseError::Truncated)?;
        Ok(Self {
            adr_control: bytes[1],
            track_number: bytes[2],
            track_start: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }

    pub const fn number(&self) -> u8 {
        self.track_number
    }

    pub const fn track_start(&self) -> u32 {
        self.track_start
    }

    pub const fn is_data_track(&self) -> bool {
        self.adr_control & 0x04 != 0
    }

    pub const fn is_audio_track(&self) -> bool {
        !self.is_data_track()
    }
}

/// Validated table-of-contents response and its decoded records.
#[derive(Debug, PartialEq, Eq)]
pub struct TableOfContents {
    first_track: u8,
    last_track: u8,
    tracks: Vec<TocTrackDescriptor>,
}

impl TableOfContents {
    /// Decodes a complete READ TOC response.
    ///
    /// # Errors
    /// Rejects truncated declarations, non-record-aligned payloads, and record
    /// capacity exhaustion without publishing a partial table.
    pub fn parse(bytes: &[u8]) -> Result<Self, AtapiParseError> {
        let header = bytes.get(..4).ok_or(AtapiParseError::Truncated)?;
        let declared_after_length = usize::from(u16::from_be_bytes([header[0], header[1]]));
        let total = declared_after_length
            .checked_add(2)
            .ok_or(AtapiParseError::MalformedLength)?;
        if total < 4 {
            return Err(AtapiParseError::MalformedLength);
        }
        let complete = bytes.get(..total).ok_or(AtapiParseError::Truncated)?;
        let records = complete.get(4..).ok_or(AtapiParseError::MalformedLength)?;
        if !records.len().is_multiple_of(8) {
            return Err(AtapiParseError::MalformedLength);
        }
        let mut tracks = Vec::new();
        tracks
            .try_reserve_exact(records.len() / 8)
            .map_err(|_| AtapiParseError::Capacity)?;
        let (records, remainder) = records.as_chunks::<8>();
        debug_assert!(remainder.is_empty());
        for record in records {
            tracks.push(TocTrackDescriptor::parse(record)?);
        }
        Ok(Self {
            first_track: header[2],
            last_track: header[3],
            tracks,
        })
    }

    pub const fn first_track(&self) -> u8 {
        self.first_track
    }

    pub const fn last_track(&self) -> u8 {
        self.last_track
    }

    pub fn tracks(&self) -> &[TocTrackDescriptor] {
        &self.tracks
    }

    pub fn track_count(&self) -> usize {
        self.tracks
            .iter()
            .filter(|track| track.track_number != 0xaa)
            .count()
    }

    pub fn get_track(&self, number: u8) -> Option<&TocTrackDescriptor> {
        self.tracks
            .iter()
            .find(|track| track.track_number == number)
    }

    pub fn lead_out(&self) -> Option<&TocTrackDescriptor> {
        self.get_track(0xaa)
    }

    pub fn total_length_seconds(&self) -> Option<u32> {
        self.lead_out().map(|track| track.track_start() / 75)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdbs_use_scsi_byte_positions_and_big_endian_integers() {
        assert_eq!(
            ScsiCdb12::read10(0x1234_5678, 0x0100).as_bytes(),
            &[0x28, 0, 0x12, 0x34, 0x56, 0x78, 0, 0x01, 0, 0, 0, 0]
        );
        assert_eq!(
            ScsiCdb12::read12(0x0102_0304, 0x0506_0708).as_bytes(),
            &[0xa8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0]
        );
    }

    #[test]
    fn fixed_responses_reject_truncation_and_decode_big_endian_values() {
        assert_eq!(
            ReadCapacityResponse::parse(&[1, 2, 3]),
            Err(AtapiParseError::Truncated)
        );
        let capacity = ReadCapacityResponse::parse(&[1, 2, 3, 4, 0, 0, 8, 0]);
        assert_eq!(capacity.map(|value| value.last_lba()), Ok(0x0102_0304));
        assert_eq!(capacity.map(|value| value.block_length()), Ok(2048));
    }

    #[test]
    fn inquiry_parsing_copies_only_the_validated_fixed_prefix() {
        let mut bytes = [0u8; 36];
        bytes[0] = 0x05;
        bytes[1] = 0x80;
        bytes[8..16].copy_from_slice(b"VENDOR  ");
        bytes[16..32].copy_from_slice(b"OPTICAL DRIVE   ");
        bytes[32..36].copy_from_slice(b"1.0 ");
        let inquiry = InquiryResponse::parse(&bytes);
        assert_eq!(
            inquiry.map(|value| value.device_type()),
            Ok(AtapiDeviceType::CdDvd)
        );
        assert_eq!(
            inquiry.map(|value| value.vendor_string()),
            Ok(String::from("VENDOR"))
        );
    }

    #[test]
    fn toc_requires_complete_aligned_records() {
        assert_eq!(
            TableOfContents::parse(&[0, 3, 1, 1, 0]),
            Err(AtapiParseError::MalformedLength)
        );
        assert_eq!(
            TableOfContents::parse(&[0, 10, 1, 1, 0, 4, 1, 0, 0, 0]),
            Err(AtapiParseError::Truncated)
        );

        let bytes = [
            0, 18, 1, 1, 0, 4, 1, 0, 0, 0, 0, 75, 0, 4, 0xaa, 0, 0, 0, 0x02, 0x31,
        ];
        let toc = TableOfContents::parse(&bytes);
        assert_eq!(toc.as_ref().map(|value| value.track_count()), Ok(1));
        assert_eq!(
            toc.as_ref()
                .ok()
                .and_then(|value| value.total_length_seconds()),
            Some(7)
        );
    }
}
