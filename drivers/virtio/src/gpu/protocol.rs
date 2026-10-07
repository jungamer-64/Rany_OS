//! Wire fields are encoded and decoded independently of Rust object layout.
//! A used entry permits response inspection; only a matching fence proves that
//! command processing and guest backing accesses have completed.
#![deny(unsafe_code)]

use super::defs::{DisplayInfo, DisplayMode, GpuCmd, MAX_SCANOUTS, Rect};
use kernel_api::{KapiError, KapiResult};

pub(super) const HEADER_BYTES: usize = 24;
pub(super) const DISPLAY_BYTES: usize = HEADER_BYTES + MAX_SCANOUTS * 24;
pub(super) const REQUEST_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuDeviceError {
    Unspecified,
    OutOfMemory,
    InvalidScanout,
    InvalidResource,
    InvalidContext,
    InvalidParameter,
}

#[derive(Clone, Copy)]
pub(super) enum Response {
    Header,
    Display,
}
impl Response {
    pub(super) fn byte_count(self) -> usize {
        match self {
            Self::Header => HEADER_BYTES,
            Self::Display => DISPLAY_BYTES,
        }
    }
}

pub(super) struct WireCommand {
    bytes: [u8; REQUEST_BYTES],
    length: usize,
    pub(super) fence: u64,
    pub(super) response: Response,
}
impl WireCommand {
    pub(super) fn new(command: GpuCmd, fence: u64, response: Response) -> Self {
        let mut bytes = [0; REQUEST_BYTES];
        bytes[..4].copy_from_slice(&(command as u32).to_le_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&fence.to_le_bytes());
        Self {
            bytes,
            length: HEADER_BYTES,
            fence,
            response,
        }
    }
    pub(super) fn u32(&mut self, value: u32) -> KapiResult<()> {
        self.append(&value.to_le_bytes())
    }
    pub(super) fn u64(&mut self, value: u64) -> KapiResult<()> {
        self.append(&value.to_le_bytes())
    }
    pub(super) fn rect(&mut self, rect: Rect) -> KapiResult<()> {
        self.u32(rect.x)?;
        self.u32(rect.y)?;
        self.u32(rect.width)?;
        self.u32(rect.height)
    }
    fn append(&mut self, bytes: &[u8]) -> KapiResult<()> {
        let end = self
            .length
            .checked_add(bytes.len())
            .ok_or(KapiError::InvalidSize)?;
        self.bytes
            .get_mut(self.length..end)
            .ok_or(KapiError::InvalidSize)?
            .copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "a bounded wire response is decoded without allocating at command completion"
)]
pub(super) enum Reply {
    Done,
    Display(DisplayInfo),
}
pub(super) enum ReplyError {
    Protocol,
    Device(GpuDeviceError),
}

pub(super) fn decode(bytes: &[u8], fence: u64, response: Response) -> Result<Reply, ReplyError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ReplyError::Protocol);
    }
    let kind = u32_at(bytes, 0)?;
    if u32_at(bytes, 4)? != 1
        || u64_at(bytes, 8)? != fence
        || fence == 0
        || u32_at(bytes, 16)? != 0
        || u32_at(bytes, 20)? != 0
    {
        return Err(ReplyError::Protocol);
    }
    if (0x1200..=0x1205).contains(&kind) {
        if bytes.len() != HEADER_BYTES {
            return Err(ReplyError::Protocol);
        }
        let failure = match kind {
            0x1200 => GpuDeviceError::Unspecified,
            0x1201 => GpuDeviceError::OutOfMemory,
            0x1202 => GpuDeviceError::InvalidScanout,
            0x1203 => GpuDeviceError::InvalidResource,
            0x1204 => GpuDeviceError::InvalidContext,
            _ => GpuDeviceError::InvalidParameter,
        };
        return Err(ReplyError::Device(failure));
    }
    match response {
        Response::Header if kind == 0x1100 && bytes.len() == HEADER_BYTES => Ok(Reply::Done),
        Response::Display if kind == 0x1101 && bytes.len() == DISPLAY_BYTES => {
            let mut modes = [DisplayMode::default(); MAX_SCANOUTS];
            for (index, mode) in modes.iter_mut().enumerate() {
                let offset = HEADER_BYTES + index * 24;
                let rect = Rect {
                    x: u32_at(bytes, offset)?,
                    y: u32_at(bytes, offset + 4)?,
                    width: u32_at(bytes, offset + 8)?,
                    height: u32_at(bytes, offset + 12)?,
                };
                let enabled = u32_at(bytes, offset + 16)?;
                if enabled != 0
                    && (rect.width == 0
                        || rect.height == 0
                        || rect.x.checked_add(rect.width).is_none()
                        || rect.y.checked_add(rect.height).is_none())
                {
                    return Err(ReplyError::Protocol);
                }
                *mode = DisplayMode {
                    rect,
                    enabled,
                    flags: u32_at(bytes, offset + 20)?,
                };
            }
            Ok(Reply::Display(DisplayInfo { modes }))
        }
        _ => Err(ReplyError::Protocol),
    }
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ReplyError> {
    let bytes = bytes.get(offset..offset + 4).ok_or(ReplyError::Protocol)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| ReplyError::Protocol)?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ReplyError> {
    let bytes = bytes.get(offset..offset + 8).ok_or(ReplyError::Protocol)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| ReplyError::Protocol)?,
    ))
}
