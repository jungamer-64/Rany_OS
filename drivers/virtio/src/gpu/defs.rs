// ============================================================================
// drivers/virtio/src/gpu/defs.rs - Shared VirtIO GPU Definitions
// ============================================================================
//!
//! Shared types and constants for VirtIO GPU devices.
//! Based on VirtIO Specification 5.7.

// =============================================================================
// Constants and Features
// =============================================================================

pub const VIRTIO_GPU_F_VIRGL: u64 = 1 << 0;
pub const VIRTIO_GPU_F_EDID: u64 = 1 << 1;
pub const VIRTIO_GPU_F_RESOURCE_UUID: u64 = 1 << 2;
pub const VIRTIO_GPU_F_RESOURCE_BLOB: u64 = 1 << 3;

pub const VIRTQUEUE_CTRL: u16 = 0;
pub const VIRTQUEUE_CURSOR: u16 = 1;

pub const MAX_SCANOUTS: usize = 16;

// =============================================================================
// Commands
// =============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuCmd {
    GetDisplayInfo = 0x0100,
    ResourceCreate2D = 0x0101,
    ResourceUnref = 0x0102,
    SetScanout = 0x0103,
    ResourceFlush = 0x0104,
    TransferToHost2D = 0x0105,
    ResourceAttachBacking = 0x0106,
    ResourceDetachBacking = 0x0107,
    GetCapsetInfo = 0x0108,
    GetCapset = 0x0109,
    GetEdid = 0x010A,
    UpdateCursor = 0x0300,
    MoveCursor = 0x0301,
    CtxCreate = 0x0200,
    CtxDestroy = 0x0201,
    CtxAttachResource = 0x0202,
    CtxDetachResource = 0x0203,
    ResourceCreate3D = 0x0204,
    TransferToHost3D = 0x0205,
    TransferFromHost3D = 0x0206,
    Submit3D = 0x0207,
    RespOkNoData = 0x1100,
    RespOkDisplayInfo = 0x1101,
    RespOkCapsetInfo = 0x1102,
    RespOkCapset = 0x1103,
    RespOkEdid = 0x1104,
    RespErrUnspec = 0x1200,
    RespErrOutOfMemory = 0x1201,
    RespErrInvalidScanoutId = 0x1202,
    RespErrInvalidResourceId = 0x1203,
    RespErrInvalidCtxId = 0x1204,
    RespErrInvalidParameter = 0x1205,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuCtrlHdr {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub _padding: u32,
}

impl GpuCtrlHdr {
    pub fn new(cmd_type: GpuCmd) -> Self {
        Self {
            cmd_type: cmd_type as u32,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
            _padding: 0,
        }
    }

    pub fn with_fence(mut self, fence_id: u64) -> Self {
        self.flags |= 1; // VIRTIO_GPU_FLAG_FENCE
        self.fence_id = fence_id;
        self
    }
}

// =============================================================================
// Display Info
// =============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayMode {
    pub rect: Rect,
    pub enabled: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct DisplayInfo {
    pub modes: [DisplayMode; MAX_SCANOUTS],
}

// =============================================================================
// Resources
// =============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    B8G8R8A8Unorm = 1,
    B8G8R8X8Unorm = 2,
    A8R8G8B8Unorm = 3,
    X8R8G8B8Unorm = 4,
    R8G8B8A8Unorm = 67,
    X8B8G8R8Unorm = 68,
    A8B8G8R8Unorm = 121,
    R8G8B8X8Unorm = 134,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceCreate2D {
    pub hdr: GpuCtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemEntry {
    pub addr: u64,
    pub length: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceAttachBacking {
    pub hdr: GpuCtrlHdr,
    pub resource_id: u32,
    pub nr_entries: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransferToHost2D {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub offset: u64,
    pub resource_id: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SetScanout {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceFlush {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub resource_id: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceUnref {
    pub hdr: GpuCtrlHdr,
    pub resource_id: u32,
    pub _padding: u32,
}

// =============================================================================
// Cursor
// =============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CursorPos {
    pub scanout_id: u32,
    pub x: u32,
    pub y: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UpdateCursor {
    pub hdr: GpuCtrlHdr,
    pub pos: CursorPos,
    pub resource_id: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub _padding: u32,
}
