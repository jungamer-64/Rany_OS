//! AHCIコマンド関連構造体
//!
//! CommandHeader, PhysicalRegionDescriptor, CommandTable, ReceivedFis

// ============================================================================
// Command Header
// ============================================================================

/// コマンドヘッダ（32バイト）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CommandHeader {
    /// Flags (CFL, A, W, P, R, B, C, PMP)
    flags: u16,
    /// Physical Region Descriptor Table Length
    pub prdtl: u16,
    /// Physical Region Descriptor Byte Count
    pub prdbc: u32,
    /// Command Table Descriptor Base Address
    ctba: u32,
    /// Command Table Descriptor Base Address Upper
    ctbau: u32,
    /// Reserved
    reserved: [u32; 4],
}

impl CommandHeader {
    /// フラグを設定
    /// - cfl: Command FIS Length (in DWORDs, 2-16)
    /// - write: Write operation
    /// - atapi: ATAPI command
    /// - prefetch: Prefetchable
    pub fn set_flags(&mut self, cfl: u8, write: bool, atapi: bool, prefetch: bool) {
        let mut flags: u16 = (cfl & 0x1F) as u16;
        if atapi {
            flags |= 1 << 5;
        }
        if write {
            flags |= 1 << 6;
        }
        if prefetch {
            flags |= 1 << 7;
        }
        self.flags = flags;
    }

    /// コマンドテーブルのアドレスを設定
    pub fn set_ctba(&mut self, addr: u64) {
        self.ctba = addr as u32;
        self.ctbau = (addr >> 32) as u32;
    }
}

impl Default for CommandHeader {
    fn default() -> Self {
        Self {
            flags: 0,
            prdtl: 0,
            prdbc: 0,
            ctba: 0,
            ctbau: 0,
            reserved: [0; 4],
        }
    }
}

// ============================================================================
// Physical Region Descriptor
// ============================================================================

/// Physical Region Descriptor（16バイト）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PhysicalRegionDescriptor {
    /// Data Base Address
    dba: u32,
    /// Data Base Address Upper
    dbau: u32,
    /// Reserved
    reserved: u32,
    /// Data Byte Count + Interrupt on Completion
    dbc_i: u32,
}

impl PhysicalRegionDescriptor {
    /// 新しいPRDを作成
    pub fn new(addr: u64, byte_count: u32, interrupt: bool) -> Self {
        let dbc = (byte_count - 1) & 0x3FFFFF; // 22-bit, 0-based
        let i = if interrupt { 1 << 31 } else { 0 };

        Self {
            dba: addr as u32,
            dbau: (addr >> 32) as u32,
            reserved: 0,
            dbc_i: dbc | i,
        }
    }
}

impl Default for PhysicalRegionDescriptor {
    fn default() -> Self {
        Self {
            dba: 0,
            dbau: 0,
            reserved: 0,
            dbc_i: 0,
        }
    }
}

// ============================================================================
// Command Table
// ============================================================================

/// コマンドテーブル
#[repr(C, align(128))]
#[derive(Clone)]
pub struct CommandTable {
    /// Command FIS (64 bytes)
    pub cfis: [u8; 64],
    /// ATAPI Command (16 bytes)
    pub acmd: [u8; 16],
    /// Reserved (48 bytes)
    pub reserved: [u8; 48],
    /// Physical Region Descriptor Table (up to 65535 entries, but we use 8)
    pub prdt: [PhysicalRegionDescriptor; 8],
}

impl Default for CommandTable {
    fn default() -> Self {
        Self {
            cfis: [0; 64],
            acmd: [0; 16],
            reserved: [0; 48],
            prdt: [PhysicalRegionDescriptor::default(); 8],
        }
    }
}

// ============================================================================
// Received FIS
// ============================================================================

/// Received FIS構造体（256バイト、アライメント必須）
#[repr(C, align(256))]
pub struct ReceivedFis {
    /// DMA Setup FIS (28 bytes)
    pub dsfis: [u8; 28],
    /// Reserved
    pub reserved0: [u8; 4],
    /// PIO Setup FIS (20 bytes)
    pub psfis: [u8; 20],
    /// Reserved
    pub reserved1: [u8; 12],
    /// D2H Register FIS (20 bytes)
    pub rfis: [u8; 20],
    /// Reserved
    pub reserved2: [u8; 4],
    /// Set Device Bits FIS (8 bytes)
    pub sdbfis: [u8; 8],
    /// Unknown FIS (64 bytes)
    pub ufis: [u8; 64],
    /// Reserved
    pub reserved3: [u8; 96],
}
