//! SMBIOS (System Management BIOS) 情報検出
//!
//! UEFI Configuration Tableから SMBIOS 3.x/2.x テーブルを検出し、
//! システムハードウェア情報を取得する。

use core::ptr;
use uefi::guid;

/// SMBIOS 3.x Entry Point GUID
/// F2FD1544-9794-4A2C-992E-E5BBCF20E394
pub const SMBIOS3_TABLE_GUID: uefi::Guid = guid!("f2fd1544-9794-4a2c-992e-e5bbcf20e394");

/// SMBIOS 2.x Entry Point GUID
/// EB9D2D31-2D88-11D3-9A16-0090273FC14D
pub const SMBIOS_TABLE_GUID: uefi::Guid = guid!("eb9d2d31-2d88-11d3-9a16-0090273fc14d");

/// SMBIOS情報
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SmbiosInfo {
    /// SMBIOS 3.x テーブルアドレス（0 = 未検出）
    pub smbios3_addr: u64,
    /// SMBIOS 2.x テーブルアドレス（0 = 未検出）
    pub smbios_addr: u64,
    /// SMBIOSメジャーバージョン
    pub major_version: u8,
    /// SMBIOSマイナーバージョン
    pub minor_version: u8,
    /// テーブル構造の最大サイズ
    pub table_max_size: u32,
    /// フラグ
    pub flags: u16,
    /// 予約
    pub _reserved: [u8; 4],
    // 以下、パースした基本情報
    /// BIOSベンダー文字列オフセット（テーブル内）
    pub bios_vendor_offset: u32,
    /// BIOSバージョン文字列オフセット
    pub bios_version_offset: u32,
    /// システム製造元文字列オフセット
    pub system_manufacturer_offset: u32,
    /// システム製品名文字列オフセット
    pub system_product_offset: u32,
    /// システムシリアル番号文字列オフセット
    pub system_serial_offset: u32,
    /// システムUUID
    pub system_uuid: [u8; 16],
}

impl Default for SmbiosInfo {
    fn default() -> Self {
        Self {
            smbios3_addr: 0,
            smbios_addr: 0,
            major_version: 0,
            minor_version: 0,
            table_max_size: 0,
            flags: 0,
            _reserved: [0; 4],
            bios_vendor_offset: 0,
            bios_version_offset: 0,
            system_manufacturer_offset: 0,
            system_product_offset: 0,
            system_serial_offset: 0,
            system_uuid: [0; 16],
        }
    }
}

/// SMBIOSフラグ
pub mod smbios_flags {
    /// SMBIOS 3.x が利用可能
    pub const SMBIOS3_AVAILABLE: u16 = 1 << 0;
    /// SMBIOS 2.x が利用可能
    pub const SMBIOS2_AVAILABLE: u16 = 1 << 1;
    /// BIOS情報が取得済み
    pub const BIOS_INFO_VALID: u16 = 1 << 2;
    /// システム情報が取得済み
    pub const SYSTEM_INFO_VALID: u16 = 1 << 3;
    /// プロセッサ情報が取得済み
    #[allow(dead_code)]
    pub const PROCESSOR_INFO_VALID: u16 = 1 << 4;
    /// メモリ情報が取得済み
    #[allow(dead_code)]
    pub const MEMORY_INFO_VALID: u16 = 1 << 5;
}

/// SMBIOS 3.x Entry Point 構造体
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Smbios3EntryPoint {
    anchor: [u8; 5],           // "_SM3_"
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    docrev: u8,
    entry_point_revision: u8,
    _reserved: u8,
    table_max_size: u32,
    table_address: u64,
}

/// SMBIOS 2.x Entry Point 構造体
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Smbios2EntryPoint {
    anchor: [u8; 4],           // "_SM_"
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    max_structure_size: u16,
    entry_point_revision: u8,
    formatted_area: [u8; 5],
    intermediate_anchor: [u8; 5], // "_DMI_"
    intermediate_checksum: u8,
    table_length: u16,
    table_address: u32,
    number_of_structures: u16,
    bcd_revision: u8,
}

/// SMBIOS 構造体ヘッダ
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct SmbiosHeader {
    struct_type: u8,
    length: u8,
    handle: u16,
}

/// SMBIOSタイプ
const SMBIOS_TYPE_BIOS: u8 = 0;
const SMBIOS_TYPE_SYSTEM: u8 = 1;
const SMBIOS_TYPE_END_OF_TABLE: u8 = 127;

/// UEFI Configuration TableからSMBIOS情報を検出
pub fn detect_smbios() -> SmbiosInfo {
    let mut info = SmbiosInfo::default();

    // Configuration Tableを検索
    uefi::system::with_config_table(|entries| {
        for entry in entries {
            if entry.guid == SMBIOS3_TABLE_GUID {
                info.smbios3_addr = entry.address as u64;
                info.flags |= smbios_flags::SMBIOS3_AVAILABLE;
                
                // SMBIOS 3.x Entry Point をパース
                if let Some((major, minor, max_size, table_addr)) = parse_smbios3_entry(entry.address) {
                    info.major_version = major;
                    info.minor_version = minor;
                    info.table_max_size = max_size;
                    
                    // 構造体テーブルをパース
                    parse_smbios_structures(&mut info, table_addr, max_size as usize);
                }
            } else if entry.guid == SMBIOS_TABLE_GUID {
                info.smbios_addr = entry.address as u64;
                info.flags |= smbios_flags::SMBIOS2_AVAILABLE;
                
                // SMBIOS 3.x が未検出の場合のみ 2.x を使用
                if info.smbios3_addr == 0 {
                    if let Some((major, minor, table_addr, table_len)) = parse_smbios2_entry(entry.address) {
                        info.major_version = major;
                        info.minor_version = minor;
                        info.table_max_size = table_len as u32;
                        
                        parse_smbios_structures(&mut info, table_addr as u64, table_len as usize);
                    }
                }
            }
        }
    });

    info
}

/// SMBIOS 3.x Entry Pointをパース
fn parse_smbios3_entry(addr: *const core::ffi::c_void) -> Option<(u8, u8, u32, u64)> {
    let entry = unsafe { ptr::read_unaligned(addr as *const Smbios3EntryPoint) };
    
    // アンカー文字列を検証
    if &entry.anchor != b"_SM3_" {
        return None;
    }
    
    Some((
        entry.major_version,
        entry.minor_version,
        entry.table_max_size,
        entry.table_address,
    ))
}

/// SMBIOS 2.x Entry Pointをパース
fn parse_smbios2_entry(addr: *const core::ffi::c_void) -> Option<(u8, u8, u32, u16)> {
    let entry = unsafe { ptr::read_unaligned(addr as *const Smbios2EntryPoint) };
    
    // アンカー文字列を検証
    if &entry.anchor != b"_SM_" {
        return None;
    }
    
    Some((
        entry.major_version,
        entry.minor_version,
        entry.table_address,
        entry.table_length,
    ))
}

/// SMBIOS構造体テーブルをパース
fn parse_smbios_structures(info: &mut SmbiosInfo, table_addr: u64, max_size: usize) {
    let mut offset: usize = 0;
    let table_ptr = table_addr as *const u8;
    
    while offset < max_size {
        // ヘッダを読み取り
        let header = unsafe {
            ptr::read_unaligned(table_ptr.add(offset) as *const SmbiosHeader)
        };
        
        // End of Table
        if header.struct_type == SMBIOS_TYPE_END_OF_TABLE {
            break;
        }
        
        let struct_start = offset;
        
        // 構造体タイプに応じてパース
        match header.struct_type {
            SMBIOS_TYPE_BIOS => {
                parse_bios_info(info, table_ptr, struct_start, header.length as usize);
            }
            SMBIOS_TYPE_SYSTEM => {
                parse_system_info(info, table_ptr, struct_start, header.length as usize);
            }
            _ => {}
        }
        
        // 構造体の終端（文字列テーブル後の2つのNULL）を探す
        offset += header.length as usize;
        
        // 文字列テーブルをスキップ
        while offset + 1 < max_size {
            let b0 = unsafe { *table_ptr.add(offset) };
            let b1 = unsafe { *table_ptr.add(offset + 1) };
            
            if b0 == 0 && b1 == 0 {
                offset += 2;
                break;
            }
            offset += 1;
        }
    }
}

/// BIOS情報 (Type 0) をパース
fn parse_bios_info(info: &mut SmbiosInfo, table_ptr: *const u8, offset: usize, _length: usize) {
    // Type 0 構造体: offset+4 = Vendor string index, offset+5 = Version string index
    let vendor_idx = unsafe { *table_ptr.add(offset + 4) };
    let version_idx = unsafe { *table_ptr.add(offset + 5) };
    
    // 文字列テーブルのオフセットを記録（実際の文字列は構造体の後）
    // ここでは構造体開始からのオフセットを記録
    info.bios_vendor_offset = (offset as u32) | ((vendor_idx as u32) << 24);
    info.bios_version_offset = (offset as u32) | ((version_idx as u32) << 24);
    
    info.flags |= smbios_flags::BIOS_INFO_VALID;
}

/// システム情報 (Type 1) をパース
fn parse_system_info(info: &mut SmbiosInfo, table_ptr: *const u8, offset: usize, length: usize) {
    // Type 1 構造体:
    // offset+4 = Manufacturer string index
    // offset+5 = Product Name string index
    // offset+7 = Serial Number string index
    // offset+8..24 = UUID (16 bytes) - length >= 25 の場合のみ
    
    let manufacturer_idx = unsafe { *table_ptr.add(offset + 4) };
    let product_idx = unsafe { *table_ptr.add(offset + 5) };
    let serial_idx = unsafe { *table_ptr.add(offset + 7) };
    
    info.system_manufacturer_offset = (offset as u32) | ((manufacturer_idx as u32) << 24);
    info.system_product_offset = (offset as u32) | ((product_idx as u32) << 24);
    info.system_serial_offset = (offset as u32) | ((serial_idx as u32) << 24);
    
    // UUID (SMBIOS 2.1+)
    if length >= 25 {
        for i in 0..16 {
            info.system_uuid[i] = unsafe { *table_ptr.add(offset + 8 + i) };
        }
    }
    
    info.flags |= smbios_flags::SYSTEM_INFO_VALID;
}

/// SMBIOS情報の概要をシリアル出力
#[cfg(feature = "serial_log")]
fn log_system_uuid(uuid: &[u8; 16]) {
    if *uuid != [0; 16] {
        serial_println!("  System UUID: {:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            uuid[0], uuid[1], uuid[2], uuid[3],
            uuid[4], uuid[5],
            uuid[6], uuid[7],
            uuid[8], uuid[9],
            uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
        );
    }
}

pub fn log_smbios_info(info: &SmbiosInfo) {
    use crate::serial_println;
    
    serial_println!("[SMBIOS] Detection results:");
    
    if info.flags & smbios_flags::SMBIOS3_AVAILABLE != 0 {
        serial_println!("  SMBIOS 3.x: 0x{:016X}", info.smbios3_addr);
    }
    if info.flags & smbios_flags::SMBIOS2_AVAILABLE != 0 {
        serial_println!("  SMBIOS 2.x: 0x{:016X}", info.smbios_addr);
    }
    
    if info.major_version > 0 {
        serial_println!("  Version: {}.{}", info.major_version, info.minor_version);
        serial_println!("  Table max size: {} bytes", info.table_max_size);
    }
    
    if info.flags & smbios_flags::BIOS_INFO_VALID != 0 {
        serial_println!("  BIOS info: available");
    }
    
    if info.flags & smbios_flags::SYSTEM_INFO_VALID != 0 {
        serial_println!("  System info: available");
        log_system_uuid(&info.system_uuid);
    }
    
    if info.smbios3_addr == 0 && info.smbios_addr == 0 {
        serial_println!("  No SMBIOS tables found");
    }
}

/// SMBIOS情報の概要をシリアル出力（シリアル無効時はnoop）
#[cfg(not(feature = "serial_log"))]
pub fn log_smbios_info(_info: &SmbiosInfo) {
    // シリアルログ無効時は何もしない
}
