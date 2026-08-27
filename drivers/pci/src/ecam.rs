// ============================================================================
// src/io/pci/ecam.rs - PCIe Enhanced Configuration Access Mechanism
// ============================================================================
//!
//! # ECAM (Enhanced Configuration Access Mechanism)
//!
//! PCIe設定空間へのメモリマップドアクセスを提供。
//! 4KBの設定空間にアクセス可能（PCIe拡張設定空間を含む）。

use crate::traits::ConfigSpaceAccessor;
use crate::types::BdfAddress;

// ============================================================================
// ECAM Implementation
// ============================================================================

/// ECAM (Enhanced Configuration Access Mechanism)
///
/// PCIe設定空間へのメモリマップドアクセスを提供します。
/// ACPIのMCFGテーブルからベースアドレスを取得して初期化します。
pub struct EcamAccess {
    /// Process-lifetime ECAM mapping owned by this accessor.
    registers: hal::MappedMmio,
    /// PCIセグメントグループ番号
    segment: u16,
    /// 対応する開始バス番号
    start_bus: u8,
    /// 対応する終了バス番号
    end_bus: u8,
}

impl EcamAccess {
    /// 新しいECAMアクセスを作成
    ///
    /// # Arguments
    /// * `registers` - validated ECAM mapping capability
    /// * `segment` - PCIセグメントグループ番号（通常0）
    /// * `start_bus` - 開始バス番号
    /// * `end_bus` - 終了バス番号
    pub const fn new(registers: hal::MappedMmio, segment: u16, start_bus: u8, end_bus: u8) -> Self {
        Self {
            registers,
            segment,
            start_bus,
            end_bus,
        }
    }

    /// セグメント番号を取得
    pub const fn segment(&self) -> u16 {
        self.segment
    }

    /// 開始バス番号を取得
    pub const fn start_bus(&self) -> u8 {
        self.start_bus
    }

    /// 終了バス番号を取得
    pub const fn end_bus(&self) -> u8 {
        self.end_bus
    }

    /// BDFアドレスがこのECAM範囲内かどうかを確認
    pub fn contains(&self, bdf: BdfAddress) -> bool {
        bdf.bus.0 >= self.start_bus && bdf.bus.0 <= self.end_bus
    }

    /// ECAM設定空間アドレスを計算
    ///
    /// ECAM アドレス計算:
    /// Address = Base + ((Bus - StartBus) << 20) + (Device << 15) + (Function << 12) + Offset
    fn config_offset(&self, bdf: BdfAddress, offset: u16) -> Option<usize> {
        if !self.contains(bdf) {
            return None;
        }

        let bus_offset = usize::from(bdf.bus.0 - self.start_bus);
        let device_offset = usize::from(bdf.device.0 & 0x1F);
        let function_offset = usize::from(bdf.function.0 & 0x07);
        let register_offset = usize::from(offset & 0xFFF);

        (bus_offset << 20)
            .checked_add(device_offset << 15)?
            .checked_add(function_offset << 12)?
            .checked_add(register_offset)
    }
}

impl ConfigSpaceAccessor for EcamAccess {
    fn read8(&self, bdf: BdfAddress, offset: u16) -> u8 {
        self.config_offset(bdf, offset)
            .and_then(|offset| self.registers.region().read_only::<u8>(offset).ok())
            .map(|register| register.read())
            .unwrap_or(0xFF)
    }

    fn read16(&self, bdf: BdfAddress, offset: u16) -> u16 {
        // 16ビット境界にアラインメント
        let aligned_offset = offset & !1;
        self.config_offset(bdf, aligned_offset)
            .and_then(|offset| self.registers.region().read_only::<u16>(offset).ok())
            .map(|register| register.read())
            .unwrap_or(0xFFFF)
    }

    fn read32(&self, bdf: BdfAddress, offset: u16) -> u32 {
        // 32ビット境界にアラインメント
        let aligned_offset = offset & !3;
        self.config_offset(bdf, aligned_offset)
            .and_then(|offset| self.registers.region().read_only::<u32>(offset).ok())
            .map(|register| register.read())
            .unwrap_or(0xFFFF_FFFF)
    }

    fn write8(&self, bdf: BdfAddress, offset: u16, value: u8) {
        if let Some(mut register) = self
            .config_offset(bdf, offset)
            .and_then(|offset| self.registers.region().write_only::<u8>(offset).ok())
        {
            register.write(value);
        }
    }

    fn write16(&self, bdf: BdfAddress, offset: u16, value: u16) {
        // 16ビット境界にアラインメント
        let aligned_offset = offset & !1;
        if let Some(mut register) = self
            .config_offset(bdf, aligned_offset)
            .and_then(|offset| self.registers.region().write_only::<u16>(offset).ok())
        {
            register.write(value);
        }
    }

    fn write32(&self, bdf: BdfAddress, offset: u16, value: u32) {
        // 32ビット境界にアラインメント
        let aligned_offset = offset & !3;
        if let Some(mut register) = self
            .config_offset(bdf, aligned_offset)
            .and_then(|offset| self.registers.region().write_only::<u32>(offset).ok())
        {
            register.write(value);
        }
    }
}

// ============================================================================
// ECAM Manager - 複数セグメント対応
// ============================================================================

/// ECAMマネージャ
///
/// 複数のPCIセグメントに対応するECAMアクセスを管理
pub struct EcamManager {
    /// ECAM領域のリスト（最大16セグメント）
    regions: [Option<EcamAccess>; 16],
    /// 登録されている領域数
    count: usize,
}

impl EcamManager {
    /// 新しいECAMマネージャを作成
    pub const fn new() -> Self {
        Self {
            regions: [const { None }; 16],
            count: 0,
        }
    }

    /// ECAM領域を追加
    pub fn add_region(&mut self, ecam: EcamAccess) -> bool {
        if self.count >= self.regions.len() {
            return false;
        }
        self.regions[self.count] = Some(ecam);
        self.count += 1;
        true
    }

    /// BDFアドレスに対応するECAMを検索
    pub fn find_ecam(&self, bdf: BdfAddress) -> Option<&EcamAccess> {
        for i in 0..self.count {
            if let Some(ref ecam) = self.regions[i] {
                if ecam.contains(bdf) {
                    return Some(ecam);
                }
            }
        }
        None
    }

    /// 設定空間を読み取り（8ビット）
    pub fn read8(&self, bdf: BdfAddress, offset: u16) -> Option<u8> {
        self.find_ecam(bdf).map(|e| e.read8(bdf, offset))
    }

    /// 設定空間を読み取り（16ビット）
    pub fn read16(&self, bdf: BdfAddress, offset: u16) -> Option<u16> {
        self.find_ecam(bdf).map(|e| e.read16(bdf, offset))
    }

    /// 設定空間を読み取り（32ビット）
    pub fn read32(&self, bdf: BdfAddress, offset: u16) -> Option<u32> {
        self.find_ecam(bdf).map(|e| e.read32(bdf, offset))
    }

    /// 設定空間に書き込み（8ビット）
    pub fn write8(&self, bdf: BdfAddress, offset: u16, value: u8) {
        if let Some(ecam) = self.find_ecam(bdf) {
            ecam.write8(bdf, offset, value);
        }
    }

    /// 設定空間に書き込み（16ビット）
    pub fn write16(&self, bdf: BdfAddress, offset: u16, value: u16) {
        if let Some(ecam) = self.find_ecam(bdf) {
            ecam.write16(bdf, offset, value);
        }
    }

    /// 設定空間に書き込み（32ビット）
    pub fn write32(&self, bdf: BdfAddress, offset: u16, value: u32) {
        if let Some(ecam) = self.find_ecam(bdf) {
            ecam.write32(bdf, offset, value);
        }
    }
}

impl Default for EcamManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Extended Configuration Space (PCIe specific)
// ============================================================================

/// 拡張設定空間オフセット（0x100〜0xFFF）
pub mod ext_config {
    /// 拡張ケーパビリティヘッダの開始
    pub const EXT_CAP_START: u16 = 0x100;

    /// 拡張設定空間の終端
    pub const EXT_CAP_END: u16 = 0xFFF;
}

/// 拡張ケーパビリティヘッダ
#[derive(Clone, Copy, Debug)]
pub struct ExtendedCapabilityHeader {
    /// ケーパビリティID
    pub id: u16,
    /// バージョン
    pub version: u8,
    /// 次のケーパビリティへのオフセット
    pub next_offset: u16,
}

impl ExtendedCapabilityHeader {
    /// 32ビット値から解析
    pub fn from_u32(value: u32) -> Self {
        Self {
            id: (value & 0xFFFF) as u16,
            version: ((value >> 16) & 0x0F) as u8,
            next_offset: ((value >> 20) & 0xFFF) as u16,
        }
    }

    /// 有効なヘッダかどうか
    pub fn is_valid(&self) -> bool {
        self.id != 0 && self.id != 0xFFFF
    }
}

/// 拡張ケーパビリティを列挙するイテレータ
pub struct ExtendedCapabilityIterator<'a> {
    accessor: &'a dyn ConfigSpaceAccessor,
    bdf: BdfAddress,
    current_offset: u16,
}

impl<'a> ExtendedCapabilityIterator<'a> {
    /// 新しいイテレータを作成
    pub fn new(accessor: &'a dyn ConfigSpaceAccessor, bdf: BdfAddress) -> Self {
        Self {
            accessor,
            bdf,
            current_offset: ext_config::EXT_CAP_START,
        }
    }
}

impl<'a> Iterator for ExtendedCapabilityIterator<'a> {
    type Item = (u16, ExtendedCapabilityHeader);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset == 0 || self.current_offset > ext_config::EXT_CAP_END {
            return None;
        }

        let value = self.accessor.read32(self.bdf, self.current_offset);
        if value == 0xFFFF_FFFF || value == 0 {
            return None;
        }

        let header = ExtendedCapabilityHeader::from_u32(value);
        if !header.is_valid() {
            return None;
        }

        let offset = self.current_offset;
        self.current_offset = header.next_offset;

        Some((offset, header))
    }
}
