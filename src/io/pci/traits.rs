// ============================================================================
// src/io/pci/traits.rs - PCI Configuration Space Accessor Trait
// ============================================================================
//!
//! PCI/PCIe 共通アクセストレイト
//!
//! このトレイトにより、Legacy I/O ポートアクセスと ECAM アクセスを
//! 同一のインターフェースで扱うことができる。

use super::types::{BdfAddress, BarInfo, BarType, CapabilityId, config_regs, command_bits};

// ============================================================================
// Configuration Space Accessor Trait
// ============================================================================

/// PCI Configuration Space アクセサトレイト
///
/// Legacy I/O ポートベースのアクセスと ECAM (Memory-Mapped) アクセスの
/// 両方を抽象化する。
pub trait ConfigSpaceAccessor {
    /// 8ビット読み取り
    fn read8(&self, bdf: BdfAddress, offset: u16) -> u8;

    /// 16ビット読み取り
    fn read16(&self, bdf: BdfAddress, offset: u16) -> u16;

    /// 32ビット読み取り
    fn read32(&self, bdf: BdfAddress, offset: u16) -> u32;

    /// 8ビット書き込み
    fn write8(&self, bdf: BdfAddress, offset: u16, value: u8);

    /// 16ビット書き込み
    fn write16(&self, bdf: BdfAddress, offset: u16, value: u16);

    /// 32ビット書き込み
    fn write32(&self, bdf: BdfAddress, offset: u16, value: u32);

    // ========================================================================
    // Convenience methods with default implementations
    // ========================================================================

    /// ベンダーIDを読み取り
    fn read_vendor_id(&self, bdf: BdfAddress) -> u16 {
        self.read16(bdf, config_regs::VENDOR_ID)
    }

    /// デバイスIDを読み取り
    fn read_device_id(&self, bdf: BdfAddress) -> u16 {
        self.read16(bdf, config_regs::DEVICE_ID)
    }

    /// ベンダー/デバイスIDを読み取り
    fn read_vendor_device(&self, bdf: BdfAddress) -> (u16, u16) {
        let dword = self.read32(bdf, config_regs::VENDOR_ID);
        ((dword & 0xFFFF) as u16, (dword >> 16) as u16)
    }

    /// デバイスが存在するか確認
    fn device_exists(&self, bdf: BdfAddress) -> bool {
        self.read_vendor_id(bdf) != 0xFFFF
    }

    /// コマンドレジスタを読み取り
    fn read_command(&self, bdf: BdfAddress) -> u16 {
        self.read16(bdf, config_regs::COMMAND)
    }

    /// コマンドレジスタを書き込み
    fn write_command(&self, bdf: BdfAddress, value: u16) {
        self.write16(bdf, config_regs::COMMAND, value);
    }

    /// ステータスレジスタを読み取り
    fn read_status(&self, bdf: BdfAddress) -> u16 {
        self.read16(bdf, config_regs::STATUS)
    }

    /// クラスコードを読み取り (class, subclass, prog_if)
    fn read_class(&self, bdf: BdfAddress) -> (u8, u8, u8) {
        let class = self.read8(bdf, config_regs::CLASS_CODE);
        let subclass = self.read8(bdf, config_regs::SUBCLASS);
        let prog_if = self.read8(bdf, config_regs::PROG_IF);
        (class, subclass, prog_if)
    }

    /// ヘッダータイプを読み取り
    fn read_header_type(&self, bdf: BdfAddress) -> u8 {
        self.read8(bdf, config_regs::HEADER_TYPE)
    }

    /// マルチファンクションデバイスかどうか
    fn is_multifunction(&self, bdf: BdfAddress) -> bool {
        (self.read_header_type(bdf) & 0x80) != 0
    }

    /// Capability ポインタを読み取り
    fn read_capabilities_ptr(&self, bdf: BdfAddress) -> u8 {
        self.read8(bdf, config_regs::CAPABILITIES_PTR)
    }

    /// 割り込みライン/ピンを読み取り
    fn read_interrupt(&self, bdf: BdfAddress) -> (u8, u8) {
        let line = self.read8(bdf, config_regs::INTERRUPT_LINE);
        let pin = self.read8(bdf, config_regs::INTERRUPT_PIN);
        (line, pin)
    }

    /// 割り込みラインを書き込み
    fn write_interrupt_line(&self, bdf: BdfAddress, line: u8) {
        self.write8(bdf, config_regs::INTERRUPT_LINE, line);
    }

    // ========================================================================
    // Command Register Helpers
    // ========================================================================

    /// バスマスタを有効化
    fn enable_bus_master(&self, bdf: BdfAddress) {
        let cmd = self.read_command(bdf);
        self.write_command(bdf, cmd | command_bits::BUS_MASTER);
    }

    /// バスマスタを無効化
    fn disable_bus_master(&self, bdf: BdfAddress) {
        let cmd = self.read_command(bdf);
        self.write_command(bdf, cmd & !command_bits::BUS_MASTER);
    }

    /// メモリ空間アクセスを有効化
    fn enable_memory_space(&self, bdf: BdfAddress) {
        let cmd = self.read_command(bdf);
        self.write_command(bdf, cmd | command_bits::MEMORY_SPACE);
    }

    /// メモリ空間アクセスを無効化
    fn disable_memory_space(&self, bdf: BdfAddress) {
        let cmd = self.read_command(bdf);
        self.write_command(bdf, cmd & !command_bits::MEMORY_SPACE);
    }

    /// I/O空間アクセスを有効化
    fn enable_io_space(&self, bdf: BdfAddress) {
        let cmd = self.read_command(bdf);
        self.write_command(bdf, cmd | command_bits::IO_SPACE);
    }

    /// I/O空間アクセスを無効化
    fn disable_io_space(&self, bdf: BdfAddress) {
        let cmd = self.read_command(bdf);
        self.write_command(bdf, cmd & !command_bits::IO_SPACE);
    }

    /// 割り込みを無効化
    fn disable_interrupts(&self, bdf: BdfAddress) {
        let cmd = self.read_command(bdf);
        self.write_command(bdf, cmd | command_bits::INTERRUPT_DISABLE);
    }

    /// 割り込みを有効化
    fn enable_interrupts(&self, bdf: BdfAddress) {
        let cmd = self.read_command(bdf);
        self.write_command(bdf, cmd & !command_bits::INTERRUPT_DISABLE);
    }

    // ========================================================================
    // BAR Access
    // ========================================================================

    /// BAR を読み取り（生の値）
    fn read_bar_raw(&self, bdf: BdfAddress, bar_index: u8) -> u32 {
        if bar_index > 5 {
            return 0;
        }
        let offset = config_regs::BAR0 + (bar_index as u16) * 4;
        self.read32(bdf, offset)
    }

    /// BAR を書き込み
    fn write_bar(&self, bdf: BdfAddress, bar_index: u8, value: u32) {
        if bar_index > 5 {
            return;
        }
        let offset = config_regs::BAR0 + (bar_index as u16) * 4;
        self.write32(bdf, offset, value);
    }

    /// BAR 情報を取得
    fn read_bar_info(&self, bdf: BdfAddress, bar_index: u8) -> BarInfo {
        if bar_index > 5 {
            return BarInfo {
                index: bar_index,
                bar_type: BarType::Unused,
                base_address: 0,
                size: 0,
            };
        }

        let offset = config_regs::BAR0 + (bar_index as u16) * 4;
        let bar_value = self.read32(bdf, offset);

        // 未使用BAR
        if bar_value == 0 {
            return BarInfo {
                index: bar_index,
                bar_type: BarType::Unused,
                base_address: 0,
                size: 0,
            };
        }

        // I/O BAR
        if (bar_value & 1) != 0 {
            // サイズを計算
            self.write32(bdf, offset, 0xFFFFFFFF);
            let size_mask = self.read32(bdf, offset);
            self.write32(bdf, offset, bar_value); // 復元

            let size = !((size_mask | 0x3) as u64) + 1;
            let base = (bar_value & !0x3) as u64;

            return BarInfo {
                index: bar_index,
                bar_type: BarType::Io,
                base_address: base,
                size,
            };
        }

        // Memory BAR
        let prefetchable = (bar_value & 0x08) != 0;
        let bar_type_bits = (bar_value >> 1) & 0x3;

        match bar_type_bits {
            0 => {
                // 32-bit Memory
                self.write32(bdf, offset, 0xFFFFFFFF);
                let size_mask = self.read32(bdf, offset);
                self.write32(bdf, offset, bar_value);

                let size = !((size_mask | 0xF) as u64) + 1;
                let base = (bar_value & !0xF) as u64;

                BarInfo {
                    index: bar_index,
                    bar_type: BarType::Memory32 { prefetchable },
                    base_address: base,
                    size,
                }
            }
            2 => {
                // 64-bit Memory
                if bar_index > 4 {
                    return BarInfo {
                        index: bar_index,
                        bar_type: BarType::Unused,
                        base_address: 0,
                        size: 0,
                    };
                }

                let bar_high = self.read32(bdf, offset + 4);
                let base = ((bar_high as u64) << 32) | ((bar_value & !0xF) as u64);

                // サイズを計算
                self.write32(bdf, offset, 0xFFFFFFFF);
                self.write32(bdf, offset + 4, 0xFFFFFFFF);
                let size_low = self.read32(bdf, offset);
                let size_high = self.read32(bdf, offset + 4);
                self.write32(bdf, offset, bar_value);
                self.write32(bdf, offset + 4, bar_high);

                let size_mask = ((size_high as u64) << 32) | (size_low as u64);
                let size = !(size_mask | 0xF) + 1;

                BarInfo {
                    index: bar_index,
                    bar_type: BarType::Memory64 { prefetchable },
                    base_address: base,
                    size,
                }
            }
            _ => BarInfo {
                index: bar_index,
                bar_type: BarType::Unused,
                base_address: 0,
                size: 0,
            },
        }
    }

    // ========================================================================
    // Capability Walking
    // ========================================================================

    /// 指定したケーパビリティを検索
    fn find_capability(&self, bdf: BdfAddress, cap_id: CapabilityId) -> Option<u8> {
        let status = self.read_status(bdf);
        if (status & 0x10) == 0 {
            // Capabilities List bit not set
            return None;
        }

        let mut cap_ptr = self.read_capabilities_ptr(bdf) & 0xFC;
        let target_id = cap_id as u8;

        while cap_ptr != 0 {
            let cap_header = self.read16(bdf, cap_ptr as u16);
            let id = (cap_header & 0xFF) as u8;
            let next = ((cap_header >> 8) & 0xFC) as u8;

            if id == target_id {
                return Some(cap_ptr);
            }

            cap_ptr = next;
        }

        None
    }

    /// MSI ケーパビリティを検索
    fn find_msi_capability(&self, bdf: BdfAddress) -> Option<u8> {
        self.find_capability(bdf, CapabilityId::Msi)
    }

    /// MSI-X ケーパビリティを検索
    fn find_msix_capability(&self, bdf: BdfAddress) -> Option<u8> {
        self.find_capability(bdf, CapabilityId::MsiX)
    }

    /// PCIe ケーパビリティを検索
    fn find_pcie_capability(&self, bdf: BdfAddress) -> Option<u8> {
        self.find_capability(bdf, CapabilityId::PciExpress)
    }

    /// Power Management ケーパビリティを検索
    fn find_power_management_capability(&self, bdf: BdfAddress) -> Option<u8> {
        self.find_capability(bdf, CapabilityId::PowerManagement)
    }
}

// ============================================================================
// Extended Configuration Space Accessor (PCIe)
// ============================================================================

/// PCIe 拡張 Configuration Space アクセサトレイト
///
/// ECAM アクセスでのみ利用可能な 4KB 空間（256バイト以上）へのアクセスを提供。
pub trait ExtendedConfigSpaceAccessor: ConfigSpaceAccessor {
    /// 拡張空間が利用可能かどうか
    fn supports_extended_config(&self) -> bool {
        true
    }

    /// 拡張ケーパビリティを検索
    fn find_extended_capability(&self, bdf: BdfAddress, cap_id: u16) -> Option<u16> {
        if !self.supports_extended_config() {
            return None;
        }

        let mut cap_offset: u16 = 0x100; // Extended capabilities start at offset 0x100

        while cap_offset != 0 && cap_offset < 0x1000 {
            let cap_header = self.read32(bdf, cap_offset);
            if cap_header == 0 || cap_header == 0xFFFFFFFF {
                break;
            }

            let id = (cap_header & 0xFFFF) as u16;
            let next = ((cap_header >> 20) & 0xFFC) as u16;

            if id == cap_id {
                return Some(cap_offset);
            }

            cap_offset = next;
        }

        None
    }

    /// AER (Advanced Error Reporting) ケーパビリティを検索
    fn find_aer_capability(&self, bdf: BdfAddress) -> Option<u16> {
        self.find_extended_capability(bdf, 0x0001)
    }

    /// SR-IOV ケーパビリティを検索
    fn find_sriov_capability(&self, bdf: BdfAddress) -> Option<u16> {
        self.find_extended_capability(bdf, 0x0010)
    }

    /// Resizable BAR ケーパビリティを検索
    fn find_resizable_bar_capability(&self, bdf: BdfAddress) -> Option<u16> {
        self.find_extended_capability(bdf, 0x0015)
    }
}
