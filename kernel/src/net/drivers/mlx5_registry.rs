// ============================================================================
// kernel/src/net/drivers/mlx5_registry.rs - ConnectX Family Driver Registry
// ============================================================================
//!
//! ConnectX ファミリ (mlx5) ドライバの DriverRegistry 統合。
//!
//! ConnectX-4 / 4 Lx / 5 / 5 Ex / 6 / 6 Dx / 6 Lx / 7 をサポート。
//!
//! PCI バスからデバイスを検出し、BAR0 マッピング・DMA バッファ割り当て・
//! HCA 初期化シーケンスを実行して NIC をアクティブにする。
//!
//! ## 初期化フロー
//!
//! 1. PCI バス検出 (Vendor=0x15B3, 全 ConnectX Device ID)
//! 2. BAR0 マッピング → FW Ready 待ち
//! 3. コマンドインタフェース初期化
//! 4. ENABLE_HCA → QUERY_ISSI → SET_ISSI → QUERY_HCA_CAP → INIT_HCA
//! 5. MANAGE_PAGES（FW要求ページ提供）
//! 6. CREATE_MKEY → CREATE_TIS → CREATE_TIR
//! 7. キュー作成（EQ, CQ, SQ, RQ）
//! 8. フローテーブル設定（RX steering）
//! 9. デバイスアクティベーション → ブリッジ接続

extern crate alloc;

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use mlx5_driver::{
    MELLANOX_VENDOR_ID, SUPPORTED_DEVICE_IDS, ConnectXVariant,
    Mlx5Device,
};
use mlx5_driver::eq::EventQueue;
use mlx5_driver::cq::CompletionQueue;
use mlx5_driver::wq::{SendQueue, ReceiveQueue};
use mlx5_driver::resources::{TisParams, TirParams, TirReceiveType, MkeyParams};

const CONNECTX4_LX_VF_ID: u16 = 0x1016;

/// ConnectX ファミリのサポートデバイスID一覧を動的構築
fn build_supported_devices() -> alloc::vec::Vec<DeviceId> {
    SUPPORTED_DEVICE_IDS
        .iter()
        .map(|&(vendor, device)| DeviceId {
            vendor,
            device,
            subsystem_vendor: None,
            subsystem_device: None,
        })
        .collect()
}

/// ConnectX ファミリドライバラッパー for DriverRegistry
pub struct Mlx5ConnectXDriver {
    /// 初期化済みかどうか
    initialized: bool,
    /// 内部デバイスインスタンス（probe成功後に保持）
    device: Option<Mlx5Device>,
    /// サポートデバイスリスト（動的構築）
    supported_devices: alloc::vec::Vec<DeviceId>,
}

impl Mlx5ConnectXDriver {
    /// 新しいドライバインスタンスを作成
    pub fn new() -> Self {
        Self {
            initialized: false,
            device: None,
            supported_devices: build_supported_devices(),
        }
    }
}

impl Default for Mlx5ConnectXDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for Mlx5ConnectXDriver {
    fn name(&self) -> &str {
        "mlx5"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 3, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Network
    }

    fn probe(&mut self) -> KapiResult<()> {
        crate::io::log::early_print("[MLX5DBG] probe enter\n");
        log::info!(target: "mlx5", "Probing for ConnectX family devices...");

        // SUPPORTED_DEVICE_IDS をイテレートして最初に見つかったデバイスを初期化
        for &(_vendor_id, device_id) in SUPPORTED_DEVICE_IDS {
            let pci_devices = crate::io::pci::find_by_id(MELLANOX_VENDOR_ID, device_id);
            if !pci_devices.is_empty() {
                let variant = ConnectXVariant::from_device_id(device_id);
                log::info!(
                    target: "mlx5",
                    "Found {} (device_id={:#06x})",
                    variant.name(),
                    device_id,
                );
                crate::io::log::early_print("[MLX5DBG] probing first device\n");
                return self.probe_device(&pci_devices[0]);
            }
        }

        log::info!(target: "mlx5", "No ConnectX family devices found on PCI bus");
        Err(KapiError::NotFound)
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }

        let variant_name = self.device.as_ref()
            .map(|d| d.variant().name())
            .unwrap_or("ConnectX");
        log::info!(target: "mlx5", "{} driver started", variant_name);
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        let variant_name = self.device.as_ref()
            .map(|d| d.variant().name())
            .unwrap_or("ConnectX");
        log::info!(target: "mlx5", "{} driver stopping...", variant_name);

        if let Some(ref mut dev) = self.device {
            // 安全にデバイスをシャットダウン
            unsafe {
                if let Err(e) = dev.teardown() {
                    log::warn!(target: "mlx5", "Teardown error: {:?}", e);
                }
            }
        }
        self.initialized = false;
        log::info!(target: "mlx5", "{} driver stopped", variant_name);
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        &self.supported_devices
    }
}

/// log2 の整数計算（キュー深度からログサイズを得る）
fn log2_u32(val: u32) -> u8 {
    if val == 0 {
        return 0;
    }
    31 - val.leading_zeros() as u8
}

fn ensure_bar_mapped(base_phys: u64, bar_size: u64) -> Option<u64> {
    if base_phys == 0 || bar_size == 0 {
        return None;
    }

    let base_virt = crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(base_phys)).as_u64();
    let page_size = 0x1000u64;
    let map_size = crate::util::align_up_u64(bar_size, page_size);
    let virt_start = crate::mm::virt::higher_half::VirtAddr::new(base_virt);
    let phys_start = crate::mm::virt::higher_half::PhysAddr::new(base_phys);

    if let Some(pte) = crate::mm::virt::higher_half::get_current_pte(virt_start) {
        if pte.is_present() && pte.phys_addr() == phys_start {
            return Some(base_virt);
        }
    }

    let pm_offset = crate::mm::virt::higher_half::physical_memory_offset();
    let mut manager = unsafe { crate::mm::virt::higher_half::PageTableManager::from_current_cr3(pm_offset) };
    let flags = crate::mm::virt::higher_half::PageFlags::write_combining();
    match unsafe { manager.map_range(virt_start, phys_start, map_size, flags) } {
        Ok(()) | Err(crate::mm::virt::higher_half::MapError::AlreadyMapped) => Some(base_virt),
        Err(err) => {
            log::error!(
                target: "mlx5",
                "BAR mapping failed: phys={:#x} size={:#x} err={:?}",
                base_phys,
                bar_size,
                err
            );
            None
        }
    }
}

impl Mlx5ConnectXDriver {
    /// PCI デバイスの完全な初期化を行う
    ///
    /// ConnectX ファミリの初期化シーケンス:
    /// Phase 1: FW Ready Wait
    /// Phase 2: Command Interface Setup
    /// Phase 3: HCA Enable & Init (ENABLE_HCA, ISSI, QUERY_HCA_CAP, INIT_HCA)
    /// Phase 4: Page Management (MANAGE_PAGES)
    /// Phase 5: Port MAC Query
    /// Phase 6: Resource Creation (MKEY, TIS, TIR)
    /// Phase 7: Queue Setup (EQ, CQ, SQ, RQ)
    /// Phase 8: Flow Table Setup (RX Steering)
    /// Phase 9: Activation
    fn probe_device(&mut self, pci_dev: &crate::io::pci::PciDeviceInfo) -> KapiResult<()> {
        let variant = ConnectXVariant::from_device_id(pci_dev.device_id.0);
        crate::io::log::early_print("[MLX5DBG] probe_device enter\n");
        log::info!(
            target: "mlx5",
            "Initializing {} at {:02x}:{:02x}.{} (vendor={:#06x} device={:#06x})",
            variant.name(),
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
            pci_dev.vendor_id.0,
            pci_dev.device_id.0,
        );

        // ================================================================
        // BAR0 取得
        // ================================================================
        let bar0 = pci_dev.bars[0].ok_or_else(|| {
            log::error!(target: "mlx5", "BAR0 not found");
            KapiError::IoError
        })?;

        let bar0_phys = bar0.base();
        let bar0_size_u64 = bar0.size();
        let bar0_size = bar0_size_u64 as usize;

        if bar0_phys == 0 || bar0_size == 0 {
            log::error!(
                target: "mlx5",
                "BAR0 invalid: phys={:#x} size={:#x}",
                bar0_phys,
                bar0_size
            );
            return Err(KapiError::IoError);
        }

        let bar0_base = match ensure_bar_mapped(bar0_phys, bar0_size_u64) {
            Some(virt) => virt,
            None => {
                log::error!(
                    target: "mlx5",
                    "BAR0 mapping failed: phys={:#x} size={:#x}",
                    bar0_phys,
                    bar0_size
                );
                return Err(KapiError::IoError);
            }
        };

        if bar0_base == 0 {
            log::error!(
                target: "mlx5",
                "BAR0 virtual base is zero after mapping: phys={:#x}",
                bar0_phys
            );
            return Err(KapiError::IoError);
        }

        log::info!(
            target: "mlx5",
            "BAR0: phys={:#x} virt={:#x} size={:#x} ({}KB)",
            bar0_phys,
            bar0_base,
            bar0_size,
            bar0_size / 1024
        );

        // バスマスタを有効化（DMA用）
        pci_dev.enable_bus_master();
        pci_dev.enable_memory_space();

        // MSI-X セットアップ
        if let Some(msix_offset) = pci_dev.msix_cap_offset {
            log::info!(target: "mlx5", "MSI-X capability at offset {:#x}", msix_offset);
        } else {
            log::warn!(target: "mlx5", "MSI-X not available; using polling mode");
        }

        // ================================================================
        // Phase 1: Mlx5Device 作成 & FW Ready
        // ================================================================
        let mut device = Mlx5Device::new(bar0_base, bar0_size, pci_dev.device_id.0);
        device.set_pci_bdf(
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
        );

        unsafe {
            crate::io::log::early_print("[MLX5DBG] before wait_firmware\n");
            match device.wait_firmware() {
                Ok(()) => {}
                Err(e) => {
                    if pci_dev.device_id.0 == CONNECTX4_LX_VF_ID {
                        log::warn!(
                            target: "mlx5",
                            "FW ready wait failed on VF ({:?}); continuing with VF fallback",
                            e
                        );
                        device.assume_firmware_ready_for_vf();
                    } else {
                        log::error!(target: "mlx5", "FW init failed: {:?}", e);
                        return Err(KapiError::IoError);
                    }
                }
            }
            crate::io::log::early_print("[MLX5DBG] after wait_firmware\n");
        }

        // ================================================================
        // Phase 2: コマンドインタフェース初期化
        // ================================================================
        // DMA対応メモリの割り当て（コマンドキュー + 入出力メールボックス）
        //
        // 設計書 §2: Exchange Heap を通じた DMA バッファ管理
        // TODO: CoherentDmaBuffer API が安定したら移行する
        // 現在は SAS identity mapping を前提に BAR0 空間末尾を一時使用
        let cmdq_offset = bar0_size as u64 - 0x4000;
        let in_mbox_offset = bar0_size as u64 - 0x3000;
        let out_mbox_offset = bar0_size as u64 - 0x2000;

        let cmdq_virt = bar0_base + cmdq_offset;
        let cmdq_phys = bar0_phys + cmdq_offset;
        let in_mbox_virt = bar0_base + in_mbox_offset;
        let in_mbox_phys = bar0_phys + in_mbox_offset;
        let out_mbox_virt = bar0_base + out_mbox_offset;
        let out_mbox_phys = bar0_phys + out_mbox_offset;

        unsafe {
            crate::io::log::early_print("[MLX5DBG] before init_cmd_if\n");
            device
                .init_command_interface(
                    cmdq_virt, cmdq_phys,
                    in_mbox_virt, in_mbox_phys,
                    out_mbox_virt, out_mbox_phys,
                )
                .map_err(|e| {
                    log::error!(target: "mlx5", "CMD interface init failed: {:?}", e);
                    KapiError::IoError
                })?;
            crate::io::log::early_print("[MLX5DBG] after init_cmd_if\n");
        }

        // ================================================================
        // Phase 3: HCA 有効化・初期化
        // ================================================================
        unsafe {
            crate::io::log::early_print("[MLX5DBG] before enable_and_init_hca\n");
            device.enable_and_init_hca().map_err(|e| {
                log::error!(target: "mlx5", "HCA enable/init failed: {:?}", e);
                KapiError::IoError
            })?;
            crate::io::log::early_print("[MLX5DBG] after enable_and_init_hca\n");
        }

        // ================================================================
        // Phase 4: FW ページ管理
        // ================================================================
        // ConnectX FWは初期化中にページを要求する
        // 初期ブートページを提供（SAS identity map: phys == virt）
        let boot_page_base = bar0_phys + bar0_size as u64 - 0x10_0000;
        let boot_page_count = 4u32; // 最小限のブートページ
        let mut boot_pas = alloc::vec::Vec::with_capacity(boot_page_count as usize);
        for i in 0..boot_page_count {
            boot_pas.push(boot_page_base + (i as u64) * 0x1000);
        }

        unsafe {
            if let Err(e) = device.provide_pages(0, &boot_pas) {
                // ページ提供失敗は致命的ではない（FWが要求しない場合もある）
                log::warn!(target: "mlx5", "Boot page provision: {:?} (non-fatal)", e);
            }
        }

        // ================================================================
        // Phase 5: ポートMAC取得
        // ================================================================
        unsafe {
            device.query_port_mac(0).map_err(|e| {
                log::error!(target: "mlx5", "Port MAC query failed: {:?}", e);
                KapiError::IoError
            })?;
        }

        if let Some(port) = device.port(0) {
            log::info!(
                target: "mlx5",
                "Port 0: MAC={} MTU={}",
                port.mac_address(),
                port.mtu()
            );
        }

        // ================================================================
        // Phase 6: リソース作成 (MKEY, TIS, TIR)
        // ================================================================

        // Direct Memory Key 作成（全DMAアクセス用）
        let mkey_params = MkeyParams::default();
        let mkey = unsafe {
            device.create_mkey(&mkey_params).unwrap_or_else(|e| {
                log::warn!(target: "mlx5", "MKEY creation failed: {:?}, using direct key", e);
                0xFF_FF_FF // fallback: direct key
            })
        };

        // TIS 作成（送信インタフェース）
        let tis_params = TisParams {
            port: 1, // ポート1
            ..TisParams::default()
        };
        let tisn = unsafe {
            device.create_tis(&tis_params).unwrap_or_else(|e| {
                log::warn!(target: "mlx5", "TIS creation failed: {:?}, using TISN=0", e);
                0
            })
        };

        // ================================================================
        // Phase 7: キュー設定
        // ================================================================
        let uar_base = bar0_base + 0x800; // UAR page 0 offset
        device.set_uar(uar_base, 0);
        device.set_mkey(mkey);

        let eq_log_size = log2_u32(mlx5_driver::defs::MLX5_EQ_DEPTH);
        let cq_log_size = log2_u32(mlx5_driver::defs::MLX5_CQ_DEPTH);
        let sq_log_size = log2_u32(mlx5_driver::defs::MLX5_WQ_DEPTH);
        let rq_log_size = log2_u32(mlx5_driver::defs::MLX5_WQ_DEPTH);

        // Event Queue: EQN=0, MSI-Xベクタ0
        let eq_base_virt = bar0_base + 0x1_0000;
        let eq_base_phys = bar0_phys + 0x1_0000;
        let eq = EventQueue::new(0, eq_base_virt, eq_base_phys, uar_base, eq_log_size, 0);
        device.add_eq(eq);

        // Completion Queues: TX CQ + RX CQ
        let cq_tx_base_virt = bar0_base + 0x2_0000;
        let cq_tx_base_phys = bar0_phys + 0x2_0000;
        let cq_tx_db = bar0_base + 0x2_F000;
        let tx_cq = CompletionQueue::new(
            0,
            cq_tx_base_virt,
            cq_tx_base_phys,
            uar_base,
            cq_tx_db,
            cq_log_size,
            0,
        );
        device.add_cq(tx_cq);

        let cq_rx_base_virt = bar0_base + 0x3_0000;
        let cq_rx_base_phys = bar0_phys + 0x3_0000;
        let cq_rx_db = bar0_base + 0x3_F000;
        let rx_cq = CompletionQueue::new(
            1,
            cq_rx_base_virt,
            cq_rx_base_phys,
            uar_base,
            cq_rx_db,
            cq_log_size,
            0,
        );
        device.add_cq(rx_cq);

        // Send Queue: SQN=0, CQN=0 (TX CQ), TISN from create_tis, mkey
        let sq_base_virt = bar0_base + 0x4_0000;
        let sq_base_phys = bar0_phys + 0x4_0000;
        let sq_db = bar0_base + 0x4_F000;
        let sq = SendQueue::new(
            0,
            sq_base_virt,
            sq_base_phys,
            sq_db,
            uar_base,
            sq_log_size,
            tisn,
            0,
            mkey,
        );
        device.add_sq(sq);

        // Receive Queue: RQN=0, CQN=1 (RX CQ), TIRN=0 (set after TIR creation), mkey
        let rq_base_virt = bar0_base + 0x5_0000;
        let rq_base_phys = bar0_phys + 0x5_0000;
        let rq_db = bar0_base + 0x5_F000;
        let rq = ReceiveQueue::new(
            0,
            rq_base_virt,
            rq_base_phys,
            rq_db,
            rq_log_size,
            1,
            0,
            mkey,
        );
        device.add_rq(rq);

        // キューセットアップ完了
        device.mark_queues_ready();

        // ================================================================
        // Phase 8: TIR 作成 & フローテーブル設定
        // ================================================================

        // TIR 作成（直接RQ配送: RQN=0）
        let tir_params = TirParams {
            receive_type: TirReceiveType::DirectRq,
            inline_rqn: 0, // RQN=0
            ..TirParams::default()
        };
        let tirn = unsafe {
            device.create_tir(&tir_params).unwrap_or_else(|e| {
                log::warn!(target: "mlx5", "TIR creation failed: {:?}", e);
                0
            })
        };

        // RXフローテーブル設定（catch-all → TIR）
        unsafe {
            if let Err(e) = device.setup_rx_flow_table(tirn) {
                log::warn!(target: "mlx5", "Flow table setup failed: {:?} (non-fatal)", e);
            }
        }

        // ================================================================
        // Phase 9: アクティベーション
        // ================================================================
        device.activate();

        log::info!(
            target: "mlx5",
            "{} device initialized and active \
             MKEY={:#x} TISN={} TIRN={} polling={}",
            variant.name(), mkey, tisn, tirn, device.polling_state().mode()
        );

        self.device = Some(device);
        self.initialized = true;
        Ok(())
    }
}
