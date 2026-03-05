// ============================================================================
// kernel/src/net/drivers/mlx5_registry.rs - ConnectX-4 Lx Driver Registry
// ============================================================================
//!
//! ConnectX-4 Lx (mlx5) ドライバの DriverRegistry 統合。
//!
//! PCI バスからデバイスを検出し、BAR0 マッピング・DMA バッファ割り当て・
//! HCA 初期化シーケンスを実行して NIC をアクティブにする。
//!
//! VirtIO-Net と同じパターンで `Driver` トレイトを実装し、
//! `network_bootstrap_task()` から登録・probe・start される。

extern crate alloc;

use kernel_api::driver::{DeviceId, Driver, DriverType, DriverVersion};
use kernel_api::error::{KapiError, KapiResult};

use mlx5_driver::{
    CONNECTX4_LX_DEVICE_ID, CONNECTX4_LX_VF_DEVICE_ID, MELLANOX_VENDOR_ID,
    Mlx5Device,
};
use mlx5_driver::eq::EventQueue;
use mlx5_driver::cq::CompletionQueue;
use mlx5_driver::wq::{SendQueue, ReceiveQueue};

/// ConnectX-4 Lx のサポートデバイスID一覧
static SUPPORTED_DEVICES: [DeviceId; 2] = [
    DeviceId {
        vendor: MELLANOX_VENDOR_ID,
        device: CONNECTX4_LX_DEVICE_ID,
        subsystem_vendor: None,
        subsystem_device: None,
    },
    DeviceId {
        vendor: MELLANOX_VENDOR_ID,
        device: CONNECTX4_LX_VF_DEVICE_ID,
        subsystem_vendor: None,
        subsystem_device: None,
    },
];

/// ConnectX-4 Lx ドライバラッパー for DriverRegistry
pub struct Mlx5ConnectXDriver {
    /// 初期化済みかどうか
    initialized: bool,
    /// 内部デバイスインスタンス（probe成功後に保持）
    device: Option<Mlx5Device>,
}

impl Mlx5ConnectXDriver {
    /// 新しいドライバインスタンスを作成
    pub fn new() -> Self {
        Self {
            initialized: false,
            device: None,
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
        "mlx5-connectx4lx"
    }

    fn version(&self) -> DriverVersion {
        DriverVersion::new(0, 1, 0)
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Network
    }

    fn probe(&mut self) -> KapiResult<()> {
        log::info!(target: "mlx5", "Probing for ConnectX-4 Lx devices...");

        // PCI バスから Mellanox ConnectX-4 Lx (PF) を検索
        let pci_devices = crate::io::pci::find_by_id(MELLANOX_VENDOR_ID, CONNECTX4_LX_DEVICE_ID);

        if pci_devices.is_empty() {
            log::info!(target: "mlx5", "No ConnectX-4 Lx PF found, trying VF...");
            let vf_devices =
                crate::io::pci::find_by_id(MELLANOX_VENDOR_ID, CONNECTX4_LX_VF_DEVICE_ID);
            if vf_devices.is_empty() {
                log::info!(target: "mlx5", "No ConnectX-4 Lx devices found on PCI bus");
                return Err(KapiError::NotFound);
            }
            return self.probe_device(&vf_devices[0]);
        }

        self.probe_device(&pci_devices[0])
    }

    fn start(&mut self) -> KapiResult<()> {
        if !self.initialized {
            return Err(KapiError::Internal(-1));
        }

        log::info!(target: "mlx5", "ConnectX-4 Lx driver started");

        // TODO: ネットワークブリッジへの接続（VirtIO-Netのinit_bridge()相当）
        // 将来的にmlx5専用ブリッジアダプタを実装する。
        // 現時点ではデバイスの初期化完了をもってstartとする。

        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        log::info!(target: "mlx5", "ConnectX-4 Lx driver stopped");

        if let Some(ref mut dev) = self.device {
            // 安全にデバイスをシャットダウン
            unsafe {
                if let Err(e) = dev.teardown() {
                    log::warn!(target: "mlx5", "Teardown error: {:?}", e);
                }
            }
        }
        self.initialized = false;
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        &SUPPORTED_DEVICES
    }
}

/// log2 の整数計算（キュー深度からログサイズを得る）
fn log2_u32(val: u32) -> u8 {
    if val == 0 {
        return 0;
    }
    31 - val.leading_zeros() as u8
}

impl Mlx5ConnectXDriver {
    /// PCI デバイスの初期化を行う
    fn probe_device(&mut self, pci_dev: &crate::io::pci::PciDeviceInfo) -> KapiResult<()> {
        log::info!(
            target: "mlx5",
            "Found ConnectX-4 Lx at {:02x}:{:02x}.{} (vendor={:#06x} device={:#06x})",
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
            pci_dev.vendor_id.0,
            pci_dev.device_id.0,
        );

        // BAR0 の取得（64-bit MMIO）
        let bar0 = pci_dev.bars[0].ok_or_else(|| {
            log::error!(target: "mlx5", "BAR0 not found");
            KapiError::IoError
        })?;

        let bar0_base = bar0.base();
        let bar0_size = bar0.size() as usize;

        if bar0_base == 0 || bar0_size == 0 {
            log::error!(target: "mlx5", "BAR0 invalid: base={:#x} size={:#x}", bar0_base, bar0_size);
            return Err(KapiError::IoError);
        }

        log::info!(
            target: "mlx5",
            "BAR0: base={:#x} size={:#x} ({}KB)",
            bar0_base,
            bar0_size,
            bar0_size / 1024
        );

        // バスマスタを有効化（DMA用）
        pci_dev.enable_bus_master();

        // MSI-X セットアップ（ConnectX-4 Lx は MSI-X 必須）
        if let Some(msix_offset) = pci_dev.msix_cap_offset {
            log::info!(target: "mlx5", "MSI-X capability at offset {:#x}", msix_offset);
            // 将来的にMSI-Xベクタの割り当てを行う
            // 現時点ではポーリングモードで動作
        } else {
            log::warn!(target: "mlx5", "MSI-X not available; using polling mode");
        }

        // Mlx5Device を作成
        let mut device = Mlx5Device::new(bar0_base, bar0_size);
        device.set_pci_bdf(
            pci_dev.bdf.bus(),
            pci_dev.bdf.device(),
            pci_dev.bdf.function(),
        );

        // Phase 1: ファームウェア待機
        unsafe {
            device.wait_firmware().map_err(|e| {
                log::error!(target: "mlx5", "FW init failed: {:?}", e);
                KapiError::IoError
            })?;
        }

        // Phase 2: コマンドインタフェース初期化
        // DMA対応メモリの割り当て（コマンドキュー + 入出力メールボックス）
        //
        // 設計書 §2: Exchange Heap を通じた DMA バッファ管理
        // TODO: CoherentDmaBuffer API が安定したら移行する
        // 現在は SAS identity mapping を前提に BAR0 空間末尾を一時使用
        let cmdq_offset = bar0_size as u64 - 0x4000;
        let in_mbox_offset = bar0_size as u64 - 0x3000;
        let out_mbox_offset = bar0_size as u64 - 0x2000;

        let cmdq_virt = bar0_base + cmdq_offset;
        let cmdq_phys = cmdq_virt; // SAS identity map
        let in_mbox_virt = bar0_base + in_mbox_offset;
        let in_mbox_phys = in_mbox_virt;
        let out_mbox_virt = bar0_base + out_mbox_offset;
        let out_mbox_phys = out_mbox_virt;

        unsafe {
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
        }

        // Phase 3: HCA 有効化・初期化
        unsafe {
            device.enable_and_init_hca().map_err(|e| {
                log::error!(target: "mlx5", "HCA enable/init failed: {:?}", e);
                KapiError::IoError
            })?;
        }

        // Phase 4: ポートMAC取得（port 0）
        unsafe {
            device.query_port_mac(0).map_err(|e| {
                log::error!(target: "mlx5", "Port MAC query failed: {:?}", e);
                KapiError::IoError
            })?;
        }

        // ポート情報をログ出力
        if let Some(port) = device.port(0) {
            log::info!(
                target: "mlx5",
                "Port 0: MAC={} MTU={}",
                port.mac_address(),
                port.mtu()
            );
        }

        // Phase 5: キュー設定
        let uar_base = bar0_base + 0x800; // UAR page 0 offset
        device.set_uar(uar_base, 0);

        // Direct Memory Key (全DMAアクセス用)
        device.set_mkey(0xFF_FF_FF);

        // キューバッファ用のオフセット
        let eq_log_size = log2_u32(mlx5_driver::defs::MLX5_EQ_DEPTH);
        let cq_log_size = log2_u32(mlx5_driver::defs::MLX5_CQ_DEPTH);
        let sq_log_size = log2_u32(mlx5_driver::defs::MLX5_WQ_DEPTH);
        let rq_log_size = log2_u32(mlx5_driver::defs::MLX5_WQ_DEPTH);

        // Event Queue: EQN=0, MSI-Xベクタ0
        let eq_base = bar0_base + 0x1_0000;
        let eq = EventQueue::new(0, eq_base, eq_base, uar_base, eq_log_size, 0);
        device.add_eq(eq);

        // Completion Queues: TX CQ + RX CQ
        let cq_tx_base = bar0_base + 0x2_0000;
        let cq_tx_db = bar0_base + 0x2_F000;
        let tx_cq = CompletionQueue::new(0, cq_tx_base, cq_tx_base, uar_base, cq_tx_db, cq_log_size, 0);
        device.add_cq(tx_cq);

        let cq_rx_base = bar0_base + 0x3_0000;
        let cq_rx_db = bar0_base + 0x3_F000;
        let rx_cq = CompletionQueue::new(1, cq_rx_base, cq_rx_base, uar_base, cq_rx_db, cq_log_size, 0);
        device.add_cq(rx_cq);

        // Send Queue: SQN=0, CQN=0 (TX CQ), TISN=0, mkey
        let sq_base = bar0_base + 0x4_0000;
        let sq_db = bar0_base + 0x4_F000;
        let sq = SendQueue::new(0, sq_base, sq_base, sq_db, uar_base, sq_log_size, 0, 0, 0xFF_FF_FF);
        device.add_sq(sq);

        // Receive Queue: RQN=0, CQN=1 (RX CQ), TIRN=0, mkey
        let rq_base = bar0_base + 0x5_0000;
        let rq_db = bar0_base + 0x5_F000;
        let rq = ReceiveQueue::new(0, rq_base, rq_base, rq_db, rq_log_size, 1, 0, 0xFF_FF_FF);
        device.add_rq(rq);

        // キューセットアップ完了 → アクティベーション
        device.mark_queues_ready();
        device.activate();

        log::info!(target: "mlx5", "ConnectX-4 Lx device initialized and active");
        self.device = Some(device);
        self.initialized = true;
        Ok(())
    }
}
