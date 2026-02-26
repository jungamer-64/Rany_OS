// ============================================================================
// kernel/src/io/iommu/groups.rs
// ============================================================================

//! IOMMU Group Management
//!
//! PCIeトポロジーに基づいたIOMMUグルーピングを管理する。
//! ACS (Access Control Services) 対応ブリッジによるデバイス分離を検出し、
//! 分離不可能なデバイス群を同一IOMMUドメインに割り当てる。

use crate::io::iommu::intel::controller::dma::DomainManager;
use crate::io::iommu::intel::controller::IommuController;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError};
use crate::io::iommu::types::{IommuGroup, IommuGroupId};
use crate::sync::PoisonLock;
use hashbrown::HashMap;
use spin::Once;

// ============================================================================
// PCI Topology Abstraction
// ============================================================================

/// PCIeトポロジー問い合わせを抽象化するトレイト。
///
/// 本番コードは `RealPciTopology` (PcieExtManager委譲) を使用し、
/// QEMUスモークテストは `MockPciTopology` を注入する。
pub trait PciTopologyProvider {
    /// 指定BDFのヘッダタイプレジスタを読取る (Type 0 = エンドポイント, Type 1 = ブリッジ)。
    /// デバイスが存在しない場合は None を返す。
    fn read_header_type(&self, bus: u8, device: u8, function: u8) -> Option<u8>;

    /// 指定BDFのブリッジ/ポートでACS分離が有効かを確認する。
    /// ACSケイパビリティがない場合は None を返す。
    fn is_acs_isolation_enabled(&self, bus: u8, device: u8, function: u8) -> Option<bool>;

    /// `child_bus` を所有する親ブリッジを検索する。
    /// 見つかった場合は (bus, device, function) を返す。
    /// ルートバス (bus 0) の場合は None を返す。
    fn find_parent_bridge(&self, child_bus: u8) -> Option<(u8, u8, u8)>;
}

// ============================================================================
// Real PCI Topology (production - delegates to pci_driver crate)
// ============================================================================

#[cfg(not(test))]
pub struct RealPciTopology {
    ext_manager: &'static pci_driver::PcieExtManager,
}

#[cfg(not(test))]
impl RealPciTopology {
    pub fn new(ext_manager: &'static pci_driver::PcieExtManager) -> Self {
        Self { ext_manager }
    }
}

#[cfg(not(test))]
impl PciTopologyProvider for RealPciTopology {
    fn read_header_type(&self, bus: u8, device: u8, function: u8) -> Option<u8> {
        let bdf = pci_driver::PcieBdf::new(bus, device, function);
        self.ext_manager
            .config()
            .read8(bdf, pci_driver::config_regs::HEADER_TYPE)
    }

    fn is_acs_isolation_enabled(&self, bus: u8, device: u8, function: u8) -> Option<bool> {
        let bdf = pci_driver::PcieBdf::new(bus, device, function);
        pci_driver::AcsController::new(self.ext_manager.config(), bdf)
            .ok()
            .map(|acs| acs.is_isolation_enabled())
    }

    fn find_parent_bridge(&self, child_bus: u8) -> Option<(u8, u8, u8)> {
        let config = self.ext_manager.config();
        for device_info in self.ext_manager.devices() {
            let ht = config
                .read8(device_info.bdf, pci_driver::config_regs::HEADER_TYPE)
                .unwrap_or(0);
            if (ht & 0x7F) == 0x01 {
                // Secondary Bus Number register (offset 0x19) for Type 1 headers
                let secondary_bus = config.read8(device_info.bdf, 0x19).unwrap_or(0);
                if secondary_bus == child_bus {
                    return Some((
                        device_info.bdf.bus,
                        device_info.bdf.device,
                        device_info.bdf.function,
                    ));
                }
            }
        }
        None
    }
}

// ============================================================================
// IOMMU Group Manager
// ============================================================================

/// IOMMUグループの割当・検索を管理する。
pub struct IommuGroupManager {
    /// IommuGroupId から IommuGroup へのマップ。
    groups: PoisonLock<HashMap<IommuGroupId, IommuGroup>>,
    /// デバイスが割当済みのグループを追跡する。
    device_to_group: PoisonLock<HashMap<DeviceId, IommuGroupId>>,
}

impl IommuGroupManager {
    pub fn new() -> Self {
        Self {
            groups: PoisonLock::new(HashMap::new()),
            device_to_group: PoisonLock::new(HashMap::new()),
        }
    }

    /// 指定デバイスのIOMMUグループを検索し、なければ作成する。
    ///
    /// # Arguments
    /// * `device` - グルーピング対象のPCI DeviceId。
    /// * `controller` - デバイスを管理するIOMMUコントローラ。
    /// * `controller_idx` - コントローラのインデックス (グループ構造体に格納)。
    /// * `topology` - PCIeトポロジー問い合わせプロバイダ。
    ///
    /// # Returns
    /// (IommuGroup, 新規作成かどうか) のタプル。
    pub fn find_or_create_group<P: PciTopologyProvider>(
        &self,
        device: DeviceId,
        controller: &IommuController,
        controller_idx: usize,
        topology: &P,
    ) -> Result<(IommuGroup, bool), IommuError> {
        let mut groups_guard = self.groups.lock().map_err(|_| IommuError::Poisoned)?;
        let mut device_to_group_guard = self
            .device_to_group
            .lock()
            .map_err(|_| IommuError::Poisoned)?;

        // 1. デバイスが既にグループに所属しているか確認
        if let Some(group_id) = device_to_group_guard.get(&device) {
            if let Some(group) = groups_guard.get(group_id) {
                if group.controller_idx != controller_idx {
                    log::error!(
                        "[IOMMU] Group {:?} controller mismatch for device {:?}: existing={} requested={}",
                        group_id,
                        device,
                        group.controller_idx,
                        controller_idx
                    );
                    return Err(IommuError::HardwareError);
                }
                return Ok((group.clone(), false));
            }
        }

        // 2. PCIeトポロジーを走査してグループIDを決定
        let group_id = Self::determine_group_id_for_device(device, topology)?;

        // 3. 既存グループがあればデバイスを追加して返す
        if let Some(group) = groups_guard.get(&group_id) {
            if group.controller_idx != controller_idx {
                log::error!(
                    "[IOMMU] Group {:?} controller mismatch for device {:?}: existing={} requested={}",
                    group_id,
                    device,
                    group.controller_idx,
                    controller_idx
                );
                return Err(IommuError::HardwareError);
            }
            device_to_group_guard.insert(device, group.id);
            return Ok((group.clone(), false));
        }

        // 4. 新しいIOMMUグループを作成してドメインを割当
        let domain_id = controller.create_domain(None, IommuDomainType::Translated)?;
        let new_group = IommuGroup {
            id: group_id,
            domain_id,
            controller_idx,
        };

        groups_guard.insert(group_id, new_group.clone());
        device_to_group_guard.insert(device, group_id);

        log::info!(
            "[IOMMU] Created new group {:?} with domain {} for device {:?}",
            group_id,
            domain_id,
            device
        );

        Ok((new_group, true))
    }

    /// PCIeヒエラルキーを走査してIOMMUグループIDを決定する。
    ///
    /// グループIDはグループの「ルート」デバイス (分離不可能な最上位) のDeviceId。
    /// ACSで完全分離されたデバイスは自身 (または多機能なら function 0) がグループIDとなる。
    fn determine_group_id_for_device<P: PciTopologyProvider>(
        device: DeviceId,
        topology: &P,
    ) -> Result<IommuGroupId, IommuError> {
        let mut current_bus = device.bus;
        let mut current_dev = device.device;
        let mut current_func = device.function;
        let mut first_hop = true;

        // 多機能デバイスの全ファンクションは同一グループ (function 0 ベース)
        let mut group_root_bus = current_bus;
        let mut group_root_dev = current_dev;
        let group_root_func: u8 = 0;

        // PCIヒエラルキーを上位方向に走査
        loop {
            // 多機能デバイスの場合、function 0のDeviceIdをグループルート候補とする
            if current_func != 0 {
                group_root_bus = current_bus;
                group_root_dev = current_dev;
            }

            // ヘッダタイプを読取ってブリッジかどうか確認
            let header_type = match topology.read_header_type(current_bus, current_dev, current_func)
            {
                Some(header_type) => header_type,
                None if first_hop => return Err(IommuError::DeviceNotFound),
                None => {
                    // 途中ノード情報が欠落している場合は、ここまでに確定した保守的ルートで打ち切る。
                    break;
                }
            };

            let is_pci_to_pci_bridge = (header_type & 0x7F) == 0x01; // Type 1 header

            if is_pci_to_pci_bridge {
                // ブリッジは function 0 ベースでグループルートを扱う。
                let candidate_root_bus = current_bus;
                let candidate_root_dev = current_dev;

                // ACS判定:
                // - Some(true):  このブリッジで下流が分離されるため、ここではルート昇格しない
                // - Some(false): 分離不能なのでこのブリッジをグループルートに昇格
                // - None:        情報不足/非対応は安全側に倒して分離不能扱い
                match topology.is_acs_isolation_enabled(current_bus, current_dev, current_func) {
                    Some(true) => {
                        // ACS分離有効 → 下流デバイスは独立グループ
                        break;
                    }
                    Some(false) | None => {
                        group_root_bus = candidate_root_bus;
                        group_root_dev = candidate_root_dev;
                    }
                }
            }

            // バス0に到達 → ルートコンプレックスで分離を仮定
            if current_bus == 0 {
                break;
            }

            // 親ブリッジを検索
            match topology.find_parent_bridge(current_bus) {
                Some((parent_bus, parent_dev, parent_func)) => {
                    current_bus = parent_bus;
                    current_dev = parent_dev;
                    current_func = parent_func;
                }
                None => {
                    // 親ブリッジ不在 → ルートコンプレックスデバイスまたはトポロジーエラー
                    // 既知の情報だけで保守的グループを返す。
                    break;
                }
            }
            first_hop = false;
        }

        Ok(DeviceId::new(
            device.segment,
            group_root_bus,
            group_root_dev,
            group_root_func,
        ))
    }

    /// デバイスが属するグループIDを取得する (検索のみ)
    pub fn get_group_for_device(&self, device: &DeviceId) -> Option<IommuGroupId> {
        match self.device_to_group.lock() {
            Ok(guard) => guard.get(device).copied(),
            Err(_) => None,
        }
    }

    /// テスト専用: groups ロックを取得して毒化テストに使用する。
    #[cfg(feature = "qemu-test-export")]
    pub fn groups_lock_for_test(
        &self,
    ) -> crate::sync::LockResult<
        crate::sync::PoisonLockGuard<'_, HashMap<IommuGroupId, IommuGroup>>,
    > {
        self.groups.lock()
    }
}

// ============================================================================
// Global IOMMU Group Manager
// ============================================================================

#[cfg(not(test))]
pub static IOMMU_GROUP_MANAGER: Once<IommuGroupManager> = Once::new();

#[cfg(not(test))]
pub fn get_iommu_group_manager() -> Option<&'static IommuGroupManager> {
    IOMMU_GROUP_MANAGER.get()
}
