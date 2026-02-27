// ============================================================================
// kernel/src/io/iommu/groups.rs
// ============================================================================

//! IOMMU Group Management
//!
//! PCIeトポロジーに基づいたIOMMUグルーピングを管理する。
//! ACS (Access Control Services) 対応ブリッジによるデバイス分離を検出し、
//! 分離不可能なデバイス群を同一IOMMUドメインに割り当てる。

use crate::io::iommu::runtime::backend::IommuBackend;
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
    /// * `backend` - IOMMUバックエンドドライバ。
    /// * `controller_idx` - コントローラのインデックス (グループ構造体に格納)。
    /// * `topology` - PCIeトポロジー問い合わせプロバイダ。
    ///
    /// # Returns
    /// (IommuGroup, 新規作成かどうか) のタプル。
    pub fn find_or_create_group<P: PciTopologyProvider>(
        &self,
        device: DeviceId,
        backend: &IommuBackend,
        controller_idx: usize,
        topology: &P,
        domain_type: IommuDomainType,
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
                // Check if the domain type matches
                let domain = backend.get_domain(group.domain_id)?;
                if domain.domain_type() != domain_type {
                    log::warn!(
                        "[IOMMU] Domain type mismatch for group {:?} (device {:?}): existing={:?} requested={:?}",
                        group_id,
                        device,
                        domain.domain_type(),
                        domain_type
                    );
                    // Use existing domain type (group policy takes precedence)
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
        let domain_id = backend.create_domain(None, domain_type)?;
        let new_group = IommuGroup {
            id: group_id,
            domain_id,
            controller_idx,
        };

        groups_guard.insert(group_id, new_group.clone());
        device_to_group_guard.insert(device, group_id);

        log::info!(
            "[IOMMU] Created new group {:?} with domain {} ({:?}) for device {:?}",
            group_id,
            domain_id,
            domain_type,
            device
        );

        Ok((new_group, true))
    }

    /// PCIeヒエラルキーを走査してIOMMUグループIDを決定する。
    ///
    /// グループIDはグループの「ルート」デバイス (分離不可能な最上位) のDeviceId。
    /// ACSで完全分離されたデバイスは自身 (または多機能なら function 0) がグループIDとなる。
    ///
    /// # Security Policy
    /// - 多機能(Multifunction)デバイス内の全ファンクションは、互いに分離不可能であれば同一グループ。
    /// - ブリッジの下流にあり、ACS Source Validation 等で分離されていないデバイスは同一グループ。
    /// - パス上の *全ての* ブリッジがACS分離を提供している必要がある。1つでも欠けていれば上位にマージ。
    fn determine_group_id_for_device<P: PciTopologyProvider>(
        device: DeviceId,
        topology: &P,
    ) -> Result<IommuGroupId, IommuError> {
        let mut current_bus = device.bus;
        let mut current_dev = device.device;
        let mut current_func = device.function;
        let mut first_hop = true;

        // グループのルート候補を保持
        let mut group_root_bus = current_bus;
        let mut group_root_dev = current_dev;
        let mut group_root_func = current_func;

        // Check if the device itself is a multifunction device and if it lacks ACS isolation
        if let Some(header_type) = topology.read_header_type(current_bus, current_dev, 0) {
            let is_multifunction = (header_type & 0x80) != 0;
            if is_multifunction {
                match topology.is_acs_isolation_enabled(current_bus, current_dev, 0) {
                    Some(true) => {
                        // Functions are isolated. Group root stays as the device's own function.
                    }
                    Some(false) | None => {
                        // Functions are NOT isolated - they must share a group (root is func 0)
                        group_root_func = 0;
                    }
                }
            } else {
                // Single function device
                group_root_func = 0;
            }
        }

        // PCIヒエラルキーをルートコンプレックスに向かって走査
        loop {
            // ... (rest of the loop is correct as it updates bus/dev and resets func to 0 on bridge merge)
            let header_type = match topology.read_header_type(current_bus, current_dev, current_func)
            {
                Some(header_type) => header_type,
                None if first_hop => return Err(IommuError::DeviceNotFound),
                None => {
                    log::error!(
                        "[IOMMU] Topology information missing during grouping for device {:?} at {:02x}:{:02x}.{:x}",
                        device,
                        current_bus,
                        current_dev,
                        current_func
                    );
                    return Err(IommuError::HardwareError);
                }
            };

            let is_bridge = (header_type & 0x7F) == 0x01;

            if is_bridge {
                // ブリッジの下流分離を確認 (ACS)
                match topology.is_acs_isolation_enabled(current_bus, current_dev, current_func) {
                    Some(true) => {
                        // このブリッジで下流が分離されている。
                    }
                    Some(false) | None => {
                        // 分離不能ブリッジ → グループのルートをこのブリッジに引き上げる。
                        group_root_bus = current_bus;
                        group_root_dev = current_dev;
                        group_root_func = 0; // Bridges are group roots via function 0
                    }
                }
            }

            if current_bus == 0 {
                break;
            }

            match topology.find_parent_bridge(current_bus) {
                Some((parent_bus, parent_dev, parent_func)) => {
                    current_bus = parent_bus;
                    current_dev = parent_dev;
                    current_func = parent_func;
                }
                None if current_bus == 0 => break,
                None => {
                    log::error!(
                        "[IOMMU] Parent bridge not found for bus {} during grouping walk for device {:?}",
                        current_bus,
                        device
                    );
                    return Err(IommuError::HardwareError);
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
