// ============================================================================
// kernel/src/io/iommu/runtime/groups.rs
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

    /// 指定デバイス(bus:device)の全ての機能でACS分離が有効かを確認する。
    /// 一つでも無効またはケイパビリティがない場合は false を返す。
    ///
    /// # Security Policy
    /// 多機能デバイスの場合、全ファンクションがACS対応で分離されている必要がある。
    /// また、一部のデバイスは多機能ビットを偽装する場合があるため、常に全ファンクションをスキャンする。
    fn has_acs_on_all_functions(&self, bus: u8, device: u8) -> bool {
        let mut found_multifunction = false;
        let mut all_acs_enabled = true;
        let mut any_function_exists = false;

        // Check all 8 possible functions.
        for func in 0..8 {
            if let Some(ht) = self.read_header_type(bus, device, func) {
                any_function_exists = true;
                if func > 0 || (ht & 0x80) != 0 {
                    found_multifunction = true;
                }

                if !self
                    .is_acs_isolation_enabled(bus, device, func)
                    .unwrap_or(false)
                {
                    all_acs_enabled = false;
                    // If any function lacks ACS, we can stop early if it's already known to be multifunction.
                    if found_multifunction {
                        return false;
                    }
                }
            }
        }

        if !any_function_exists {
            return false;
        }

        // If it's a multifunction device, all functions MUST have ACS enabled.
        if found_multifunction {
            return all_acs_enabled;
        }

        // Single-function device: just check function 0's ACS (for P2P isolation if it's a bridge).
        all_acs_enabled
    }

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

// ============================================================================
// Legacy PCI Topology (fallback when PCIe Extended Config is unavailable)
// ============================================================================

/// Fallback topology provider that uses legacy I/O port PCI config reads.
/// This is used when no MCFG/ECAM is available (no PCIe extended config space).
///
/// ACS is not available via legacy config access, so this implementation
/// conservatively treats each device as having NO ACS isolation.  This means
/// all devices behind the same non-ACS bridge are grouped together, which is
/// the safe default.
#[cfg(not(test))]
pub struct LegacyPciTopology;

#[cfg(not(test))]
impl PciTopologyProvider for LegacyPciTopology {
    fn read_header_type(&self, bus: u8, device: u8, function: u8) -> Option<u8> {
        // Legacy PCI config space: Header Type is at offset 0x0E
        let vendor_id = pci_driver::pci_read16(bus, device, function, 0x00);
        if vendor_id == 0xFFFF {
            return None; // Device not present
        }
        Some(pci_driver::pci_read8(bus, device, function, 0x0E))
    }

    fn is_acs_isolation_enabled(&self, _bus: u8, _device: u8, _function: u8) -> Option<bool> {
        // ACS capabilities are in PCIe extended config space (offset > 0xFF),
        // which is not accessible via legacy I/O ports.
        // Conservative default: no ACS isolation available.
        None
    }

    fn find_parent_bridge(&self, child_bus: u8) -> Option<(u8, u8, u8)> {
        if child_bus == 0 {
            return None;
        }
        // Scan bus 0 for bridges whose secondary bus matches child_bus
        for dev in 0..32u8 {
            let vendor_id = pci_driver::pci_read16(0, dev, 0, 0x00);
            if vendor_id == 0xFFFF {
                continue;
            }
            let header_type = pci_driver::pci_read8(0, dev, 0, 0x0E);
            if (header_type & 0x7F) == 0x01 {
                // Type 1 header (PCI-to-PCI bridge)
                let secondary_bus = pci_driver::pci_read8(0, dev, 0, 0x19);
                if secondary_bus == child_bus {
                    return Some((0, dev, 0));
                }
            }
        }
        None
    }
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
        if !topology.has_acs_on_all_functions(current_bus, current_dev) {
            // Either multifunction without ACS or single-function without ACS.
            // In both cases, if the device isn't isolated from its peers or its own functions,
            // we group it by its base device (function 0).
            group_root_func = 0;
        }

        // PCIヒエラルキーをルートコンプレックスに向かって走査
        loop {
            // ... (rest of the loop is correct as it updates bus/dev and resets func to 0 on bridge merge)
            let header_type = match topology.read_header_type(
                current_bus,
                current_dev,
                current_func,
            ) {
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
                // Note: Multi-function bridges must also be fully isolated at all functions.
                if !topology.has_acs_on_all_functions(current_bus, current_dev) {
                    // 分離不能ブリッジ → グループのルートをこのブリッジに引き上げる。
                    group_root_bus = current_bus;
                    group_root_dev = current_dev;
                    group_root_func = 0; // Bridges are group roots via function 0
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
    ) -> crate::sync::LockResult<crate::sync::PoisonLockGuard<'_, HashMap<IommuGroupId, IommuGroup>>>
    {
        self.groups.lock()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    struct MockTopology {
        header_types: BTreeMap<(u8, u8, u8), u8>,
        acs_enabled: BTreeMap<(u8, u8, u8), bool>,
        parents: BTreeMap<u8, (u8, u8, u8)>,
    }

    impl MockTopology {
        fn new() -> Self {
            Self {
                header_types: BTreeMap::new(),
                acs_enabled: BTreeMap::new(),
                parents: BTreeMap::new(),
            }
        }

        fn add_endpoint(&mut self, bus: u8, dev: u8, func: u8, multi: bool) {
            let ht = if multi { 0x80 } else { 0x00 };
            self.header_types.insert((bus, dev, func), ht);
        }

        fn add_bridge(&mut self, bus: u8, dev: u8, func: u8, child_bus: u8, acs: bool) {
            self.header_types.insert((bus, dev, func), 0x01);
            self.acs_enabled.insert((bus, dev, func), acs);
            self.parents.insert(child_bus, (bus, dev, func));
        }
    }

    impl PciTopologyProvider for MockTopology {
        fn read_header_type(&self, bus: u8, device: u8, function: u8) -> Option<u8> {
            self.header_types.get(&(bus, device, function)).copied()
        }

        fn is_acs_isolation_enabled(&self, bus: u8, device: u8, function: u8) -> Option<bool> {
            self.acs_enabled.get(&(bus, device, function)).copied()
        }

        fn find_parent_bridge(&self, child_bus: u8) -> Option<(u8, u8, u8)> {
            self.parents.get(&child_bus).copied()
        }
    }

    #[test_case]
    fn test_group_single_endpoint() {
        let mut topo = MockTopology::new();
        topo.add_endpoint(0, 1, 0, false);

        let dev = DeviceId::new(0, 0, 1, 0);
        let group_id = IommuGroupManager::determine_group_id_for_device(dev, &topo).unwrap();

        // Single isolated endpoint should be its own group root
        assert_eq!(group_id, dev);
    }

    #[test_case]
    fn test_group_multifunction_no_acs() {
        let mut topo = MockTopology::new();
        // Multifunction device at 00:02.x, no ACS reported
        topo.add_endpoint(0, 2, 0, true);
        topo.add_endpoint(0, 2, 1, true);

        let dev0 = DeviceId::new(0, 0, 2, 0);
        let dev1 = DeviceId::new(0, 0, 2, 1);

        let id0 = IommuGroupManager::determine_group_id_for_device(dev0, &topo).unwrap();
        let id1 = IommuGroupManager::determine_group_id_for_device(dev1, &topo).unwrap();

        // Both should be grouped under function 0
        assert_eq!(id0, dev0);
        assert_eq!(id1, dev0);
    }

    #[test_case]
    fn test_group_behind_non_acs_bridge() {
        let mut topo = MockTopology::new();
        // Root bridge (0,1,0) -> Bus 1, ACS disabled
        topo.add_bridge(0, 1, 0, 1, false);
        topo.add_endpoint(1, 0, 0, false);

        let dev = DeviceId::new(0, 1, 0, 0);
        let group_id = IommuGroupManager::determine_group_id_for_device(dev, &topo).unwrap();

        // Should be grouped under the bridge (0,1,0)
        assert_eq!(group_id, DeviceId::new(0, 0, 1, 0));
    }

    #[test_case]
    fn test_group_behind_acs_bridge() {
        let mut topo = MockTopology::new();
        // Root bridge (0,1,0) -> Bus 1, ACS enabled
        topo.add_bridge(0, 1, 0, 1, true);
        topo.add_endpoint(1, 0, 0, false);

        let dev = DeviceId::new(0, 1, 0, 0);
        let group_id = IommuGroupManager::determine_group_id_for_device(dev, &topo).unwrap();

        // Bridge has ACS, so the endpoint is isolated
        assert_eq!(group_id, dev);
    }

    #[test_case]
    fn test_group_non_acs_chain() {
        let mut topo = MockTopology::new();
        // Bridge A (0,1,0) -> Bus 1, ACS disabled
        topo.add_bridge(0, 1, 0, 1, false);
        // Bridge B (1,2,0) -> Bus 2, ACS disabled
        topo.add_bridge(1, 2, 0, 2, false);
        topo.add_endpoint(2, 0, 0, false);

        let dev = DeviceId::new(0, 2, 0, 0);
        let group_id = IommuGroupManager::determine_group_id_for_device(dev, &topo).unwrap();

        // Should be promoted to the highest non-ACS ancestor: Bridge A
        assert_eq!(group_id, DeviceId::new(0, 0, 1, 0));
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
