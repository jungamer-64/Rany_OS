use super::*;

impl Default for ProcessAddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProcessAddressSpace {
    fn drop(&mut self) {
        // 全領域を解放
        let _ = self.exec_reset();

        // ページテーブルを解放
        let pt_root = self.page_table_root.load(Ordering::Acquire);
        if pt_root != 0 {
            // TODO: ページテーブル階層を再帰的に解放
        }
    }
}

// ============================================================================
// Address Space Error
// ============================================================================

/// アドレス空間操作のエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceError {
    /// メモリ不足
    OutOfMemory,
    /// 無効な範囲
    InvalidRange,
    /// 無効なサイズ
    InvalidSize,
    /// 領域が重複
    RegionOverlap,
    /// 領域が見つからない
    RegionNotFound,
    /// 権限エラー
    PermissionDenied,
    /// 既にマッピング済み
    AlreadyMapped,
    /// マッピングエラー
    MapFailed,
}

// ============================================================================
// Statistics
// ============================================================================

/// アドレス空間の統計情報
#[derive(Debug, Clone)]
pub struct AddressSpaceStats {
    /// ASID
    pub asid: u64,
    /// 仮想アドレス空間の合計サイズ
    pub total_virtual: u64,
    /// マッピングされたページ数
    pub mapped_pages: u64,
    /// 領域数
    pub region_count: usize,
    /// ヒープサイズ
    pub heap_size: u64,
}

use crate::sync::IrqPoisonLock;

// ============================================================================
// Global Address Space Manager
// ============================================================================

/// グローバルアドレス空間マネージャ
pub struct AddressSpaceManager {
    /// アドレス空間のマップ (asid -> address_space)
    spaces: IrqPoisonLock<BTreeMap<u64, Box<ProcessAddressSpace>>>,
    /// 現在アクティブなASID
    current_asid: AtomicU64,
}

impl AddressSpaceManager {
    /// 新しいマネージャを作成
    pub const fn new() -> Self {
        Self {
            spaces: IrqPoisonLock::new(BTreeMap::new()),
            current_asid: AtomicU64::new(0),
        }
    }

    /// アドレス空間のマップを取得
    pub fn spaces(&self) -> &IrqPoisonLock<BTreeMap<u64, Box<ProcessAddressSpace>>> {
        &self.spaces
    }

    /// アドレス空間を作成
    pub fn create(&self) -> Result<u64, AddressSpaceError> {
        let space = Box::new(ProcessAddressSpace::new());
        let asid = space.asid();

        space.init_page_table()?;

        let mut spaces = match self.spaces.lock() {
            Ok(guard) => guard,
            Err(p) => p.into_inner(),
        };
        spaces.insert(asid, space);

        Ok(asid)
    }

    /// アドレス空間を取得
    pub fn get(&self, asid: u64) -> Option<u64> {
        let spaces = match self.spaces.lock() {
            Ok(guard) => guard,
            Err(p) => p.into_inner(),
        };
        spaces.get(&asid).map(|s| s.page_table_root())
    }

    /// アドレス空間を削除
    pub fn destroy(&self, asid: u64) {
        let mut spaces = match self.spaces.lock() {
            Ok(guard) => guard,
            Err(p) => p.into_inner(),
        };
        spaces.remove(&asid);
    }

    /// 現在のASIDを取得
    pub fn current_asid(&self) -> u64 {
        self.current_asid.load(Ordering::Acquire)
    }

    /// アドレス空間を切り替え
    pub fn switch_to(&self, asid: u64) -> Result<(), AddressSpaceError> {
        let spaces = match self.spaces.lock() {
            Ok(guard) => guard,
            Err(p) => p.into_inner(),
        };

        if let Some(space) = spaces.get(&asid) {
            let cr3 = space.page_table_root();

            // CR3を設定
            unsafe {
                crate::mm::virt::higher_half::set_cr3(PhysAddr::new(cr3));
            }

            self.current_asid.store(asid, Ordering::Release);
            Ok(())
        } else {
            Err(AddressSpaceError::RegionNotFound)
        }
    }

    /// 現在のアドレス空間をスキャン（NUMA Hint）
    pub fn scan_current_address_space(
        &self,
        start_addr: VirtAddr,
        batch_size: usize,
    ) -> Option<(usize, usize, VirtAddr)> {
        let asid = self.current_asid.load(Ordering::Acquire);
        if asid == 0 {
            return None;
        }

        let spaces = match self.spaces.lock() {
            Ok(guard) => guard,
            Err(p) => p.into_inner(),
        };
        if let Some(space) = spaces.get(&asid) {
            Some(space.scan_numa_hints(start_addr, batch_size))
        } else {
            None
        }
    }
}

/// グローバルアドレス空間マネージャ
pub(crate) static ADDRESS_SPACE_MANAGER: AddressSpaceManager = AddressSpaceManager::new();

// ============================================================================
// Public API
// ============================================================================

/// アドレス空間マネージャを取得
pub fn address_space_manager() -> &'static AddressSpaceManager {
    &ADDRESS_SPACE_MANAGER
}

/// 新しいアドレス空間を作成
pub fn create_address_space() -> Result<u64, AddressSpaceError> {
    ADDRESS_SPACE_MANAGER.create()
}

/// アドレス空間を削除
pub fn destroy_address_space(asid: u64) {
    ADDRESS_SPACE_MANAGER.destroy(asid);
}

/// アドレス空間を切り替え
pub fn switch_address_space(asid: u64) -> Result<(), AddressSpaceError> {
    ADDRESS_SPACE_MANAGER.switch_to(asid)
}

/// 現在のASIDを取得
pub fn current_asid() -> u64 {
    ADDRESS_SPACE_MANAGER.current_asid()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
