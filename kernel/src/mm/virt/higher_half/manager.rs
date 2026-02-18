use super::*;


// ============================================================================
// Higher Half Kernel Manager
// ============================================================================

/// Higher Half Kernel マネージャー
pub struct HigherHalfManager {
    /// 物理メモリマッパー
    mapper: PhysicalMemoryMapper,
    /// カーネルの開始仮想アドレス
    kernel_start: VirtAddr,
    /// カーネルの終了仮想アドレス
    kernel_end: VirtAddr,
    /// 次に割り当て可能なカーネル仮想アドレス
    next_kernel_addr: AtomicU64,
}

impl HigherHalfManager {
    /// 新しいマネージャーを作成
    pub const fn new(physical_memory_offset: u64) -> Self {
        Self {
            mapper: PhysicalMemoryMapper::new(physical_memory_offset),
            kernel_start: VirtAddr::new(VirtAddr::KERNEL_BASE),
            kernel_end: VirtAddr::new(VirtAddr::KERNEL_BASE),
            next_kernel_addr: AtomicU64::new(VirtAddr::KERNEL_HEAP_BASE),
        }
    }

    /// 物理メモリマッパーを取得
    pub fn mapper(&self) -> &PhysicalMemoryMapper {
        &self.mapper
    }

    /// 物理メモリオフセットを取得
    pub fn physical_memory_offset(&self) -> u64 {
        self.mapper.offset()
    }

    /// カーネル仮想アドレス領域を割り当て
    pub fn allocate_kernel_virt(&self, pages: usize) -> VirtAddr {
        let size = (pages as u64) * PageSize::Size4KiB.as_bytes();
        let addr = self.next_kernel_addr.fetch_add(size, Ordering::SeqCst);
        VirtAddr::new(addr)
    }

    /// カーネル空間内かどうか判定
    pub fn is_kernel_address(&self, addr: VirtAddr) -> bool {
        addr.is_kernel_space()
    }
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバルHigher Halfマネージャー
pub(crate) static HIGHER_HALF_MANAGER: PoisonLock<Option<HigherHalfManager>> = PoisonLock::new(None);

/// Higher Halfカーネルを初期化
pub fn init(physical_memory_offset: u64) {
    let manager = HigherHalfManager::new(physical_memory_offset);
    // Initialization-time best-effort recovery: recovering a poisoned manager during init is
    // acceptable to allow boot to continue.
    let mut mgr_guard = HIGHER_HALF_MANAGER.lock_for_init("[MM] Higher Half init");
    *mgr_guard = Some(manager);
    // log::info!("Higher half kernel initialized with offset {:#x}", physical_memory_offset);
}

/// 物理メモリオフセットを取得
pub fn physical_memory_offset() -> u64 {
    let guard = match HIGHER_HALF_MANAGER.lock() {
        Ok(g) => g,
        Err(_) => panic!("[MM] Higher Half manager poisoned (physical_memory_offset)"),
    };
    let manager = guard.as_ref().expect("Higher half not initialized");
    manager.physical_memory_offset()
}

/// 物理アドレスを仮想アドレスに変換
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    let guard = match HIGHER_HALF_MANAGER.lock() {
        Ok(g) => g,
        Err(_) => panic!("[MM] Higher Half manager poisoned (phys_to_virt)"),
    };
    let manager = guard.as_ref().expect("Higher half not initialized");
    manager.mapper().phys_to_virt(phys)
}

/// 仮想アドレスを物理アドレスに変換（直接マップ領域）
pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    match HIGHER_HALF_MANAGER.lock() {
        Ok(guard) => {
            let manager = guard.as_ref().expect("Higher half not initialized");
            manager.mapper().virt_to_phys(virt)
        }
        Err(_) => {
            log::error!("[MM] Higher Half manager poisoned (virt_to_phys) - returning None");
            None
        }
    }
}

// ============================================================================
// TLB Operations
// ============================================================================

/// TLBを無効化（単一アドレス）
#[inline]
pub fn invalidate_page(addr: VirtAddr) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags));
    }
}

/// TLBを全無効化
#[inline]
pub fn flush_tlb() {
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// CR3を設定
#[inline]
pub unsafe fn set_cr3(pml4_phys: PhysAddr) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) pml4_phys.as_u64(), options(nostack, preserves_flags));
    }
}

/// CR3を取得
#[inline]
pub fn get_cr3() -> PhysAddr {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    PhysAddr::new(cr3 & !0xFFF)
}

// ============================================================================
// Page Table Manager
// 設計書 5.1: ページテーブル管理
// ============================================================================

/// マッピングエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// フレーム割り当て失敗
    FrameAllocationFailed,
    /// 既にマップ済み
    AlreadyMapped,
    /// マップされていない
    NotMapped,
    /// 無効なアドレス
    InvalidAddress,
    /// アラインメントエラー
    AlignmentError,
    /// 親エントリがHuge Page
    ParentEntryHugePage,
    /// ハードウェア／内部状態のエラー（PoisonLockが毒入れされているなど）
    HardwareError,
}

/// ページテーブルマネージャー
///
/// 仮想アドレスと物理アドレスのマッピングを管理する。
/// 4KiB, 2MiB, 1GiBページサイズをサポート。
#[derive(Debug)]
pub struct PageTableManager {
    /// PML4（レベル4ページテーブル）の物理アドレス
    pml4_phys: PhysAddr,
    /// 物理メモリマッパー
    mapper: PhysicalMemoryMapper,
}

impl PageTableManager {
    /// 新しいPageTableManagerを作成
    ///
    /// # Safety
    /// - `pml4_phys` は有効なPML4ページテーブルを指している必要がある
    /// - `physical_memory_offset` は正しいオフセット値である必要がある
    pub unsafe fn new(pml4_phys: PhysAddr, physical_memory_offset: u64) -> Self {
        Self {
            pml4_phys,
            mapper: PhysicalMemoryMapper::new(physical_memory_offset),
        }
    }

    /// 現在のCR3からPageTableManagerを作成
    ///
    /// # Safety
    /// カーネルモードで呼び出す必要がある
    pub unsafe fn from_current_cr3(physical_memory_offset: u64) -> Self {
        let pml4_phys = get_cr3();
        unsafe { Self::new(pml4_phys, physical_memory_offset) }
    }

    /// PML4の物理アドレスを取得
    pub fn pml4_phys(&self) -> PhysAddr {
        self.pml4_phys
    }

    /// PDPT→PD→PTまでウォークし、PTの物理アドレスを返す
    pub(super) fn walk_to_page_table(
        &mut self,
        indices: [usize; 4],
        flags: PageFlags,
    ) -> Result<PhysAddr, MapError> {
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pdpt_phys = self.ensure_table_entry(pml4, indices[0], flags)?;

        let pdpt = self.get_table_mut(pdpt_phys);
        if pdpt.entry(indices[1]).is_present() && pdpt.entry(indices[1]).is_huge() {
            return Err(MapError::ParentEntryHugePage);
        }
        let pd_phys = self.ensure_table_entry(pdpt, indices[1], flags)?;

        let pd = self.get_table_mut(pd_phys);
        if pd.entry(indices[2]).is_present() && pd.entry(indices[2]).is_huge() {
            return Err(MapError::ParentEntryHugePage);
        }
        self.ensure_table_entry(pd, indices[2], flags)
    }

    /// 4KiBページをマップ
    ///
    /// # Safety
    /// - `virt` と `phys` は4KiBアラインされている必要がある
    /// - 物理フレームは有効なメモリを指している必要がある
    pub unsafe fn map_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        if !virt.is_page_aligned() || !phys.is_page_aligned() {
            return Err(MapError::AlignmentError);
        }

        let indices = virt.page_table_indices();
        let pt_phys = self.walk_to_page_table(indices, flags)?;

        let pt = self.get_table_mut(pt_phys);
        let pte = pt.entry_mut(indices[3]);

        if pte.is_present() {
            return Err(MapError::AlreadyMapped);
        }

        *pte = PageTableEntry::new(phys, flags.set(PageFlags::PRESENT));

        // TLBを無効化
        invalidate_page(virt);

        Ok(())
    }

    /// Adjust PAT flag for huge pages (2MB/1GB): PAT bit moves from bit 7 to bit 12.
    pub(super) fn adjust_pat_for_huge(flags: PageFlags) -> PageFlags {
        if flags.contains(PageFlags::PAT) {
            flags.clear(PageFlags::PAT).set(PageFlags::PAT_LARGE)
        } else {
            flags
        }
    }

    /// 2MiBページをマップ（設計書5.1対応）
    ///
    /// # Safety
    /// - `virt` と `phys` は2MiBアラインされている必要がある
    pub unsafe fn map_2mb_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        const SIZE_2MB: u64 = PageSize::Size2MiB.as_bytes();

        if virt.as_u64() % SIZE_2MB != 0 || phys.as_u64() % SIZE_2MB != 0 {
            return Err(MapError::AlignmentError);
        }

        let actual_flags = Self::adjust_pat_for_huge(flags);

        let indices = virt.page_table_indices();

        // PML4 -> PDPT -> PD をウォーク
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pdpt_phys = self.ensure_table_entry(pml4, indices[0], flags)?;

        let pdpt = self.get_table_mut(pdpt_phys);
        if pdpt.entry(indices[1]).is_present() && pdpt.entry(indices[1]).is_huge() {
            return Err(MapError::ParentEntryHugePage);
        }
        let pd_phys = self.ensure_table_entry(pdpt, indices[1], flags)?;

        let pd = self.get_table_mut(pd_phys);
        let pde = pd.entry_mut(indices[2]);

        if pde.is_present() {
            return Err(MapError::AlreadyMapped);
        }

        // Huge Page フラグを設定
        *pde = PageTableEntry::huge(phys, actual_flags.set(PageFlags::PRESENT));

        invalidate_page(virt);

        Ok(())
    }

    /// 1GiBページをマップ（設計書5.1対応）
    ///
    /// # Safety
    /// - `virt` と `phys` は1GiBアラインされている必要がある
    pub unsafe fn map_1gb_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        const SIZE_1GB: u64 = PageSize::Size1GiB.as_bytes();

        if virt.as_u64() % SIZE_1GB != 0 || phys.as_u64() % SIZE_1GB != 0 {
            return Err(MapError::AlignmentError);
        }

        // PAT bit handling (same as 2MB pages)
        let mut actual_flags = flags;
        if actual_flags.contains(PageFlags::PAT) {
            actual_flags = actual_flags.clear(PageFlags::PAT).set(PageFlags::PAT_LARGE);
        }

        let indices = virt.page_table_indices();

        // PML4 -> PDPT をウォーク
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pdpt_phys = self.ensure_table_entry(pml4, indices[0], flags)?;

        let pdpt = self.get_table_mut(pdpt_phys);
        let pdpte = pdpt.entry_mut(indices[1]);

        if pdpte.is_present() {
            return Err(MapError::AlreadyMapped);
        }

        // Huge Page フラグを設定（1GiBページ）
        *pdpte = PageTableEntry::huge(phys, actual_flags.set(PageFlags::PRESENT));

        invalidate_page(virt);

        Ok(())
    }

    /// ページをアンマップ
    ///
    /// 4KiB, 2MiB, 1GiBページを自動検出してアンマップする。
    pub unsafe fn unmap_page(&mut self, virt: VirtAddr) -> Result<PhysAddr, MapError> {
        if !virt.is_page_aligned() {
            return Err(MapError::AlignmentError);
        }

        let indices = virt.page_table_indices();

        // PML4
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pml4e = pml4.entry(indices[0]);
        if !pml4e.is_present() {
            return Err(MapError::NotMapped);
        }

        // PDPT
        let pdpt = self.get_table_mut(pml4e.phys_addr());
        let pdpte = pdpt.entry_mut(indices[1]);
        if !pdpte.is_present() {
            return Err(MapError::NotMapped);
        }
        if pdpte.is_huge() {
            // 1GiBページ
            let phys = pdpte.phys_addr();
            pdpte.clear();
            invalidate_page(virt);
            return Ok(phys);
        }

        // PD
        let pd = self.get_table_mut(pdpte.phys_addr());
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() {
            return Err(MapError::NotMapped);
        }
        if pde.is_huge() {
            // 2MiBページ
            let phys = pde.phys_addr();
            pde.clear();
            invalidate_page(virt);
            return Ok(phys);
        }

        // PT
        let pt = self.get_table_mut(pde.phys_addr());
        let pte = pt.entry_mut(indices[3]);
        if !pte.is_present() {
            return Err(MapError::NotMapped);
        }

        // 4KiBページ
        let phys = pte.phys_addr();
        pte.clear();
        invalidate_page(virt);

        Ok(phys)
    }

    /// 仮想アドレスを物理アドレスに変換
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let walker = PageTableWalker::new(self.pml4_phys, &self.mapper);
        walker.translate(virt)
    }

    /// ページテーブルの保護フラグを変更
    pub unsafe fn update_flags(
        &mut self,
        virt: VirtAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        if !virt.is_page_aligned() {
            return Err(MapError::AlignmentError);
        }

        let indices = virt.page_table_indices();

        // テーブルをウォーク
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pml4e = pml4.entry(indices[0]);
        if !pml4e.is_present() {
            return Err(MapError::NotMapped);
        }

        let pdpt = self.get_table_mut(pml4e.phys_addr());
        let pdpte = pdpt.entry_mut(indices[1]);
        if !pdpte.is_present() {
            return Err(MapError::NotMapped);
        }
        if pdpte.is_huge() {
            pdpte.set_flags(flags.set(PageFlags::PRESENT).set(PageFlags::HUGE_PAGE));
            invalidate_page(virt);
            return Ok(());
        }

        let pd = self.get_table_mut(pdpte.phys_addr());
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() {
            return Err(MapError::NotMapped);
        }
        if pde.is_huge() {
            pde.set_flags(flags.set(PageFlags::PRESENT).set(PageFlags::HUGE_PAGE));
            invalidate_page(virt);
            return Ok(());
        }

        let pt = self.get_table_mut(pde.phys_addr());
        let pte = pt.entry_mut(indices[3]);
        if !pte.is_present() {
            return Err(MapError::NotMapped);
        }

        pte.set_flags(flags.set(PageFlags::PRESENT));
        invalidate_page(virt);

        Ok(())
    }

    /// ページサイズを自動選択して1ページマップ
    unsafe fn map_one_page(
        &mut self,
        virt: u64,
        phys: u64,
        remaining: u64,
        flags: PageFlags,
    ) -> Result<u64, MapError> {
        const SIZE_1GB: u64 = PageSize::Size1GiB.as_bytes();
        const SIZE_2MB: u64 = PageSize::Size2MiB.as_bytes();
        const SIZE_4KB: u64 = PageSize::Size4KiB.as_bytes();

        if virt % SIZE_1GB == 0 && phys % SIZE_1GB == 0 && remaining >= SIZE_1GB {
            unsafe { self.map_1gb_page(VirtAddr::new(virt), PhysAddr::new(phys), flags)? };
            return Ok(SIZE_1GB);
        }
        if virt % SIZE_2MB == 0 && phys % SIZE_2MB == 0 && remaining >= SIZE_2MB {
            unsafe { self.map_2mb_page(VirtAddr::new(virt), PhysAddr::new(phys), flags)? };
            return Ok(SIZE_2MB);
        }
        unsafe { self.map_page(VirtAddr::new(virt), PhysAddr::new(phys), flags)? };
        Ok(SIZE_4KB)
    }

    /// 連続した仮想アドレス範囲をマップ
    ///
    /// 自動的に最適なページサイズを選択する。
    pub unsafe fn map_range(
        &mut self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: u64,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        let mut virt = virt_start.as_u64();
        let mut phys = phys_start.as_u64();
        let end = virt + size;

        while virt < end {
            let remaining = end - virt;
            let step = unsafe { self.map_one_page(virt, phys, remaining, flags)? };
            virt += step;
            phys += step;
        }

        Ok(())
    }

    /// 連続した仮想アドレス範囲をアンマップ
    pub unsafe fn unmap_range(&mut self, virt_start: VirtAddr, size: u64) -> Result<(), MapError> {
        let mut virt = virt_start.as_u64();
        let end = virt + size;

        while virt < end {
            match unsafe { self.unmap_page(VirtAddr::new(virt)) } {
                Ok(_) => {
                    // ページサイズを検出してスキップ
                    // Note: unmap_pageは物理アドレスを返すが、ここではサイズ情報が必要
                    // 簡単のため4KiB単位で進める
                    virt += PageSize::Size4KiB.as_bytes();
                }
                Err(MapError::NotMapped) => {
                    // マップされていないページはスキップ
                    virt += PageSize::Size4KiB.as_bytes();
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    // --- ヘルパー関数 ---

    /// 物理アドレスからページテーブルの可変参照を取得
    pub(super) fn get_table_mut(&self, phys: PhysAddr) -> &mut PageTable {
        let virt = self.mapper.phys_to_virt(phys);
        unsafe { &mut *virt.as_mut_ptr() }
    }

    /// テーブルエントリが存在しない場合は新しいテーブルを割り当て
    pub(super) fn ensure_table_entry(
        &self,
        table: &mut PageTable,
        index: usize,
        _flags: PageFlags,
    ) -> Result<PhysAddr, MapError> {
        let entry = table.entry_mut(index);

        if entry.is_present() {
            if entry.is_huge() {
                return Err(MapError::ParentEntryHugePage);
            }
            return Ok(entry.phys_addr());
        }

        // 新しいページテーブルを割り当て
        let new_table_phys = self.alloc_page_table()?;

        // テーブルをゼロクリア
        let new_table = self.get_table_mut(new_table_phys);
        new_table.clear();

        // エントリを設定（常にWritableを設定して下位テーブルへのアクセスを許可）
        let entry_flags =
            PageFlags::new(PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER);
        *entry = PageTableEntry::new(new_table_phys, entry_flags);

        Ok(new_table_phys)
    }

    /// 新しいページテーブル用のフレームを割り当て
    pub(super) fn alloc_page_table(&self) -> Result<PhysAddr, MapError> {
        // まず現在のCPUのローカルNUMAノードから割り当てを試みる（優先）
        if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
            if let Some(frame) = crate::mm::phys::frame_allocator::alloc_frame_local(cpu_id as u8) {
                return Ok(PhysAddr::new(frame.start_address().as_u64()));
            }
        }

        // フォールバック: PMMグローバルを使用
        crate::mm::phys::frame_allocator::alloc_frame()
            .map(|frame| PhysAddr::new(frame.start_address().as_u64()))
            .ok_or(MapError::FrameAllocationFailed)
    }
}

/// グローバルなページテーブルマネージャー
pub(crate) static PAGE_TABLE_MANAGER: PoisonLock<Option<PageTableManager>> = PoisonLock::new(None);

/// ページテーブルマネージャーを初期化
pub fn init_page_table_manager(physical_memory_offset: u64) {
    log::info!("[MM] init_page_table_manager: initializing with offset {:#x}", physical_memory_offset);
    let manager = unsafe { PageTableManager::from_current_cr3(physical_memory_offset) };
    // Initialization-time best-effort recovery for PageTableManager initialization.
    let mut mgr_guard = PAGE_TABLE_MANAGER.lock_for_init("[MM] Page Table Manager init");
    *mgr_guard = Some(manager);
    log::info!("[MM] init_page_table_manager: manager set");
}

/// グローバルページテーブルマネージャーでページをマップ
pub unsafe fn global_map_page(
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PageFlags,
) -> Result<(), MapError> {
    // If the global PageTableManager lock is poisoned, treat this as a
    // hardware/internal error and propagate it rather than attempting to
    // continue with potentially corrupted state.
    let mut guard = PAGE_TABLE_MANAGER
        .lock()
        .map_err(|_| {
            log::error!("[MM] Page Table Manager lock poisoned");
            MapError::HardwareError
        })?;

    // Diagnose None manager case for debugging
    if guard.as_mut().is_none() {
        log::error!("[MM] global_map_page: PAGE_TABLE_MANAGER not initialized (None)");
        return Err(MapError::InvalidAddress);
    }

    let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;
    log::info!("[MM] global_map_page: mapping virt={:#x} phys={:#x} flags={:#x}", virt.as_u64(), phys.as_u64(), flags.as_u64());
    unsafe { manager.map_page(virt, phys, flags) }
}

/// グローバルページテーブルマネージャーでページをアンマップ
pub unsafe fn global_unmap_page(virt: VirtAddr) -> Result<PhysAddr, MapError> {
    let mut guard = PAGE_TABLE_MANAGER
        .lock()
        .map_err(|_| {
            log::error!("[MM] Page Table Manager lock poisoned");
            MapError::HardwareError
        })?;

    let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;
    unsafe { manager.unmap_page(virt) }
}

/// グローバルページテーブルマネージャーで仮想→物理変換
pub fn global_translate(virt: VirtAddr) -> Option<PhysAddr> {
    match HIGHER_HALF_MANAGER.lock() {
        Ok(guard) => {
            let manager = guard.as_ref()?;
            manager.mapper().virt_to_phys(virt)
        }
        Err(_) => None,
    }
}

/// 仮想アドレスのPTEを取得（現在のCR3を使用）
pub fn get_current_pte(virt: VirtAddr) -> Option<PageTableEntry> {
    match HIGHER_HALF_MANAGER.lock() {
        Ok(guard) => {
            let manager = guard.as_ref()?;
            // Unsafe: Reading CR3 is safe here as we are in kernel mode
            let walker = unsafe { PageTableWalker::from_current_cr3(manager.mapper()) };
            walker.walk(virt)
        }
        Err(_) => None,
    }
}

/// 仮想アドレスのPTEを変更（現在のCR3を使用）
pub fn with_current_pte_mut<F, R>(virt: VirtAddr, f: F) -> Option<R>
where
    F: FnOnce(&mut PageTableEntry) -> R,
{
    match HIGHER_HALF_MANAGER.lock() {
        Ok(guard) => {
            let manager = guard.as_ref()?;
            let walker = unsafe { PageTableWalker::from_current_cr3(manager.mapper()) };
            unsafe { walker.walk_mut(virt).map(|pte| f(pte)) }
        }
        Err(_) => None,
    }
}

/// グローバルページテーブルマネージャーでページのフラグを更新（MPK PKEY適用用）
pub unsafe fn global_update_flags(virt: VirtAddr, flags: PageFlags) -> Result<(), MapError> {
    match PAGE_TABLE_MANAGER.lock() {
        Ok(mut guard) => {
            let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;
            unsafe { manager.update_flags(virt, flags) }
        }
        Err(_) => {
            log::error!("[MM] Page Table Manager lock poisoned - returning HardwareError");
            Err(MapError::HardwareError)
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

