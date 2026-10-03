use super::*;

// ============================================================================
// Higher Half Kernel Manager
// ============================================================================

/// Higher Half Kernel マネージャー
pub struct HigherHalfManager {
    /// 物理メモリマッパー
    mapper: PhysicalMemoryMapper,
    /// 次に割り当て可能なカーネル仮想アドレス
    next_kernel_addr: AtomicU64,
}

impl HigherHalfManager {
    /// 新しいマネージャーを作成
    pub const fn new(physical_memory_offset: u64) -> Self {
        Self {
            mapper: PhysicalMemoryMapper::new(physical_memory_offset),
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

        // 脆弱性修正: カーネルスタック領域との衝突を防止
        if addr + size > VirtAddr::KERNEL_STACK_BASE {
            panic!(
                "[MM] Kernel heap overflow: requested address {:#x} exceeds KERNEL_STACK_BASE {:#x}",
                addr + size,
                VirtAddr::KERNEL_STACK_BASE
            );
        }

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

static HIGHER_HALF_MANAGER: spin::Once<HigherHalfManager> = spin::Once::new();

/// Publishes immutable HHDM geometry once before multiprocessor startup.
pub fn init(physical_memory_offset: u64) {
    let manager = HIGHER_HALF_MANAGER.call_once(|| HigherHalfManager::new(physical_memory_offset));
    assert_eq!(
        manager.physical_memory_offset(),
        physical_memory_offset,
        "HHDM geometry cannot be replaced"
    );
    init_page_table_manager(physical_memory_offset);
}

pub fn physical_memory_offset() -> u64 {
    HIGHER_HALF_MANAGER.get().map_or_else(
        crate::heap::physical_memory_offset,
        HigherHalfManager::physical_memory_offset,
    )
}

pub fn allocate_kernel_virt(pages: usize) -> VirtAddr {
    HIGHER_HALF_MANAGER
        .get()
        .expect("virtual allocation requires HHDM initialization")
        .allocate_kernel_virt(pages)
}

pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(
        phys.as_u64()
            .checked_add(physical_memory_offset())
            .expect("HHDM address overflow"),
    )
}

pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    virt.as_u64()
        .checked_sub(physical_memory_offset())
        .map(PhysAddr::new)
}

// ============================================================================// TLB Operations
// ============================================================================

/// TLBを無効化（単一アドレス）
#[inline]
pub fn invalidate_page(addr: VirtAddr) {
    // 従来のローカル無効化から、マルチコア対応のシュートダウンへアップグレード
    // Note: これにより、他CPUの古いTLBエントリによるUse-After-Freeや
    // 情報漏洩（古い読み込み専用エントリ経由の書き込み等）を防止する。
    // The shootdown boundary uses `x86_64::VirtAddr`; convert from our wrapper.
    crate::mm::sync::tlb::flush_immediate(x86_64::VirtAddr::new(addr.as_u64()));
}

/// TLBを全無効化
#[inline]
pub fn flush_tlb() {
    crate::mm::sync::tlb::flush_all();
}

/// CR3を設定
#[inline]
pub unsafe fn set_cr3(pml4_phys: PhysAddr) {
    // SAFETY: 呼び出し元がPML4テーブルの物理アドレスの有効性を保証する。
    // CR3操作はSPL設計でRing 0アクセスが保証される。
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
    FrameAllocation(crate::mm::phys::frame_allocator::FrameAllocError),
    MetadataAllocation,
    UnsupportedPageSize,
    /// 既にマップ済み
    AlreadyMapped,
    /// The mapping no longer refers to the caller's expected frame.
    MappingChanged,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbSyncState {
    Pending,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeUpdateError {
    pub cause: MapError,
    pub modified_start: VirtAddr,
    pub modified_size: u64,
    pub tlb_sync: TlbSyncState,
}

impl RangeUpdateError {
    fn unchanged(cause: MapError, start: VirtAddr) -> Self {
        Self {
            cause,
            modified_start: start,
            modified_size: 0,
            tlb_sync: TlbSyncState::Complete,
        }
    }
}

fn validate_range(start: VirtAddr, size: u64) -> Result<u64, MapError> {
    if start.as_u64() % 4096 != 0 || size % 4096 != 0 {
        return Err(MapError::AlignmentError);
    }
    let end = start
        .as_u64()
        .checked_add(size)
        .ok_or(MapError::InvalidAddress)?;
    x86_64::VirtAddr::try_new(start.as_u64()).map_err(|_| MapError::InvalidAddress)?;
    if size != 0 {
        x86_64::VirtAddr::try_new(end - 1).map_err(|_| MapError::InvalidAddress)?;
        if (start.as_u64() ^ (end - 1)) & (1 << 47) != 0 {
            return Err(MapError::InvalidAddress);
        }
    }
    Ok(end)
}

fn validate_physical_range(start: PhysAddr, size: u64) -> Result<(), MapError> {
    if !start.is_page_aligned() {
        return Err(MapError::AlignmentError);
    }
    if start
        .as_u64()
        .checked_add(size)
        .is_none_or(|end| end > 1u64 << 52)
    {
        return Err(MapError::InvalidAddress);
    }
    Ok(())
}

fn supports_1g_pages() -> bool {
    static SUPPORTED: spin::Once<bool> = spin::Once::new();
    *SUPPORTED.call_once(|| {
        // SAFETY: CPUID reads architectural feature information in every ring.
        core::arch::x86_64::__cpuid(0x80000000).eax >= 0x80000001
            && core::arch::x86_64::__cpuid(0x80000001).edx & (1 << 26) != 0
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmappedPage {
    pub physical: PhysAddr,
    pub virtual_start: VirtAddr,
    pub size: PageSize,
}

/// ページテーブルマネージャー
///
/// 仮想アドレスと物理アドレスのマッピングを管理する。
/// 4KiB, 2MiB, 1GiBページサイズをサポート。
#[derive(Debug)]
pub struct PageTableManager {
    table_frames:
        core::cell::RefCell<alloc::vec::Vec<crate::mm::phys::frame_allocator::PhysicalAllocation>>,
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
            table_frames: core::cell::RefCell::new(alloc::vec::Vec::new()),
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

    /// 使用するPML4を更新（プロセス切り替え等に対応）
    fn set_pml4_phys(&mut self, pml4_phys: PhysAddr) {
        self.pml4_phys = pml4_phys;
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
    /// - The caller retains the physical-memory owner until the mapping is
    ///   removed and all CPUs have completed the required TLB invalidation.
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
    /// - The caller retains ownership of every constituent frame through unmap
    ///   and completed TLB invalidation; mapping does not transfer ownership.
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

        Ok(())
    }

    /// 1GiBページをマップ（設計書5.1対応）
    ///
    /// # Safety
    /// - `virt` と `phys` は1GiBアラインされている必要がある
    /// - The caller retains ownership of every constituent frame through unmap
    ///   and completed TLB invalidation; mapping does not transfer ownership.
    pub unsafe fn map_1gb_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        const SIZE_1GB: u64 = PageSize::Size1GiB.as_bytes();
        if !supports_1g_pages() {
            return Err(MapError::UnsupportedPageSize);
        }

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

        Ok(())
    }

    /// ページをアンマップ
    ///
    /// 4KiB, 2MiB, 1GiBページを自動検出してアンマップする。
    pub unsafe fn unmap_page(&mut self, virt: VirtAddr) -> Result<UnmappedPage, MapError> {
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
            let phys =
                PhysAddr::new(pdpte.phys_addr().as_u64() & !(PageSize::Size1GiB.as_bytes() - 1));
            pdpte.clear();

            return Ok(UnmappedPage {
                physical: phys,
                virtual_start: VirtAddr::new(virt.as_u64() & !(PageSize::Size1GiB.as_bytes() - 1)),
                size: PageSize::Size1GiB,
            });
        }

        // PD
        let pd = self.get_table_mut(pdpte.phys_addr());
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() {
            return Err(MapError::NotMapped);
        }
        if pde.is_huge() {
            // 2MiBページ
            let phys =
                PhysAddr::new(pde.phys_addr().as_u64() & !(PageSize::Size2MiB.as_bytes() - 1));
            pde.clear();

            return Ok(UnmappedPage {
                physical: phys,
                virtual_start: VirtAddr::new(virt.as_u64() & !(PageSize::Size2MiB.as_bytes() - 1)),
                size: PageSize::Size2MiB,
            });
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

        Ok(UnmappedPage {
            physical: phys,
            virtual_start: virt,
            size: PageSize::Size4KiB,
        })
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
            let phys =
                PhysAddr::new(pdpte.phys_addr().as_u64() & !(PageSize::Size1GiB.as_bytes() - 1));
            *pdpte = PageTableEntry::huge(
                phys,
                Self::adjust_pat_for_huge(flags).set(PageFlags::PRESENT),
            );
            return Ok(());
        }

        let pd = self.get_table_mut(pdpte.phys_addr());
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() {
            return Err(MapError::NotMapped);
        }
        if pde.is_huge() {
            let phys =
                PhysAddr::new(pde.phys_addr().as_u64() & !(PageSize::Size2MiB.as_bytes() - 1));
            *pde = PageTableEntry::huge(
                phys,
                Self::adjust_pat_for_huge(flags).set(PageFlags::PRESENT),
            );
            return Ok(());
        }

        let pt = self.get_table_mut(pde.phys_addr());
        let pte = pt.entry_mut(indices[3]);
        if !pte.is_present() {
            return Err(MapError::NotMapped);
        }

        pte.set_flags(flags.set(PageFlags::PRESENT));

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

        if supports_1g_pages()
            && virt % SIZE_1GB == 0
            && phys % SIZE_1GB == 0
            && remaining >= SIZE_1GB
        {
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

    /// Range validation happens before publication. Failures retain the exact
    /// committed prefix; the global entry point synchronizes that prefix even
    /// on failure before returning to an owner that may reuse backing RAM.
    pub unsafe fn map_range(
        &mut self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: u64,
        flags: PageFlags,
    ) -> Result<(), RangeUpdateError> {
        let end = validate_range(virt_start, size)
            .map_err(|cause| RangeUpdateError::unchanged(cause, virt_start))?;
        validate_physical_range(phys_start, size)
            .map_err(|cause| RangeUpdateError::unchanged(cause, virt_start))?;
        let mut virt = virt_start.as_u64();
        let mut phys = phys_start.as_u64();
        // LOOP_PROOF: mode=condition; reason=Each committed page advances virt toward a validated exclusive end.;
        while virt < end {
            match unsafe { self.map_one_page(virt, phys, end - virt, flags) } {
                Ok(step) => {
                    virt += step;
                    phys += step;
                }
                Err(cause) => {
                    return Err(RangeUpdateError {
                        cause,
                        modified_start: virt_start,
                        modified_size: virt - virt_start.as_u64(),
                        tlb_sync: TlbSyncState::Pending,
                    });
                }
            }
        }
        Ok(())
    }

    /// A partially covered huge mapping requires an explicit demotion before
    /// mutation. Neighbouring mappings are never silently removed.
    pub unsafe fn unmap_range(
        &mut self,
        start: VirtAddr,
        size: u64,
    ) -> Result<(), RangeUpdateError> {
        let end = validate_range(start, size)
            .map_err(|cause| RangeUpdateError::unchanged(cause, start))?;
        let mut cursor = start.as_u64();
        // LOOP_PROOF: mode=condition; reason=Cursor advances by the actual leaf size or one absent 4KiB page.;
        while cursor < end {
            let virt = VirtAddr::new(cursor);
            let walker = PageTableWalker::new(self.pml4_phys, &self.mapper);
            let Some((_, page_size)) = walker.walk_mapping(virt) else {
                cursor += 4096;
                continue;
            };
            let step = page_size.as_bytes();
            if cursor % step != 0 || step > end - cursor {
                return Err(RangeUpdateError {
                    cause: MapError::AlignmentError,
                    modified_start: start,
                    modified_size: cursor - start.as_u64(),
                    tlb_sync: if cursor == start.as_u64() {
                        TlbSyncState::Complete
                    } else {
                        TlbSyncState::Pending
                    },
                });
            }
            if let Err(cause) = unsafe { self.unmap_page(virt) } {
                return Err(RangeUpdateError {
                    cause,
                    modified_start: start,
                    modified_size: cursor - start.as_u64(),
                    tlb_sync: if cursor == start.as_u64() {
                        TlbSyncState::Complete
                    } else {
                        TlbSyncState::Pending
                    },
                });
            }
            cursor += step;
        }
        Ok(())
    }
    /// Permission updates use whole existing leaves. A boundary cutting a
    /// huge leaf fails with the committed prefix; explicit demotion is separate.
    /// The caller must synchronize successful and partial changes before reuse.
    pub unsafe fn update_flags_range(
        &mut self,
        start: VirtAddr,
        size: u64,
        flags: PageFlags,
    ) -> Result<(), RangeUpdateError> {
        let end = validate_range(start, size)
            .map_err(|cause| RangeUpdateError::unchanged(cause, start))?;
        let mut cursor = start.as_u64();
        // LOOP_PROOF: mode=condition; reason=Each permission update advances by a validated whole leaf toward the finite end.;
        while cursor < end {
            let virt = VirtAddr::new(cursor);
            let leaf = PageTableWalker::new(self.pml4_phys, &self.mapper).walk_mapping(virt);
            let result = match leaf {
                None => Err(MapError::NotMapped),
                Some((_, page_size))
                    if cursor % page_size.as_bytes() != 0
                        || page_size.as_bytes() > end - cursor =>
                {
                    Err(MapError::AlignmentError)
                }
                Some((_, page_size)) => {
                    unsafe { self.update_flags(virt, flags) }.map(|()| page_size.as_bytes())
                }
            };
            match result {
                Ok(step) => cursor += step,
                Err(cause) => {
                    return Err(RangeUpdateError {
                        cause,
                        modified_start: start,
                        modified_size: cursor - start.as_u64(),
                        tlb_sync: if cursor == start.as_u64() {
                            TlbSyncState::Complete
                        } else {
                            TlbSyncState::Pending
                        },
                    });
                }
            }
        }
        Ok(())
    }

    /// Atomically replaces one existing 4KiB leaf without allocating tables.
    /// Failure leaves the mapping unchanged; success still needs TLB completion.
    /// # Safety
    /// The caller holds exclusive mapping mutation and source/destination RAM
    /// authority. Neither physical extent is used by DMA or payload borrowers.
    unsafe fn replace_owned_page(
        &mut self,
        virt: VirtAddr,
        source: &crate::mm::phys::frame_allocator::PhysicalAllocation,
        destination: &crate::mm::phys::frame_allocator::PhysicalAllocation,
    ) -> Result<(), MapError> {
        validate_range(virt, 4096)?;
        if source.page_count() != 1 || destination.page_count() != 1 {
            return Err(MapError::InvalidAddress);
        }
        let walker = PageTableWalker::new(self.pml4_phys, &self.mapper);
        let (entry, size) = walker.walk_mapping(virt).ok_or(MapError::NotMapped)?;
        if size != PageSize::Size4KiB {
            return Err(MapError::ParentEntryHugePage);
        }
        if entry.phys_addr().as_u64() != source.as_u64() {
            return Err(MapError::MappingChanged);
        }
        // SAFETY: the exclusive manager borrow excludes concurrent mutation;
        // the present 4KiB leaf was validated without releasing that authority.
        let target = unsafe { walker.walk_mut(virt) }.ok_or(MapError::NotMapped)?;
        *target = PageTableEntry::new(PhysAddr::new(destination.as_u64()), entry.flags());
        Ok(())
    }

    pub(super) fn get_table_mut(&self, phys: PhysAddr) -> &mut PageTable {
        let virt = self.mapper.phys_to_virt(phys);
        unsafe { &mut *virt.as_mut_ptr() }
    }

    /// テーブルエントリが存在しない場合は新しいテーブルを割り当て
    pub(super) fn ensure_table_entry(
        &self,
        table: &mut PageTable,
        index: usize,
        flags: PageFlags,
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
        // 脆弱性修正: USERビットは、要求されたフラグにUSERが含まれている場合のみ設定する。
        // これにより、カーネル専用領域の中間エントリにUSERビットが立つのを防止し、アイソレーションを強化。
        let mut entry_flags = PageFlags::new(PageFlags::PRESENT | PageFlags::WRITABLE);
        if flags.contains(PageFlags::USER) {
            entry_flags = entry_flags.set(PageFlags::USER);
        }
        *entry = PageTableEntry::new(new_table_phys, entry_flags);

        Ok(new_table_phys)
    }

    /// 新しいページテーブル用のフレームを割り当て
    pub(super) fn alloc_page_table(&self) -> Result<PhysAddr, MapError> {
        let mut owners = self.table_frames.borrow_mut();
        owners
            .try_reserve(1)
            .map_err(|_| MapError::MetadataAllocation)?;
        let frame =
            crate::mm::phys::frame_allocator::alloc_frame().map_err(MapError::FrameAllocation)?;
        let phys = PhysAddr::new(frame.as_u64());
        owners.push(frame);

        // Security: Register the new CPU page table as protected from DMA
        crate::security::dma::register_protected_page(phys.as_u64());

        Ok(phys)
    }
}

/// グローバルなページテーブルマネージャー
pub(crate) static PAGE_TABLE_MANAGER: crate::sync::IrqPoisonLock<Option<PageTableManager>> =
    crate::sync::IrqPoisonLock::new(None);

/// ページテーブルマネージャーを初期化
pub fn init_page_table_manager(physical_memory_offset: u64) {
    let mut manager = PAGE_TABLE_MANAGER
        .lock()
        .expect("page-table initialization lock poisoned");
    if let Some(existing) = manager.as_ref() {
        assert_eq!(
            existing.mapper.offset(),
            physical_memory_offset,
            "page-table HHDM cannot be replaced"
        );
        return;
    }
    // SAFETY: only the boot initialization boundary calls this privileged root
    // admission, before CPU startup; the active root and HHDM remain retained.
    *manager = Some(unsafe { PageTableManager::from_current_cr3(physical_memory_offset) });
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
    let mut guard = PAGE_TABLE_MANAGER.lock().map_err(|_| {
        log::error!("[MM] Page Table Manager lock poisoned");
        MapError::HardwareError
    })?;

    // Diagnose None manager case for debugging
    if guard.as_mut().is_none() {
        log::error!("[MM] global_map_page: PAGE_TABLE_MANAGER not initialized (None)");
        return Err(MapError::InvalidAddress);
    }

    let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;

    // 脆弱性修正: 常に現在のCR3を使用するように更新
    // これにより、プロセスごとのアドレス空間において、間違ったページテーブル（起動時PML4等）に
    // マッピングが作成されることを防止し、ページフォルト解決の不整合を解消する。
    manager.set_pml4_phys(get_cr3());

    log::info!(
        "[MM] global_map_page: mapping virt={:#x} phys={:#x} flags={:#x}",
        virt.as_u64(),
        phys.as_u64(),
        flags.as_u64()
    );
    let res = unsafe { manager.map_page(virt, phys, flags) };

    // ロックを解放してからTLBを無効化（デッドロック防止）
    drop(guard);
    if res.is_ok() {
        invalidate_page(virt);
    }
    res
}

/// グローバルページテーブルマネージャーでページをアンマップ
pub unsafe fn global_unmap_page(virt: VirtAddr) -> Result<UnmappedPage, MapError> {
    let mut guard = PAGE_TABLE_MANAGER.lock().map_err(|_| {
        log::error!("[MM] Page Table Manager lock poisoned");
        MapError::HardwareError
    })?;

    let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;

    // 現在のCR3を使用
    manager.set_pml4_phys(get_cr3());

    let res = unsafe { manager.unmap_page(virt) };

    // ロックを解放してからTLBを無効化（デッドロック防止）
    drop(guard);
    if let Ok(page) = &res {
        flush_range_tlb(page.virtual_start, page.size.as_bytes());
    }
    res
}

/// グローバルページテーブルマネージャーで仮想→物理変換
pub fn global_translate(virt: VirtAddr) -> Option<PhysAddr> {
    // Lock PAGE_TABLE_MANAGER instead of HIGHER_HALF_MANAGER for consistent synchronization
    match PAGE_TABLE_MANAGER.lock() {
        Ok(guard) => {
            let manager = guard.as_ref()?;
            let walker = PageTableWalker::new(get_cr3(), &manager.mapper);
            walker.translate(virt)
        }
        Err(_) => None,
    }
}

/// 仮想アドレスのPTEを取得（現在のCR3を使用）
pub fn get_current_pte(virt: VirtAddr) -> Option<PageTableEntry> {
    match PAGE_TABLE_MANAGER.lock() {
        Ok(guard) => {
            let manager = guard.as_ref()?;
            let walker = PageTableWalker::new(get_cr3(), &manager.mapper);
            walker.walk(virt)
        }
        Err(_) => None,
    }
}

fn flush_range_tlb(virt: VirtAddr, size: u64) {
    if size != 0 {
        crate::mm::sync::tlb::flush_range(x86_64::VirtAddr::new(virt.as_u64()), size);
    }
}

fn finish_range_update(
    start: VirtAddr,
    size: u64,
    result: Result<(), RangeUpdateError>,
) -> Result<(), RangeUpdateError> {
    match result {
        Ok(()) => {
            flush_range_tlb(start, size);
            Ok(())
        }
        Err(mut error) => {
            flush_range_tlb(error.modified_start, error.modified_size);
            error.tlb_sync = TlbSyncState::Complete;
            Err(error)
        }
    }
}

/// Updates a range and completes one shootdown for all committed changes.
/// On failure, `modified_size` and `tlb_sync` describe the committed prefix.
pub unsafe fn global_map_range(
    virt: VirtAddr,
    phys: PhysAddr,
    size: u64,
    flags: PageFlags,
) -> Result<(), RangeUpdateError> {
    let mut guard = PAGE_TABLE_MANAGER
        .lock()
        .map_err(|_| RangeUpdateError::unchanged(MapError::HardwareError, virt))?;
    let manager = guard
        .as_mut()
        .ok_or_else(|| RangeUpdateError::unchanged(MapError::InvalidAddress, virt))?;
    manager.set_pml4_phys(get_cr3());
    let result = unsafe { manager.map_range(virt, phys, size, flags) };
    drop(guard);
    finish_range_update(virt, size, result)
}

pub unsafe fn global_unmap_range(virt: VirtAddr, size: u64) -> Result<(), RangeUpdateError> {
    let mut guard = PAGE_TABLE_MANAGER
        .lock()
        .map_err(|_| RangeUpdateError::unchanged(MapError::HardwareError, virt))?;
    let manager = guard
        .as_mut()
        .ok_or_else(|| RangeUpdateError::unchanged(MapError::InvalidAddress, virt))?;
    manager.set_pml4_phys(get_cr3());
    let result = unsafe { manager.unmap_range(virt, size) };
    drop(guard);
    finish_range_update(virt, size, result)
}

/// Completes one shootdown over all permission changes, including a prefix
/// changed before failure. Neighbouring huge mappings retain their permissions.
pub unsafe fn global_update_flags_range(
    virt: VirtAddr,
    size: u64,
    flags: PageFlags,
) -> Result<(), RangeUpdateError> {
    let mut guard = PAGE_TABLE_MANAGER
        .lock()
        .map_err(|_| RangeUpdateError::unchanged(MapError::HardwareError, virt))?;
    let manager = guard
        .as_mut()
        .ok_or_else(|| RangeUpdateError::unchanged(MapError::InvalidAddress, virt))?;
    manager.set_pml4_phys(get_cr3());
    let result = unsafe { manager.update_flags_range(virt, size, flags) };
    drop(guard);
    finish_range_update(virt, size, result)
}

/// Replacement invalidates the entire unmapped range even if remapping fails.
/// Success/failure acknowledgement occurs after translation retirement.
pub unsafe fn global_replace_range(
    virt: VirtAddr,
    phys: PhysAddr,
    size: u64,
    flags: PageFlags,
) -> Result<(), RangeUpdateError> {
    validate_range(virt, size).map_err(|cause| RangeUpdateError::unchanged(cause, virt))?;
    validate_physical_range(phys, size)
        .map_err(|cause| RangeUpdateError::unchanged(cause, virt))?;
    let mut guard = PAGE_TABLE_MANAGER
        .lock()
        .map_err(|_| RangeUpdateError::unchanged(MapError::HardwareError, virt))?;
    let manager = guard
        .as_mut()
        .ok_or_else(|| RangeUpdateError::unchanged(MapError::InvalidAddress, virt))?;
    manager.set_pml4_phys(get_cr3());
    let result = match unsafe { manager.unmap_range(virt, size) } {
        Err(error) => Err(error),
        Ok(()) => unsafe { manager.map_range(virt, phys, size, flags) }.map_err(|mut error| {
            error.modified_size = size;
            error.tlb_sync = TlbSyncState::Pending;
            error
        }),
    };
    drop(guard);
    finish_range_update(virt, size, result)
}
/// Retires the expected page translation before consuming its RAM owner.
/// Failure changes no leaf and returns the unchanged source owner. Destination
/// ownership stays with the caller throughout publication and shootdown.
/// # Safety
/// `virt` is this source's sole non-HHDM mapping. The caller excludes payload
/// borrowers, DMA, mapping replacement and unmap until this operation completes.
/// HHDM is an immutable RAM view and grants no independent allocation authority.
pub(crate) unsafe fn global_replace_owned_page(
    virt: VirtAddr,
    source: crate::mm::phys::frame_allocator::PhysicalAllocation,
    destination: &crate::mm::phys::frame_allocator::PhysicalAllocation,
) -> Result<
    (),
    (
        MapError,
        crate::mm::phys::frame_allocator::PhysicalAllocation,
    ),
> {
    let result = match PAGE_TABLE_MANAGER.lock() {
        Ok(mut guard) => match guard.as_mut() {
            Some(manager) => {
                manager.set_pml4_phys(get_cr3());
                // SAFETY: the exclusive global lock and caller's owners cover
                // the entire comparison and one-leaf publication transition.
                unsafe { manager.replace_owned_page(virt, &source, destination) }
            }
            None => Err(MapError::InvalidAddress),
        },
        Err(_) => Err(MapError::HardwareError),
    };
    match result {
        Err(cause) => Err((cause, source)),
        Ok(()) => {
            flush_range_tlb(virt, 4096);
            source.release();
            Ok(())
        }
    }
}

/// 仮想アドレスのPTEを変更（現在のCR3を使用）
pub fn with_current_pte_mut<F, R>(virt: VirtAddr, f: F) -> Option<R>
where
    F: FnOnce(&mut PageTableEntry) -> R,
{
    // 脆弱性修正: ロックを保持したまま TLB シュートダウン (IPI) を行うと、
    // 他の CPU が同じロックを待機して割り込み禁止状態でスピンしている場合に
    // デッドロックが発生する可能性がある。ロック解除後にシュートダウンを行うように変更。
    let (res, changed) = match PAGE_TABLE_MANAGER.lock() {
        Ok(guard) => {
            if let Some(manager) = guard.as_ref() {
                let walker = PageTableWalker::new(get_cr3(), &manager.mapper);
                let r = unsafe { walker.walk_mut(virt).map(|pte| f(pte)) };
                let changed = r.is_some();
                (r, changed)
            } else {
                (None, false)
            }
        }
        Err(_) => (None, false),
    };

    if changed {
        invalidate_page(virt);
    }
    res
}

/// グローバルページテーブルマネージャーでページのフラグを更新（MPK PKEY適用用）
pub unsafe fn global_update_flags(virt: VirtAddr, flags: PageFlags) -> Result<(), MapError> {
    match PAGE_TABLE_MANAGER.lock() {
        Ok(mut guard) => {
            let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;

            // 現在のCR3を使用
            manager.set_pml4_phys(get_cr3());

            let res = unsafe { manager.update_flags(virt, flags) };

            // ロックを解放してからTLBを無効化（デッドロック防止）
            drop(guard);
            if res.is_ok() {
                invalidate_page(virt);
            }
            res
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
