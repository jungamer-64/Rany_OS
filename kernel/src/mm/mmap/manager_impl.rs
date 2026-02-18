use super::*;


impl MmapManager {
    /// デフォルトのマッピング領域
    pub const DEFAULT_BASE: usize = 0x0000_7000_0000_0000;
    pub const DEFAULT_MAX: usize = 0x0000_7fff_ffff_ffff;

    pub const fn new() -> Self {
        Self {
            mappings: spin::RwLock::new(BTreeMap::new()),
            next_addr: AtomicUsize::new(Self::DEFAULT_BASE),
            base_addr: Self::DEFAULT_BASE,
            max_addr: Self::DEFAULT_MAX,
            total_mapped: AtomicUsize::new(0),
            total_unmapped: AtomicUsize::new(0),
        }
    }

    /// 空きアドレスを探す
    pub(super) fn find_free_address(&self, size: MappingSize) -> Option<MappedAddress> {
        let aligned_size = size.page_aligned().as_usize();
        let mappings = self.mappings.read();

        let mut current = self.next_addr.load(Ordering::Acquire);

        loop {
            if current + aligned_size > self.max_addr {
                return None;
            }

            // 既存のマッピングと重複チェック
            let overlaps = mappings.iter().any(|(_addr, mapping)| {
                let m = mapping.read();
                let m_start = m.address().as_usize();
                let m_end = m.end_address().as_usize();

                // 重複チェック
                !(current + aligned_size <= m_start || current >= m_end)
            });

            if !overlaps {
                // 次回のための更新
                self.next_addr
                    .store(current + aligned_size, Ordering::Release);
                return Some(MappedAddress::new(current));
            }

            // 次の候補
            current += MappingSize::PAGE_SIZE;
        }
    }

    /// 物理メモリを割り当てて仮想アドレスにマップ (SAS統合版)
    ///
    /// Buddy Allocatorから物理フレームを割り当て、ページテーブルにマップする。
    /// これにより、mmap()が実際のページテーブル操作と統合される。
    pub fn mmap_with_physical_alloc(
        &self,
        addr: Option<MappedAddress>,
        size: MappingSize,
        protection: Protection,
        flags: MappingFlags,
    ) -> Result<MappedAddress, MmapError> {
        use crate::mm::{PageFlags, alloc_frame};
        use x86_64::PhysAddr;

        if size.as_usize() == 0 {
            return Err(MmapError::InvalidSize);
        }

        let address = self.resolve_mmap_address(addr, size, &flags)?;
        let aligned_size = size.page_aligned();
        let page_count = aligned_size.page_count();
        let pt_flags = Self::build_page_flags(&protection, address);

        let allocated_frames = self.map_pages(address, page_count, pt_flags, &flags)?;
        let _ = allocated_frames; // ownership tracked by page table

        let mapping = MemoryMapping::anonymous(address, size, protection, flags)?;
        let mapping_size = mapping.size().as_usize();

        {
            let mut mappings = self.mappings.write();
            mappings.insert(address.as_usize(), Arc::new(spin::RwLock::new(mapping)));
        }

        self.total_mapped.fetch_add(mapping_size, Ordering::Relaxed);
        Ok(address)
    }

    /// Resolve the virtual address for a new mapping.
    pub(super) fn resolve_mmap_address(
        &self,
        addr: Option<MappedAddress>,
        size: MappingSize,
        flags: &MappingFlags,
    ) -> Result<MappedAddress, MmapError> {
        if let Some(a) = addr {
            if flags.fixed && !a.is_page_aligned() {
                return Err(MmapError::AlignmentError);
            }
            if flags.fixed {
                Ok(a)
            } else {
                self.find_free_address(size).ok_or(MmapError::OutOfMemory)
            }
        } else {
            self.find_free_address(size).ok_or(MmapError::OutOfMemory)
        }
    }

    /// Build page table flags from protection and address.
    pub(super) fn build_page_flags(protection: &Protection, address: MappedAddress) -> crate::mm::PageFlags {
        use crate::mm::PageFlags;
        let mut pt_flags = PageFlags::new(PageFlags::PRESENT);
        if protection.can_write() {
            pt_flags = pt_flags.set(PageFlags::WRITABLE);
        }
        if !protection.can_exec() {
            pt_flags = pt_flags.set(PageFlags::NO_EXECUTE);
        }
        if address.as_usize() < crate::mm::higher_half::VirtAddr::KERNEL_BASE as usize {
            pt_flags = pt_flags.set(PageFlags::USER);
        }
        pt_flags
    }

    /// Allocate physical frames and map them into the page table.
    pub(super) fn map_pages(
        &self,
        address: MappedAddress,
        page_count: usize,
        pt_flags: crate::mm::PageFlags,
        flags: &MappingFlags,
    ) -> Result<Vec<x86_64::structures::paging::PhysFrame>, MmapError> {
        use crate::mm::alloc_frame;
        use x86_64::PhysAddr;

        let mut allocated_frames = Vec::new();
        for i in 0..page_count {
            let frame = alloc_frame().ok_or(MmapError::OutOfMemory)?;
            let phys_addr = PhysAddr::new(frame.start_address().as_u64());
            let virt_addr = crate::mm::higher_half::VirtAddr::new(
                (address.as_usize() + i * MappingSize::PAGE_SIZE) as u64,
            );

            let map_result = unsafe {
                crate::mm::global_map_page(
                    virt_addr,
                    crate::mm::higher_half::PhysAddr::new(phys_addr.as_u64()),
                    pt_flags,
                )
            };

            if map_result.is_err() {
                for prev_frame in allocated_frames {
                    crate::mm::dealloc_frame(prev_frame);
                }
                return Err(MmapError::NoResources);
            }

            allocated_frames.push(frame);

            if flags.zero_init {
                unsafe {
                    let ptr = virt_addr.as_u64() as *mut u8;
                    core::ptr::write_bytes(ptr, 0, MappingSize::PAGE_SIZE);
                }
            }
        }
        Ok(allocated_frames)
    }

    /// SASリニアマッピング領域から仮想アドレスを取得
    ///
    /// 物理アドレスを直接マップしている領域（Higher Half）の仮想アドレスを返す。
    /// これはゼロコピー操作に最適。
    pub fn get_sas_linear_mapping(&self, phys_addr: u64, size: usize) -> Option<MappedAddress> {
        // SAS: 物理メモリは physical_memory_offset + phys_addr でアクセス可能
        let offset = crate::mm::mapping::physical_memory_offset();
        let virt_addr = offset + phys_addr;

        // 範囲チェック
        if size == 0 {
            return None;
        }

        Some(MappedAddress::new(virt_addr as usize))
    }

    /// 匿名マッピングを作成
    pub fn mmap_anonymous(
        &self,
        addr: Option<MappedAddress>,
        size: MappingSize,
        protection: Protection,
        flags: MappingFlags,
    ) -> Result<MappedAddress, MmapError> {
        if size.as_usize() == 0 {
            return Err(MmapError::InvalidSize);
        }

        let address = if let Some(a) = addr {
            if flags.fixed {
                if !a.is_page_aligned() {
                    return Err(MmapError::AlignmentError);
                }
                a
            } else {
                self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
            }
        } else {
            self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
        };

        let mapping = MemoryMapping::anonymous(address, size, protection, flags)?;
        let mapping_size = mapping.size().as_usize();

        {
            let mut mappings = self.mappings.write();
            mappings.insert(address.as_usize(), Arc::new(spin::RwLock::new(mapping)));
        }

        self.total_mapped.fetch_add(mapping_size, Ordering::Relaxed);
        Ok(address)
    }

    /// ファイルマッピングを作成
    pub fn mmap_file(
        &self,
        addr: Option<MappedAddress>,
        size: MappingSize,
        protection: Protection,
        flags: MappingFlags,
        path: &str,
        offset: MappingOffset,
    ) -> Result<MappedAddress, MmapError> {
        if size.as_usize() == 0 {
            return Err(MmapError::InvalidSize);
        }

        let address = if let Some(a) = addr {
            if flags.fixed {
                if !a.is_page_aligned() {
                    return Err(MmapError::AlignmentError);
                }
                a
            } else {
                self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
            }
        } else {
            self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
        };

        let mapping = MemoryMapping::file(address, size, protection, flags, path, offset)?;
        let mapping_size = mapping.size().as_usize();

        {
            let mut mappings = self.mappings.write();
            mappings.insert(address.as_usize(), Arc::new(spin::RwLock::new(mapping)));
        }

        self.total_mapped.fetch_add(mapping_size, Ordering::Relaxed);
        Ok(address)
    }

    /// マッピングを解除
    pub fn munmap(&self, addr: MappedAddress, _size: MappingSize) -> Result<(), MmapError> {
        let mut mappings = self.mappings.write();

        // 該当するマッピングを探す
        let mapping = mappings
            .remove(&addr.as_usize())
            .ok_or(MmapError::NotMapped)?;

        let mapping_size = mapping.read().size().as_usize();
        self.total_unmapped
            .fetch_add(mapping_size, Ordering::Relaxed);

        Ok(())
    }

    /// マッピングを解除し、物理フレームも解放する（SAS統合版）
    ///
    /// `mmap_with_physical_alloc`で作成したマッピングを解除する際に使用。
    /// ページテーブルのマッピングを解除し、物理フレームをBuddy Allocatorに返却する。
    pub fn munmap_with_physical_dealloc(
        &self,
        addr: MappedAddress,
        size: MappingSize,
    ) -> Result<(), MmapError> {
        use x86_64::structures::paging::PageSize;

        // マッピング情報を取得・削除
        let mapping = {
            let mut mappings = self.mappings.write();
            mappings
                .remove(&addr.as_usize())
                .ok_or(MmapError::NotMapped)?
        };

        let mapping_guard = mapping.read();
        let aligned_size = size.page_aligned();
        let page_count = aligned_size.page_count();

        // 各ページをアンマップして物理フレームを解放
        for i in 0..page_count {
            let virt_addr = crate::mm::higher_half::VirtAddr::new(
                (addr.as_usize() + i * MappingSize::PAGE_SIZE) as u64,
            );

            // ページテーブルから仮想アドレスを物理アドレスに変換
            if let Some(phys_addr) = crate::mm::global_translate(virt_addr) {
                // ページテーブルからアンマップ
                let _ = unsafe { crate::mm::global_unmap_page(virt_addr) };

                // 物理フレームをPMMに返却
                let frame = x86_64::structures::paging::PhysFrame::<
                    x86_64::structures::paging::Size4KiB,
                >::containing_address(x86_64::PhysAddr::new(
                    phys_addr.as_u64(),
                ));
                crate::mm::dealloc_frame(frame);
            }
        }

        let mapping_size = mapping_guard.size().as_usize();
        drop(mapping_guard);

        self.total_unmapped
            .fetch_add(mapping_size, Ordering::Relaxed);
        Ok(())
    }

    /// 保護を変更
    pub fn mprotect(
        &self,
        addr: MappedAddress,
        _size: MappingSize,
        protection: Protection,
    ) -> Result<(), MmapError> {
        let mappings = self.mappings.read();

        let mapping = mappings.get(&addr.as_usize()).ok_or(MmapError::NotMapped)?;

        let mut m = mapping.write();
        m.set_protection(protection)
    }

    /// 同期
    pub fn msync(&self, addr: MappedAddress, _size: MappingSize) -> Result<(), MmapError> {
        let mappings = self.mappings.read();

        let mapping = mappings.get(&addr.as_usize()).ok_or(MmapError::NotMapped)?;

        let mut m = mapping.write();
        m.sync()
    }

    /// マッピングを取得
    pub fn get_mapping(&self, addr: MappedAddress) -> Option<Arc<spin::RwLock<MemoryMapping>>> {
        let mappings = self.mappings.read();

        // 完全一致
        if let Some(m) = mappings.get(&addr.as_usize()) {
            return Some(m.clone());
        }

        // 範囲内のマッピングを探す
        for (_, mapping) in mappings.iter() {
            let m = mapping.read();
            if m.contains(addr) {
                return Some(mapping.clone());
            }
        }

        None
    }

    /// マッピング情報を取得
    pub fn info(&self, addr: MappedAddress) -> Option<MappingInfo> {
        let mapping = self.get_mapping(addr)?;
        let m = mapping.read();

        Some(MappingInfo {
            address: m.address(),
            size: m.size(),
            protection: m.protection(),
            is_shared: m.flags.shared,
            is_anonymous: matches!(m.mapping_type, MappingType::Anonymous),
            is_dirty: m.is_dirty(),
        })
    }

    /// 全マッピング情報を取得
    pub fn list_mappings(&self) -> Vec<MappingInfo> {
        let mappings = self.mappings.read();
        let mut result = Vec::new();

        for (_, mapping) in mappings.iter() {
            let m = mapping.read();
            result.push(MappingInfo {
                address: m.address(),
                size: m.size(),
                protection: m.protection(),
                is_shared: m.flags.shared,
                is_anonymous: matches!(m.mapping_type, MappingType::Anonymous),
                is_dirty: m.is_dirty(),
            });
        }

        result
    }

    /// 統計を取得
    pub fn stats(&self) -> MmapStats {
        MmapStats {
            total_mapped: self.total_mapped.load(Ordering::Relaxed),
            total_unmapped: self.total_unmapped.load(Ordering::Relaxed),
            active_mappings: self.mappings.read().len(),
        }
    }
}
