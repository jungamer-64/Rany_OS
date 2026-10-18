use super::*;
use alloc::collections::BTreeMap;

mod relocation;
impl<'a> ElfLoader<'a> {
    /// 新しいELFローダーを作成
    ///
    /// 【セキュリティ】入力データの境界チェックを厳密に実行
    ///
    /// # Errors
    /// Rejects oversized/truncated inputs and unsupported ELF class, byte order
    /// or machine. Section and segment contents are validated when accessed;
    /// creating a parser does not grant execution admission.
    pub fn new(data: &'a [u8]) -> Result<Self, LoadError> {
        validate_elf_size(data)?;

        // 【設計書 2.2】安全なラッパーを使用してヘッダーを読み取り
        let header: Elf64Header = crate::util::read_struct(data, 0)
            .ok_or_else(|| LoadError::InvalidFormat("Failed to read ELF header".into()))?;

        // マジックナンバーの検証
        if header.e_ident[0..4] != ELF_MAGIC {
            return Err(LoadError::InvalidFormat("Invalid ELF magic".into()));
        }

        // 64ビットELFであることを確認
        if header.e_ident[4] != ELFCLASS64 {
            return Err(LoadError::InvalidFormat("Not 64-bit ELF".into()));
        }

        // リトルエンディアンであることを確認
        if header.e_ident[5] != ELFDATA2LSB {
            return Err(LoadError::InvalidFormat("Not little endian".into()));
        }

        // x86_64であることを確認
        if header.e_machine != 0x3E {
            return Err(LoadError::InvalidFormat("Not x86_64".into()));
        }

        Ok(Self { data, header })
    }

    /// 単一のPT_LOADセグメントを検証・解析する
    pub(super) fn validate_load_segment(
        &self,
        ph: &Elf64ProgramHeader,
        segments: &mut Vec<SegmentInfo>,
        max_addr: &mut usize,
        alignment: &mut usize,
    ) -> Result<(), LoadError> {
        if ph.p_filesz > ph.p_memsz {
            return Err(LoadError::InvalidFormat(
                "Segment file size exceeds memory size".into(),
            ));
        }
        let source_end = ph
            .p_offset
            .checked_add(ph.p_filesz)
            .ok_or_else(|| LoadError::InvalidFormat("Segment file range overflow".into()))?;
        if source_end > self.data.len() as u64 {
            return Err(LoadError::InvalidFormat("Segment data outside ELF".into()));
        }
        // 【セキュリティ】セグメントサイズのチェック
        if ph.p_memsz as usize > MAX_SEGMENT_SIZE {
            return Err(LoadError::InvalidFormat(alloc::format!(
                "Segment too large: {} bytes (max {})",
                ph.p_memsz,
                MAX_SEGMENT_SIZE
            )));
        }

        // 【セキュリティ】W^X (Writable XOR Executable) チェック
        let is_writable = (ph.p_flags & PF_W) != 0;
        let is_executable = (ph.p_flags & PF_X) != 0;
        if is_writable && is_executable {
            return Err(LoadError::InvalidPermissions(alloc::format!(
                "Segment at vaddr {:#x} is both writable and executable (W^X violation)",
                ph.p_vaddr
            )));
        }

        // 【セキュリティ】オーバーフローチェック
        let end_addr = (ph.p_vaddr as usize)
            .checked_add(ph.p_memsz as usize)
            .ok_or_else(|| LoadError::InvalidFormat("Segment address overflow".into()))?;

        *max_addr = (*max_addr).max(end_addr);
        *alignment = (*alignment).max(ph.p_align as usize);

        segments.push(SegmentInfo {
            file_offset: ph.p_offset as usize,
            vaddr: ph.p_vaddr as usize,
            file_size: ph.p_filesz as usize,
            mem_size: ph.p_memsz as usize,
            flags: ph.p_flags,
        });
        Ok(())
    }

    /// ELFをパースしてセル情報を取得
    ///
    /// 最適化:
    /// - シンボル名は `String` を割り当てずに `&str` で保持する（ゼロコピー）
    /// - セグメント/シンボルベクタに容量予約を行い再割り当てを減らす
    ///
    /// # Errors
    /// Rejects invalid table extents, excessive counts, malformed segments and
    /// writable executable mappings. Metadata allocation failure is recoverable;
    /// no executable allocation is made and no partial `CellInfo` is returned.
    pub fn parse(&self) -> Result<CellInfo<'a>, LoadError> {
        // 【セキュリティ】プログラムヘッダー数のチェック
        if self.header.e_phnum as usize > MAX_SEGMENTS {
            return Err(LoadError::InvalidFormat(alloc::format!(
                "Too many program headers: {} (max {})",
                self.header.e_phnum,
                MAX_SEGMENTS
            )));
        }

        self.section_headers().map_err(LoadError::InvalidSections)?;
        let mut segments = Vec::new();
        segments
            .try_reserve(usize::from(self.header.e_phnum))
            .map_err(|_| LoadError::OutOfMemory)?;
        let mut exports = Vec::new();
        let mut imports = Vec::new();
        let mut max_addr = 0usize;
        let mut alignment = 4096usize;
        if self.header.e_phnum != 0 {
            let stride = usize::from(self.header.e_phentsize);
            if stride < mem::size_of::<Elf64ProgramHeader>() {
                return Err(LoadError::InvalidFormat(
                    "Program header entry too small".into(),
                ));
            }
            let start = usize::try_from(self.header.e_phoff)
                .map_err(|_| LoadError::InvalidFormat("Program header offset overflow".into()))?;
            if start == 0 {
                return Err(LoadError::InvalidFormat(
                    "Missing program header table".into(),
                ));
            }
            let end = usize::from(self.header.e_phnum)
                .checked_mul(stride)
                .and_then(|size| start.checked_add(size))
                .ok_or_else(|| LoadError::InvalidFormat("Program header table overflow".into()))?;
            let table = self.data.get(start..end).ok_or_else(|| {
                LoadError::InvalidFormat("Program header table outside ELF".into())
            })?;
            for slot in table.chunks_exact(stride) {
                let ph: Elf64ProgramHeader =
                    crate::util::read_struct(slot, 0).ok_or_else(|| {
                        LoadError::InvalidFormat("Failed to read program header".into())
                    })?;
                if ph.p_type == PT_LOAD {
                    self.validate_load_segment(&ph, &mut segments, &mut max_addr, &mut alignment)?;
                }
            }
        }

        // シンボルテーブルを解析
        self.parse_symbols(&mut exports, &mut imports)?;

        Ok(CellInfo {
            entry_offset: self.header.e_entry,
            memory_size: max_addr,
            alignment,
            exports,
            imports,
            segments,
        })
    }

    fn parse_symbols(
        &self,
        exports: &mut Vec<(&'a str, u64)>,
        imports: &mut Vec<&'a str>,
    ) -> Result<(), LoadError> {
        let headers = self.section_headers().map_err(LoadError::InvalidSections)?;
        let mut has_static_symbols = false;
        for index in 0..headers.len() {
            let header = headers.get(index).map_err(LoadError::InvalidSections)?;
            if header.sh_type == SHT_SYMTAB {
                has_static_symbols = true;
                self.process_symbol_table(index, &header, exports, imports)?;
            }
        }
        if !has_static_symbols {
            for index in 0..headers.len() {
                let header = headers.get(index).map_err(LoadError::InvalidSections)?;
                if header.sh_type == SHT_DYNSYM {
                    self.process_symbol_table(index, &header, exports, imports)?;
                }
            }
        }
        Ok(())
    }

    /// シンボルテーブルを処理
    pub(super) fn process_symbol_table(
        &self,
        index: usize,
        sh: &Elf64SectionHeader,
        exports: &mut Vec<(&'a str, u64)>,
        imports: &mut Vec<&'a str>,
    ) -> Result<(), LoadError> {
        let records = self.symbol_records(index, sh)?;
        let sym_count = records.len() / mem::size_of::<Elf64Symbol>();
        let strtab = self.get_string_table(sh.sh_link as usize)?;

        // ある程度の容量を予約して再割り当てを減らす。
        // fallible reserve avoids heap-alloc panic; convert failures into errors.
        let reserve_amount = sym_count;
        if exports.try_reserve(reserve_amount).is_err() {
            return Err(LoadError::OutOfMemory);
        }
        if imports.try_reserve(reserve_amount).is_err() {
            return Err(LoadError::OutOfMemory);
        }

        for record in records.as_chunks::<{ mem::size_of::<Elf64Symbol>() }>().0 {
            let sym: Elf64Symbol = crate::util::read_struct(record, 0)
                .ok_or_else(|| LoadError::InvalidFormat("Invalid symbol record".into()))?;

            // グローバルシンボルのみ処理
            if sym.binding() == STB_GLOBAL
                && sym.st_name != 0
                && let Some(name) = self.get_string(strtab, sym.st_name as usize)
            {
                if name.is_empty() {
                    continue;
                }
                if sym.st_shndx == 0 {
                    // 未定義シンボル = インポート（ゼロコピー）
                    // avoid duplicates (linear scan, no allocations)
                    if !imports.contains(&name) {
                        imports.push(name);
                    }
                } else {
                    // 定義済みシンボル = エクスポート（ゼロコピー）
                    // avoid duplicate exports of same name/value
                    if !exports.iter().any(|&(n, v)| n == name && v == sym.st_value) {
                        exports.push((name, sym.st_value));
                    }
                }
            }
        }

        Ok(())
    }

    fn symbol_records(
        &self,
        index: usize,
        header: &Elf64SectionHeader,
    ) -> Result<&'a [u8], LoadError> {
        let size = mem::size_of::<Elf64Symbol>();
        if !matches!(header.sh_type, SHT_SYMTAB | SHT_DYNSYM)
            || header.sh_entsize != size as u64
            || !header.sh_size.is_multiple_of(size as u64)
        {
            return Err(LoadError::InvalidFormat(
                "Invalid symbol table layout".into(),
            ));
        }
        if header.sh_size / size as u64 > MAX_SYMBOLS as u64 {
            return Err(LoadError::InvalidFormat(
                "Symbol table exceeds loader capacity".into(),
            ));
        }
        self.section_bytes(header, index)
            .map_err(LoadError::InvalidSections)
    }

    fn get_string_table(&self, index: usize) -> Result<&'a [u8], LoadError> {
        let header = self
            .section_headers()
            .map_err(LoadError::InvalidSections)?
            .get(index)
            .map_err(LoadError::InvalidSections)?;
        if header.sh_type != 3 {
            return Err(LoadError::InvalidFormat(
                "Symbol names must reference a string table".into(),
            ));
        }
        let bytes = self
            .section_bytes(&header, index)
            .map_err(LoadError::InvalidSections)?;
        if bytes.first() != Some(&0) || bytes.last() != Some(&0) {
            return Err(LoadError::InvalidFormat(
                "Invalid symbol string table".into(),
            ));
        }
        Ok(bytes)
    }

    /// 文字列テーブルから文字列を取得
    ///
    /// 【セキュリティ】シンボル名の長さ制限を適用してDoS攻撃を防止
    pub(super) fn get_string(&self, strtab: &'a [u8], offset: usize) -> Option<&'a str> {
        if offset >= strtab.len() {
            return None;
        }

        let max_end = (offset + MAX_SYMBOL_NAME_LENGTH).min(strtab.len());
        let slice = &strtab[offset..max_end];
        let pos = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());

        // NULL終端が見つからなかった場合（文字列が長すぎる）
        if pos == slice.len() && (offset + pos >= strtab.len() || strtab[offset + pos] != 0) {
            // 警告を記録し、Noneを返す
            return None;
        }

        core::str::from_utf8(&slice[..pos]).ok()
    }

    /// セルをメモリにロード
    pub(in crate::loader) fn load(&self, info: &CellInfo<'a>) -> Result<LoadedCell, LoadError> {
        // Protection Key は page-table manager が利用可能な場合にのみ割り当てる。
        // テストビルド（libテスト）では `mm` モジュールが公開されていないため
        // PKEY の割り当てとページフラグの更新はスキップする。
        // PkeyGuard is available either in normal builds (when `test` cfg is
        // not set) or when the `pkey_integration_test` feature is enabled for
        // test-time integration checks.
        #[cfg(any(feature = "pkey_integration_test", not(test)))]
        struct PkeyGuard(Option<u8>);
        #[cfg(any(feature = "pkey_integration_test", not(test)))]
        impl PkeyGuard {
            pub(super) fn new(v: u8) -> Self {
                Self(Some(v))
            }

            /// Consume the guard and take ownership of the key so it will not be
            /// freed by Drop.
            pub(super) fn release(mut self) -> u8 {
                let v = self.0.take().unwrap();
                core::mem::forget(self);
                v
            }
        }
        #[cfg(any(feature = "pkey_integration_test", not(any(test, feature = "bench"))))]
        impl Drop for PkeyGuard {
            fn drop(&mut self) {
                if let Some(v) = self.0 {
                    crate::security::mpk::free_protection_key(v);
                }
            }
        }

        // Allocate PKEY only when mm is available (non-test builds). The guard
        // will free the PKEY on early return if something goes wrong.
        #[cfg(any(feature = "pkey_integration_test", not(any(test, feature = "bench"))))]
        let guard = {
            let pkey_raw =
                crate::security::mpk::allocate_protection_key().ok_or(LoadError::OutOfMemory)?;
            PkeyGuard::new(pkey_raw)
        };

        // メモリを割り当て
        let (base_address, allocation_base, allocation_size) =
            self.allocate_memory(info.memory_size, info.alignment)?;

        // PKEY を取得（テストビルドでは None）
        #[cfg(any(feature = "pkey_integration_test", not(any(test, feature = "bench"))))]
        let pkey = guard.release();
        #[cfg(not(any(feature = "pkey_integration_test", not(any(test, feature = "bench")))))]
        let pkey = 0u8; // ダミー値（テスト/ベンチではフラグ更新を行わないため使用されない）

        // 各セグメントをロード
        self.load_segments(info, base_address, pkey)?;

        let entry_point = if info.entry_offset != 0 {
            Some(base_address + info.entry_offset as usize)
        } else {
            None
        };

        #[cfg(any(feature = "pkey_integration_test", not(test)))]
        return Ok(LoadedCell {
            base_address,
            size: info.memory_size,
            allocation_base,
            allocation_size,
            entry_point,
            pkey: Some(pkey),
        });

        #[cfg(not(any(feature = "pkey_integration_test", not(test))))]
        return Ok(LoadedCell {
            base_address,
            size: info.memory_size,
            allocation_base,
            allocation_size,
            entry_point,
            pkey: None,
        });
    }

    /// 各セグメントをメモリにロードする
    fn load_segments(
        &self,
        info: &CellInfo<'a>,
        base_address: usize,
        pkey: u8,
    ) -> Result<(), LoadError> {
        // Copy/zero all segment contents first, then apply page protections.
        // Adjacent ELF segments can share a page; applying RX/RO too early can
        // fault when a later segment still needs to write into that page.
        for segment in &info.segments {
            if segment.file_size > segment.mem_size {
                return Err(LoadError::InvalidFormat(alloc::format!(
                    "Segment file_size > mem_size (vaddr={:#x}, file={}, mem={})",
                    segment.vaddr,
                    segment.file_size,
                    segment.mem_size
                )));
            }
            let seg_end = segment
                .vaddr
                .checked_add(segment.mem_size)
                .ok_or_else(|| LoadError::InvalidFormat("Segment range overflow".into()))?;
            if seg_end > info.memory_size {
                return Err(LoadError::InvalidFormat(alloc::format!(
                    "Segment out of bounds (vaddr={:#x}, mem={}, image={})",
                    segment.vaddr,
                    segment.mem_size,
                    info.memory_size
                )));
            }
            let dest = base_address + segment.vaddr;
            let src_start = segment.file_offset;
            let src_end = src_start + segment.file_size;

            if src_end > self.data.len() {
                return Err(LoadError::InvalidFormat(
                    "Segment data out of bounds".into(),
                ));
            }

            // データをコピー
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.data.as_ptr().add(src_start),
                    dest as *mut u8,
                    segment.file_size,
                );

                // BSS領域をゼロで初期化
                if segment.mem_size > segment.file_size {
                    let bss_start = dest + segment.file_size;
                    let bss_size = segment.mem_size - segment.file_size;
                    core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size);
                }
            }
        }

        // Apply page permissions after all copies complete. Adjacent ELF segments can
        // share a page (e.g. text tail + rodata head), so merge flags per page first
        // to avoid a later non-exec segment clobbering execute permission.
        let mut page_flags: BTreeMap<usize, u32> = BTreeMap::new();
        for segment in &info.segments {
            let dest = base_address + segment.vaddr;
            let seg_start = dest & !0xfffusize;
            let seg_end = (dest + segment.mem_size + 0xfffusize) & !0xfffusize;
            for page_addr in (seg_start..seg_end).step_by(4096) {
                let merged = page_flags.entry(page_addr).or_insert(0);
                *merged |= segment.flags;
            }
        }

        for (page_addr, flags) in page_flags {
            if (flags & PF_X) != 0 && (flags & PF_W) != 0 {
                log::warn!(
                    "[ELF] Page {:#x} spans writable+executable segments; preferring executable page flags",
                    page_addr
                );
            }
            self.apply_page_flags(page_addr, 4096, flags, pkey)?;
        }
        Ok(())
    }

    /// メモリを割り当て
    ///
    /// ASLRが有効な場合、ランダムなオフセットを加算してベースアドレスを予測困難にする
    fn allocate_memory(
        &self,
        size: usize,
        _alignment: usize,
    ) -> Result<(usize, usize, usize), LoadError> {
        // Note: フレームアロケータは mm::frame_allocator モジュールで実装
        // 現在はallocクレートを使用したヒープ割り当て
        use alloc::alloc::Layout;

        // ASLRが有効な場合、追加のパディング領域を確保
        let aslr_offset = if is_aslr_enabled() {
            generate_aslr_offset()
        } else {
            0
        };

        // サイズオーバーフローチェック
        let total_size = size
            .checked_add(aslr_offset)
            .ok_or(LoadError::OutOfMemory)?;

        let layout =
            Layout::from_size_align(total_size, 4096).map_err(|_| LoadError::OutOfMemory)?;

        let ptr = crate::util::allocate_zeroed(layout).ok_or(LoadError::OutOfMemory)?;

        let allocation_base = ptr.as_ptr() as usize;
        // ASLRオフセットを適用したアドレスを返す
        let base_address = allocation_base + aslr_offset;

        log::debug!(
            "[ELF] Allocated {} bytes at {:#x} (ASLR offset: {:#x})",
            size,
            base_address,
            aslr_offset
        );

        Ok((base_address, allocation_base, total_size))
    }

    /// Apply per-page flags for a memory range belonging to a segment.
    ///
    /// This is a thin wrapper that calls into `mm::global_update_flags` when
    /// compiled for the full kernel; for `#[cfg(test)]` builds this is a
    /// no-op to avoid depending on the `mm` module during library tests.
    #[cfg(not(any(test, feature = "bench")))]
    fn apply_page_flags(
        &self,
        dest: usize,
        mem_size: usize,
        seg_flags: u32,
        pkey: u8,
    ) -> Result<(), LoadError> {
        let flags = if (seg_flags & 0x1) != 0 {
            PageFlags::user_code().set_pkey(pkey)
        } else {
            PageFlags::user_data().set_pkey(pkey)
        };

        let seg_start = crate::mm::virt::higher_half::VirtAddr::new(dest as u64)
            .align_down()
            .as_u64() as usize;
        let seg_end = crate::mm::virt::higher_half::VirtAddr::new((dest + mem_size) as u64)
            .align_up()
            .as_u64() as usize;

        for page_addr in (seg_start..seg_end).step_by(4096) {
            let virt = crate::mm::virt::higher_half::VirtAddr::new(page_addr as u64);
            let updated_current = crate::mm::virt::higher_half::with_current_pte_mut(virt, |pte| {
                let mut new_flags = if pte.is_huge() {
                    // The current heap can be backed by 2MiB huge pages. We cannot
                    // express per-4KiB exec permissions without splitting the huge page,
                    // so keep the coarse mapping writable and clear NX for the whole
                    // huge page to avoid flipping the same PDE between exec/non-exec as
                    // we iterate segment pages.
                    pte.flags()
                        .set(PageFlags::PRESENT)
                        .set(PageFlags::WRITABLE)
                        .clear(PageFlags::NO_EXECUTE)
                        .set_pkey(pkey)
                        .set(PageFlags::HUGE_PAGE)
                } else {
                    flags.set(PageFlags::PRESENT)
                };
                if pte.is_huge() {
                    new_flags = new_flags.set(PageFlags::HUGE_PAGE);
                }
                pte.set_flags(new_flags);
            })
            .is_some();
            if updated_current {
                crate::mm::virt::higher_half::invalidate_page(virt);
                continue;
            }

            unsafe {
                match crate::mm::virt::higher_half::global_update_flags(virt, flags) {
                    Ok(()) => {}
                    Err(e) => match e {
                        crate::mm::virt::higher_half::MapError::InvalidAddress
                        | crate::mm::virt::higher_half::MapError::NotMapped => {
                            log::warn!(
                                "[ELF] Could not update flags for page {:#x}: {:?} (continuing)",
                                page_addr,
                                e
                            )
                        }
                        other => {
                            return Err(LoadError::InvalidPermissions(alloc::format!(
                                "Failed to update page flags for page {:#x}: {:?}",
                                page_addr,
                                other
                            )));
                        }
                    },
                }
            }
        }

        Ok(())
    }

    #[cfg(any(test, feature = "bench"))]
    fn apply_page_flags(
        &self,
        _dest: usize,
        _mem_size: usize,
        _seg_flags: u32,
        _pkey: u8,
    ) -> Result<(), LoadError> {
        // No-op in tests and bench builds (full `mm` not available in library
        // builds that enable `bench`). This avoids bringing the full memory
        // manager into lightweight workspace runs.
        Ok(())
    }

    pub(in crate::loader) fn relocate<F>(
        &self,
        loaded: &LoadedCell,
        resolve: F,
    ) -> Result<(), LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        let headers = self.section_headers().map_err(LoadError::InvalidSections)?;
        for index in 0..headers.len() {
            let header = headers.get(index).map_err(LoadError::InvalidSections)?;
            if header.sh_type == SHT_RELA {
                self.apply_relocations(index, &header, loaded, &resolve)?;
            }
        }
        Ok(())
    }

    fn apply_relocations<F>(
        &self,
        index: usize,
        header: &Elf64SectionHeader,
        loaded: &LoadedCell,
        resolve: &F,
    ) -> Result<(), LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        let size = mem::size_of::<Elf64Rela>();
        if header.sh_entsize != size as u64 || !header.sh_size.is_multiple_of(size as u64) {
            return Err(LoadError::RelocationFailed(
                "Invalid relocation table layout".into(),
            ));
        }
        if header.sh_size / size as u64 > MAX_RELOCATIONS as u64 {
            return Err(LoadError::RelocationFailed(
                "Relocation table exceeds loader capacity".into(),
            ));
        }
        let records = self
            .section_bytes(header, index)
            .map_err(LoadError::InvalidSections)?;
        let symtab_index = header.sh_link as usize;
        let symtab = self
            .section_headers()
            .map_err(LoadError::InvalidSections)?
            .get(symtab_index)
            .map_err(LoadError::InvalidSections)?;
        let symbols = self.symbol_records(symtab_index, &symtab)?;
        let strtab = self.get_string_table(symtab.sh_link as usize)?;
        let symbol_count = symbols.len() / mem::size_of::<Elf64Symbol>();
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(symbol_count)
            .map_err(|_| LoadError::OutOfMemory)?;
        cache.resize(symbol_count, None);
        for record in records.as_chunks::<{ mem::size_of::<Elf64Rela>() }>().0 {
            let rela: Elf64Rela = crate::util::read_struct(record, 0)
                .ok_or_else(|| LoadError::RelocationFailed("Invalid relocation record".into()))?;
            let symbol_index = rela.symbol() as usize;
            // STN_UNDEF supplies zero without resolving a symbol definition.
            let value = if symbol_index == 0 {
                0
            } else {
                self.resolve_symbol_cached(
                    symbol_index,
                    symbols,
                    strtab,
                    loaded,
                    resolve,
                    &mut cache,
                )?
            };
            self.apply_relocation(&rela, loaded.base_address, loaded.size, value)?;
        }
        Ok(())
    }

    fn resolve_symbol_cached<F>(
        &self,
        index: usize,
        symbols: &[u8],
        strtab: &[u8],
        loaded: &LoadedCell,
        resolve: &F,
        cache: &mut [Option<usize>],
    ) -> Result<usize, LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        let cached = cache.get_mut(index).ok_or_else(|| {
            LoadError::RelocationFailed("Relocation symbol index outside table".into())
        })?;
        if let Some(value) = *cached {
            return Ok(value);
        }
        let record = symbols
            .as_chunks::<{ mem::size_of::<Elf64Symbol>() }>()
            .0
            .get(index)
            .ok_or_else(|| {
                LoadError::RelocationFailed("Relocation symbol index outside table".into())
            })?;
        let sym: Elf64Symbol = crate::util::read_struct(record, 0)
            .ok_or_else(|| LoadError::InvalidFormat("Invalid symbol record".into()))?;
        let value = if sym.st_shndx == 0 {
            let name = self
                .get_string(strtab, sym.st_name as usize)
                .ok_or_else(|| LoadError::InvalidFormat("Invalid symbol name".into()))?;
            if name.is_empty() {
                0
            } else {
                resolve(name).ok_or_else(|| LoadError::UnresolvedDependency(name.to_string()))?
            }
        } else {
            loaded
                .base_address
                .checked_add(sym.st_value as usize)
                .ok_or_else(|| LoadError::RelocationFailed("Symbol address overflow".into()))?
        };
        *cached = Some(value);
        Ok(value)
    }
}

// -----------------------------------------------------------------------------
// tests for ELF loader internals (outside of the impl block)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod loader_tests;
