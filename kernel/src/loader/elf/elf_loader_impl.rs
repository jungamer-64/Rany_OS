use super::*;
use alloc::collections::{BTreeMap, BTreeSet};


mod relocation;
impl<'a> ElfLoader<'a> {
    /// 新しいELFローダーを作成
    ///
    /// 【セキュリティ】入力データの境界チェックを厳密に実行
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
        ph: &Elf64ProgramHeader,
        segments: &mut Vec<SegmentInfo>,
        max_addr: &mut usize,
        alignment: &mut usize,
    ) -> Result<(), LoadError> {
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
    pub fn parse(&self) -> Result<CellInfo<'a>, LoadError> {
        let mut segments = Vec::new();
        segments.reserve(self.header.e_phnum as usize);

        // ゼロコピーでシンボル名を扱うため、Stringを使わず参照を蓄える
        let mut exports: Vec<(&'a str, u64)> = Vec::new();
        let mut imports: Vec<&'a str> = Vec::new();
        let mut max_addr = 0usize;
        let mut alignment = 4096usize;

        // 【セキュリティ】プログラムヘッダー数のチェック
        if self.header.e_phnum as usize > MAX_SEGMENTS {
            return Err(LoadError::InvalidFormat(alloc::format!(
                "Too many program headers: {} (max {})",
                self.header.e_phnum,
                MAX_SEGMENTS
            )));
        }

        // 【セキュリティ】セクションヘッダー数のチェック
        if self.header.e_shnum as usize > MAX_SECTIONS {
            return Err(LoadError::InvalidFormat(alloc::format!(
                "Too many section headers: {} (max {})",
                self.header.e_shnum,
                MAX_SECTIONS
            )));
        }

        // プログラムヘッダーを解析
        for i in 0..self.header.e_phnum {
            let ph_offset =
                self.header.e_phoff as usize + (i as usize * self.header.e_phentsize as usize);

            // 【設計書 2.2】安全なラッパーを使用
            let ph: Elf64ProgramHeader = crate::util::read_struct(self.data, ph_offset)
                .ok_or_else(|| LoadError::InvalidFormat("Failed to read program header".into()))?;

            if ph.p_type == PT_LOAD {
                Self::validate_load_segment(&ph, &mut segments, &mut max_addr, &mut alignment)?;
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

    /// シンボルを解析
    pub(super) fn parse_symbols(
        &self,
        exports: &mut Vec<(&'a str, u64)>,
        imports: &mut Vec<&'a str>,
    ) -> Result<(), LoadError> {
        let mut seen_exports: BTreeSet<(&'a str, u64)> = BTreeSet::new();
        let mut seen_imports: BTreeSet<&'a str> = BTreeSet::new();
        let mut processed_symtab = false;

        // まず .symtab を優先して処理する。存在する場合は .dynsym をスキップし、
        // 重複と追加コストを避ける（DriverCellのデバッグビルドでは .symtab が存在する）。
        for i in 0..self.header.e_shnum {
            let sh_offset =
                self.header.e_shoff as usize + (i as usize * self.header.e_shentsize as usize);

            // 【設計書 2.2】安全なラッパーを使用、エラーはスキップ
            let sh: Elf64SectionHeader = match crate::util::read_struct(self.data, sh_offset) {
                Some(sh) => sh,
                None => continue,
            };

            // シンボルテーブルを処理
            if sh.sh_type == SHT_SYMTAB {
                processed_symtab = true;
                self.process_symbol_table(
                    &sh,
                    exports,
                    imports,
                    &mut seen_exports,
                    &mut seen_imports,
                )?;
            }
        }

        if processed_symtab {
            return Ok(());
        }

        // .symtab が無い最小ELF向けフォールバックとして .dynsym を処理。
        for i in 0..self.header.e_shnum {
            let sh_offset =
                self.header.e_shoff as usize + (i as usize * self.header.e_shentsize as usize);

            let sh: Elf64SectionHeader = match crate::util::read_struct(self.data, sh_offset) {
                Some(sh) => sh,
                None => continue,
            };

            if sh.sh_type == SHT_DYNSYM {
                self.process_symbol_table(
                    &sh,
                    exports,
                    imports,
                    &mut seen_exports,
                    &mut seen_imports,
                )?;
            }
        }

        Ok(())
    }

    /// シンボルテーブルを処理
    pub(super) fn process_symbol_table(
        &self,
        sh: &Elf64SectionHeader,
        exports: &mut Vec<(&'a str, u64)>,
        imports: &mut Vec<&'a str>,
        seen_exports: &mut BTreeSet<(&'a str, u64)>,
        seen_imports: &mut BTreeSet<&'a str>,
    ) -> Result<(), LoadError> {
        crate::io::log::early_print("[LDBG] symtab enter\n");
        let sym_count = sh.sh_size as usize / mem::size_of::<Elf64Symbol>();
        let strtab = self.get_string_table(sh.sh_link as usize)?;

        // ある程度の容量を予約して再割り当てを減らす
        let reserve_amount = core::cmp::min(sym_count, MAX_SYMBOLS);
        crate::io::log::early_print("[LDBG] symtab reserve e\n");
        exports.reserve(reserve_amount);
        crate::io::log::early_print("[LDBG] symtab reserve i\n");
        imports.reserve(reserve_amount);
        crate::io::log::early_print("[LDBG] symtab loop\n");

        for j in 0..sym_count {
            let sym_offset = sh.sh_offset as usize + j * mem::size_of::<Elf64Symbol>();

            // 【設計書 2.2】安全なラッパーを使用、エラーはスキップ
            let sym: Elf64Symbol = match crate::util::read_struct(self.data, sym_offset) {
                Some(sym) => sym,
                None => continue,
            };

            // グローバルシンボルのみ処理
            if sym.binding() == STB_GLOBAL && sym.st_name != 0 {
                if let Some(name) = self.get_string(strtab, sym.st_name as usize) {
                    if name.is_empty() {
                        continue;
                    }
                    if sym.st_shndx == 0 {
                        // 未定義シンボル = インポート（ゼロコピー）
                        if seen_imports.insert(name) {
                            imports.push(name);
                        }
                    } else {
                        // 定義済みシンボル = エクスポート（ゼロコピー）
                        let export_key = (name, sym.st_value);
                        if seen_exports.insert(export_key) {
                            exports.push((name, sym.st_value));
                        }
                    }
                }
            }
        }

        crate::io::log::early_print("[LDBG] symtab done\n");
        Ok(())
    }

    /// 文字列テーブルを取得
    pub(super) fn get_string_table(&self, index: usize) -> Result<&'a [u8], LoadError> {
        let sh_offset = self.header.e_shoff as usize + (index * self.header.e_shentsize as usize);

        // 【設計書 2.2】安全なラッパーを使用
        let sh: Elf64SectionHeader = crate::util::read_struct(self.data, sh_offset)
            .ok_or_else(|| LoadError::InvalidFormat("Failed to read section header".into()))?;

        let start = sh.sh_offset as usize;
        let size = sh.sh_size as usize;

        // 【設計書 2.2】安全なスライス取得ラッパーを使用
        crate::util::get_slice(self.data, start, size)
            .ok_or_else(|| LoadError::InvalidFormat("String table out of bounds".into()))
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
    pub fn load(&self, info: &CellInfo<'a>) -> Result<LoadedCell, LoadError> {

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
            let pkey_raw = crate::security::mpk::allocate_protection_key()
                .ok_or(LoadError::OutOfMemory)?;
            PkeyGuard::new(pkey_raw)
        };

        // メモリを割り当て
        let base_address = self.allocate_memory(info.memory_size, info.alignment)?;

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
            entry_point,
            pkey: Some(pkey),
        });

        #[cfg(not(any(feature = "pkey_integration_test", not(test))))]
        return Ok(LoadedCell {
            base_address,
            size: info.memory_size,
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
    fn allocate_memory(&self, size: usize, _alignment: usize) -> Result<usize, LoadError> {
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

        // ASLRオフセットを適用したアドレスを返す
        let base_address = ptr.as_ptr() as usize + aslr_offset;

        log::debug!(
            "[ELF] Allocated {} bytes at {:#x} (ASLR offset: {:#x})",
            size,
            base_address,
            aslr_offset
        );

        Ok(base_address)
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

        let seg_start = crate::mm::virt::higher_half::VirtAddr::new(dest as u64).align_down().as_u64() as usize;
        let seg_end = crate::mm::virt::higher_half::VirtAddr::new((dest + mem_size) as u64)
            .align_up()
            .as_u64() as usize;

        for page_addr in (seg_start..seg_end).step_by(4096) {
            let virt = crate::mm::virt::higher_half::VirtAddr::new(page_addr as u64);
            unsafe {
                match crate::mm::virt::higher_half::global_update_flags(virt, flags) {
                    Ok(()) => {}
                    Err(e) => match e {
                        crate::mm::virt::higher_half::MapError::InvalidAddress | crate::mm::virt::higher_half::MapError::NotMapped => {
                            log::warn!(
                                "[ELF] Could not update flags for page {:#x}: {:?} (continuing)",
                                page_addr,
                                e
                            )
                        }
                        other => {
                            return Err(LoadError::InvalidPermissions(alloc::format!(
                                "Failed to update page flags for page {:#x}: {:?}",
                                page_addr, other
                            )));
                        }
                    },
                }
            }
        }

        Ok(())
    }

    #[cfg(any(test, feature = "bench"))]
    fn apply_page_flags(&self, _dest: usize, _mem_size: usize, _seg_flags: u32, _pkey: u8) -> Result<(), LoadError> {
        // No-op in tests and bench builds (full `mm` not available in library
        // builds that enable `bench`). This avoids bringing the full memory
        // manager into lightweight workspace runs.
        Ok(())
    }

    /// リロケーションを適用
    pub fn relocate<F>(&self, loaded: &LoadedCell, resolve: F) -> Result<(), LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        // セクションヘッダーを探索してリロケーションセクションを処理
        for i in 0..self.header.e_shnum {
            let sh_offset =
                self.header.e_shoff as usize + (i as usize * self.header.e_shentsize as usize);

            if sh_offset + mem::size_of::<Elf64SectionHeader>() > self.data.len() {
                continue;
            }

            let sh: Elf64SectionHeader = crate::util::read_struct(self.data, sh_offset)
                .ok_or_else(|| LoadError::InvalidFormat("Failed to read section header".into()))?;

            if sh.sh_type == SHT_RELA {
                self.apply_relocations(&sh, loaded, &resolve)?;
            }
        }

        Ok(())
    }

    /// リロケーションを適用
    fn apply_relocations<F>(
        &self,
        sh: &Elf64SectionHeader,
        loaded: &LoadedCell,
        resolve: &F,
    ) -> Result<(), LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        let rela_count = sh.sh_size as usize / mem::size_of::<Elf64Rela>();

        if rela_count > MAX_RELOCATIONS {
            return Err(LoadError::RelocationFailed(alloc::format!(
                "Too many relocations: {} (max {})",
                rela_count,
                MAX_RELOCATIONS
            )));
        }

        let symtab_sh = self.get_section_header(sh.sh_link as usize)?;
        let strtab = self.get_string_table(symtab_sh.sh_link as usize)?;

        let symtab_count = symtab_sh.sh_size as usize / mem::size_of::<Elf64Symbol>();
        let mut sym_value_cache: Vec<Option<usize>> = vec![None; symtab_count];

        for j in 0..rela_count {
            self.process_single_relocation(
                sh, j, &symtab_sh, strtab, symtab_count,
                loaded, resolve, &mut sym_value_cache,
            )?;
        }

        Ok(())
    }

    /// Process one relocation entry at index `j` within section `sh`.
    fn process_single_relocation<F>(
        &self,
        sh: &Elf64SectionHeader,
        j: usize,
        symtab_sh: &Elf64SectionHeader,
        strtab: &[u8],
        symtab_count: usize,
        loaded: &LoadedCell,
        resolve: &F,
        sym_value_cache: &mut Vec<Option<usize>>,
    ) -> Result<(), LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        let rela_offset = sh.sh_offset as usize + j * mem::size_of::<Elf64Rela>();
        if rela_offset + mem::size_of::<Elf64Rela>() > self.data.len() {
            return Ok(());
        }
        let rela: Elf64Rela = crate::util::read_struct(self.data, rela_offset)
            .ok_or_else(|| LoadError::InvalidFormat("Failed to read relocation".into()))?;

        let sym_idx = rela.symbol() as usize;
        if sym_idx >= symtab_count {
            return Ok(());
        }

        let sym_value = self.resolve_symbol_cached(
            sym_idx,
            symtab_sh,
            strtab,
            loaded,
            resolve,
            sym_value_cache,
        )?;

        self.apply_relocation(&rela, loaded.base_address, loaded.size, sym_value)?;
        Ok(())
    }

    /// シンボルを読み取って解決する
    fn read_and_resolve_symbol<F>(
        &self,
        sym_idx: usize,
        symtab_sh: &Elf64SectionHeader,
        strtab: &[u8],
        loaded: &LoadedCell,
        resolve: &F,
    ) -> Result<usize, LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        let sym_offset =
            symtab_sh.sh_offset as usize + sym_idx * mem::size_of::<Elf64Symbol>();

        if sym_offset + mem::size_of::<Elf64Symbol>() > self.data.len() {
            return Err(LoadError::InvalidFormat("Symbol offset out of range".into()));
        }

        let sym: Elf64Symbol = crate::util::read_struct(self.data, sym_offset)
            .ok_or_else(|| LoadError::InvalidFormat("Failed to read symbol".into()))?;

        if sym.st_shndx == 0 {
            // ELF symbol index 0 (or unnamed undefined symbols) represent
            // "no symbol" and must resolve to 0. This is common for
            // R_X86_64_RELATIVE relocations.
            if sym.st_name == 0 {
                return Ok(0);
            }
            let name = self
                .get_string(strtab, sym.st_name as usize)
                .ok_or_else(|| LoadError::InvalidFormat("Invalid symbol name".into()))?;
            if name.is_empty() {
                return Ok(0);
            }
            resolve(name)
                .ok_or_else(|| LoadError::UnresolvedDependency(name.to_string()))
        } else {
            Ok(loaded.base_address + sym.st_value as usize)
        }
    }

    /// Resolve a symbol by index, caching the result for reuse.
    fn resolve_symbol_cached<F>(
        &self,
        sym_idx: usize,
        symtab_sh: &Elf64SectionHeader,
        strtab: &[u8],
        loaded: &LoadedCell,
        resolve: &F,
        cache: &mut [Option<usize>],
    ) -> Result<usize, LoadError>
    where
        F: Fn(&str) -> Option<usize>,
    {
        if let Some(val) = cache[sym_idx] {
            return Ok(val);
        }

        let resolved = self.read_and_resolve_symbol(sym_idx, symtab_sh, strtab, loaded, resolve)?;

        cache[sym_idx] = Some(resolved);
        Ok(resolved)
    }

    /// セクションヘッダーを取得
    fn get_section_header(&self, index: usize) -> Result<Elf64SectionHeader, LoadError> {
        let sh_offset = self.header.e_shoff as usize + (index * self.header.e_shentsize as usize);

        if sh_offset + mem::size_of::<Elf64SectionHeader>() > self.data.len() {
            return Err(LoadError::InvalidFormat(
                "Section header out of bounds".into(),
            ));
        }

        Ok(crate::util::read_struct(self.data, sh_offset)
            .ok_or_else(|| LoadError::InvalidFormat("Failed to read section header".into()))?)
    }
}
