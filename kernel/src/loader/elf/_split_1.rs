use super::*;


// ============================================================================
// Loader Trait - 静的APIを提供
// ============================================================================

/// ロード結果の情報
///
/// ELFバイナリをメモリにロードした後の結果情報を保持する構造体。
/// `registry.rs`との互換性のために使用される。
///
/// # Example
///
/// ```ignore
/// let info: LoadedInfo = ElfLoader::load(elf_data)?;
/// let entry_fn: fn() = unsafe { core::mem::transmute(info.entry_point) };
/// entry_fn(); // 関数を呼び出す
/// ```
#[derive(Debug)]
pub struct LoadedInfo {
    /// メモリ上のベースアドレス
    pub base_address: u64,
    /// 割り当てられたメモリの合計サイズ（バイト）
    pub size: usize,
    /// プログラムのエントリポイントアドレス
    pub entry_point: u64,
    /// 割り当てられた Protection Key（存在する場合）
    pub pkey: Option<u8>,
}

/// ELFローダーの静的インターフェース
///
/// このトレイトは静的メソッドを通じてELFロード機能を提供する。
/// 実装タイプのインスタンスを作成せずにロードを実行可能。
///
/// # 使用例
///
/// ```ignore
/// use kernel::loader::{ElfLoader, Loader};
///
/// let result = <ElfLoader as Loader>::load(elf_bytes)?;
/// ```
pub trait Loader {
    /// ELFデータからセルをメモリにロード
    ///
    /// # 引数
    ///
    /// * `elf_data` - ELF64バイナリデータ
    ///
    /// # 戻り値
    ///
    /// 成功時は`LoadedInfo`を返し、失敗時は`LoadError`を返す
    ///
    /// # エラー
    ///
    /// * `InvalidFormat` - ELFフォーマットが無効
    /// * `InvalidPermissions` - W^X違反
    /// * `OutOfMemory` - メモリ割り当て失敗
    /// * `RelocationFailed` - リロケーション適用エラー
    fn load(elf_data: &[u8]) -> Result<LoadedInfo, LoadError>;
}

impl Loader for ElfLoader<'_> {
    /// ELFデータをパースしてメモリにロードする静的メソッド
    ///
    /// registry.rs との互換性のためのシンプルなAPI
    fn load(elf_data: &[u8]) -> Result<LoadedInfo, LoadError> {
        // 1. ELFをパース
        let loader = ElfLoader::new(elf_data)?;
        let cell_info = loader.parse()?;

        // 2. メモリにロード
        let loaded = loader.load(&cell_info)?;

        // 3. リロケーションを適用（シンボル解決なし - 自己完結型モジュール用）
        loader.relocate(&loaded, |_sym| None)?;

        // 4. 結果を返す
        Ok(LoadedInfo {
            base_address: loaded.base_address as u64,
            size: loaded.size,
            entry_point: loaded.entry_point.unwrap_or(0) as u64,
            pkey: loaded.pkey,
        })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_empty_data_returns_error() -> bool {
    match ElfLoader::new(&[]) {
        Err(LoadError::InvalidFormat(msg)) => msg.contains("too small"),
        _ => false,
    }
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_invalid_magic_returns_error() -> bool {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    match ElfLoader::new(&data) {
        Err(LoadError::InvalidFormat(msg)) => msg.contains("magic") || msg.contains("Invalid"),
        _ => false,
    }
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_max_size_constants() -> bool {
    MAX_ELF_SIZE == 512 * 1024 * 1024
        && MAX_SEGMENT_SIZE == 256 * 1024 * 1024
        && MAX_SECTIONS == 1024
        && MAX_RELOCATIONS == 262144
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_wrong_elf_class() -> bool {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&ELF_MAGIC);
    data[4] = 1; // ELFCLASS32
    ElfLoader::new(&data).is_err()
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_wrong_endianness() -> bool {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&ELF_MAGIC);
    data[4] = ELFCLASS64;
    data[5] = 2; // ELFDATA2MSB
    ElfLoader::new(&data).is_err()
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_wx_flags() -> bool {
    PF_W == 0x2 && PF_X == 0x1 && (PF_W | PF_X) == 0x3
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_rela_extraction() -> bool {
    let rela = Elf64Rela {
        r_offset: 0x1000,
        r_info: (42 << 32) | 8,
        r_addend: 0x100,
    };
    rela.symbol() == 42 && rela.reloc_type() == 8
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_symbol_extraction() -> bool {
    let sym = Elf64Symbol {
        st_name: 0,
        st_info: (1 << 4) | 2,
        st_other: 0,
        st_shndx: 1,
        st_value: 0x1000,
        st_size: 100,
    };
    sym.binding() == 1 && sym.symbol_type() == 2
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_aslr_offset_generation() -> bool {
    let prev = is_aslr_enabled();
    set_aslr_enabled(true);
    let offset1 = generate_aslr_offset();
    let offset2 = generate_aslr_offset();
    set_aslr_enabled(prev);
    (offset1 & 0xFFF) == 0
        && (offset2 & 0xFFF) == 0
        && offset1 < ASLR_MAX_OFFSET
        && offset2 < ASLR_MAX_OFFSET
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_aslr_enable_disable() -> bool {
    let prev = is_aslr_enabled();
    set_aslr_enabled(false);
    let disabled = !is_aslr_enabled();
    set_aslr_enabled(true);
    let enabled = is_aslr_enabled();
    set_aslr_enabled(prev);
    disabled && enabled
}

#[cfg(feature = "qemu-test-export")]
pub(crate) fn qemu_smoke_get_string_zero_copy() -> bool {
    let strtab: &[u8] = b"hello\0world\0";
    let header: Elf64Header = unsafe { core::mem::zeroed() };
    let loader = ElfLoader {
        data: strtab,
        header,
    };
    let s1 = loader.get_string(strtab, 0);
    let s2 = loader.get_string(strtab, 6);
    s1 == Some("hello") && s2 == Some("world")
}

#[cfg(all(test, feature = "pkey_integration_test"))]
mod tests {
    use super::*;

    /// PKEY integration test: verify that loading a cell allocates a PKEY and
    /// unloading the cell frees it.
    #[test_case]
    fn test_pkey_alloc_and_free_on_load_unload() {
        use core::mem;

        crate::security::mpk::test_reset_pkey_allocator();

        let ph_size = mem::size_of::<Elf64ProgramHeader>();
        let mut data = vec![0u8; 64 + ph_size];

        let mut header: Elf64Header = unsafe { core::mem::zeroed() };
        header.e_ident[0..4].copy_from_slice(&ELF_MAGIC);
        header.e_ident[4] = ELFCLASS64;
        header.e_ident[5] = ELFDATA2LSB;
        header.e_machine = 0x3E;
        header.e_phoff = 64;
        header.e_phentsize = ph_size as u16;
        header.e_phnum = 1;

        crate::util::write_struct(&mut data, 0, header).expect("write header");

        let ph = Elf64ProgramHeader {
            p_type: PT_LOAD,
            p_flags: 0,
            p_offset: (64 + ph_size) as u64,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 4096,
            p_align: 4096,
        };

        crate::util::write_struct(&mut data, header.e_phoff as usize, ph).expect("write ph");

        let cell_id = crate::loader::load_cell("test-pkey", &data, false).expect("load_cell");
        let pkey_opt = crate::loader::with_registry(|r| r.find_by_name("test-pkey").unwrap().pkey);
        assert!(pkey_opt.is_some());
        let pkey = pkey_opt.unwrap();
        assert!(crate::security::mpk::is_pkey_used(pkey));

        crate::loader::unload_cell(cell_id).expect("unload");
        assert!(!crate::security::mpk::is_pkey_used(pkey));
    }
}

