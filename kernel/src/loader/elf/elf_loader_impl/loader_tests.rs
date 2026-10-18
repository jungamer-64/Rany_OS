use super::*;
use core::cell::Cell;

struct Section<'a> {
    kind: u32,
    link: u32,
    entry_bytes: u64,
    data: &'a [u8],
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// Independent ELF64 wire fixture, including a reserved null section. Section
// names are absent; symbol names use their own explicitly linked string table.
fn artifact(sections: &[Section<'_>]) -> Vec<u8> {
    let mut bytes = vec![0; 64 + (sections.len() + 1) * 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 0x3e);
    put_u32(&mut bytes, 20, 1);
    put_u16(&mut bytes, 52, 64);
    put_u64(&mut bytes, 40, 64);
    put_u16(&mut bytes, 58, 64);
    put_u16(&mut bytes, 60, (sections.len() + 1) as u16);
    for (index, section) in sections.iter().enumerate() {
        let offset = (bytes.len() + 7) & !7;
        bytes.resize(offset, 0);
        let header = 64 + (index + 1) * 64;
        put_u32(&mut bytes, header + 4, section.kind);
        put_u64(&mut bytes, header + 24, offset as u64);
        put_u64(&mut bytes, header + 32, section.data.len() as u64);
        put_u32(&mut bytes, header + 40, section.link);
        put_u64(&mut bytes, header + 48, 8);
        put_u64(&mut bytes, header + 56, section.entry_bytes);
        bytes.extend_from_slice(section.data);
    }
    bytes
}

fn symbols() -> [u8; 48] {
    let mut bytes = [0; 48];
    put_u32(&mut bytes, 24, 1); // second symbol names "item"
    bytes[28] = 0x10; // STB_GLOBAL, undefined
    bytes
}

fn relocation(offset: u64, symbol: u32, addend: u64) -> [u8; 24] {
    let mut bytes = [0; 24];
    put_u64(&mut bytes, 0, offset);
    put_u64(&mut bytes, 8, (u64::from(symbol) << 32) | 1); // R_X86_64_64
    put_u64(&mut bytes, 16, addend);
    bytes
}

fn relocatable(records: &[u8]) -> Vec<u8> {
    artifact(&[
        Section {
            kind: 3,
            link: 0,
            entry_bytes: 0,
            data: b"\0item\0",
        },
        Section {
            kind: 2,
            link: 1,
            entry_bytes: 24,
            data: &symbols(),
        },
        Section {
            kind: 4,
            link: 2,
            entry_bytes: 24,
            data: records,
        },
    ])
}

fn image(storage: &mut [u64]) -> LoadedCell {
    LoadedCell {
        base_address: storage.as_mut_ptr() as usize,
        size: core::mem::size_of_val(storage),
        allocation_base: 0,
        allocation_size: 0,
        entry_point: None,
        pkey: None,
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn parsing_keeps_symbol_names_borrowed_from_the_linked_table() {
    let bytes = relocatable(&[]);
    let info = ElfLoader::new(&bytes).unwrap().parse().unwrap();
    assert_eq!(info.imports, ["item"]);
    assert!(info.exports.is_empty());
    let name = info.imports[0].as_ptr() as usize;
    assert!((bytes.as_ptr() as usize..bytes.as_ptr() as usize + bytes.len()).contains(&name));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn parsing_rejects_truncated_section_tables_and_invalid_stride() {
    let original = relocatable(&[]);
    let mut bytes = original.clone();
    put_u64(&mut bytes, 40, u64::MAX);
    assert!(matches!(
        ElfLoader::new(&bytes).unwrap().parse(),
        Err(LoadError::InvalidSections(SectionError::InvalidTable))
    ));
    bytes.copy_from_slice(&original);
    put_u16(&mut bytes, 58, 63);
    assert!(matches!(
        ElfLoader::new(&bytes).unwrap().parse(),
        Err(LoadError::InvalidSections(SectionError::InvalidTable))
    ));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn parsing_rejects_invalid_symbol_layout_and_capacity_exhaustion() {
    let original = relocatable(&[]);
    let symbol_header = 64 + 2 * 64;
    let mut bytes = original.clone();
    put_u64(&mut bytes, symbol_header + 32, 47);
    assert!(matches!(
        ElfLoader::new(&bytes).unwrap().parse(),
        Err(LoadError::InvalidFormat(_))
    ));
    bytes.copy_from_slice(&original);
    put_u64(
        &mut bytes,
        symbol_header + 32,
        (MAX_SYMBOLS as u64 + 1) * 24,
    );
    assert!(matches!(
        ElfLoader::new(&bytes).unwrap().parse(),
        Err(LoadError::InvalidFormat(_))
    ));
    bytes.copy_from_slice(&original);
    put_u32(&mut bytes, symbol_header + 40, 2); // link must identify SHT_STRTAB
    assert!(matches!(
        ElfLoader::new(&bytes).unwrap().parse(),
        Err(LoadError::InvalidFormat(_))
    ));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn program_header_overflow_and_truncation_fail_before_image_allocation() {
    let mut bytes = artifact(&[]);
    put_u16(&mut bytes, 54, 56);
    put_u16(&mut bytes, 56, 1);
    put_u64(&mut bytes, 32, u64::MAX);
    assert!(matches!(
        ElfLoader::new(&bytes).unwrap().parse(),
        Err(LoadError::InvalidFormat(_))
    ));
    let offset = bytes.len() as u64;
    put_u64(&mut bytes, 32, offset);
    bytes.extend_from_slice(&[0; 55]);
    assert!(matches!(
        ElfLoader::new(&bytes).unwrap().parse(),
        Err(LoadError::InvalidFormat(_))
    ));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn relocation_binds_each_symbol_consistently() {
    let mut records = relocation(0, 1, 7).to_vec();
    records.extend_from_slice(&relocation(8, 1, 9));
    let bytes = relocatable(&records);
    let loader = ElfLoader::new(&bytes).unwrap();
    let mut storage = [0u64; 2];
    let loaded = image(&mut storage);
    let calls = Cell::new(0);
    loader
        .relocate(&loaded, |name| {
            assert_eq!(name, "item");
            let address = 0x1000 + calls.get() * 0x1000;
            calls.set(calls.get() + 1);
            Some(address)
        })
        .unwrap();
    assert_eq!(storage, [0x1007, 0x1009]);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn undefined_symbol_index_supplies_zero_without_provider_lookup() {
    let bytes = relocatable(&relocation(0, 0, 5));
    let loader = ElfLoader::new(&bytes).unwrap();
    let mut storage = [0u64];
    let loaded = image(&mut storage);
    loader
        .relocate(&loaded, |_| panic!("STN_UNDEF does not resolve a provider"))
        .unwrap();
    assert_eq!(storage, [5]);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn relocation_rejects_missing_symbols_and_incomplete_records() {
    let invalid = relocatable(&relocation(0, 2, 0));
    let partial = relocatable(&relocation(0, 1, 0)[..23]);
    for bytes in [&invalid, &partial] {
        let loader = ElfLoader::new(bytes).unwrap();
        let mut storage = [0xfeed_u64];
        let loaded = image(&mut storage);
        assert!(matches!(
            loader.relocate(&loaded, |_| Some(1)),
            Err(LoadError::RelocationFailed(_))
        ));
        assert_eq!(storage, [0xfeed]);
    }
}
