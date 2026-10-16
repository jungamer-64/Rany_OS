use super::*;

/// PKEY integration test: verify that loading a cell allocates a PKEY and
/// unloading the cell frees it.
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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
