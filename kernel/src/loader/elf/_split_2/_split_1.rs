use super::*;

impl<'a> ElfLoader<'a> {

    /// 単一のリロケーションを適用
    pub(super) fn apply_relocation(
        &self,
        rela: &Elf64Rela,
        base: usize,
        sym_value: usize,
    ) -> Result<(), LoadError> {
        let target = base + rela.r_offset as usize;

        // x86_64リロケーションタイプ
        match rela.reloc_type() {
            1 => {
                // R_X86_64_64: 64-bit absolute
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u64);
            }
            2 => {
                // R_X86_64_PC32: 32-bit PC-relative
                let value = (sym_value as i64)
                    .wrapping_add(rela.r_addend)
                    .wrapping_sub(target as i64);
                crate::util::write_to_addr(target, value as i32);
            }
            4 => {
                // R_X86_64_PLT32: 32-bit PLT-relative (treated same as PC32 for static linking)
                let value = (sym_value as i64)
                    .wrapping_add(rela.r_addend)
                    .wrapping_sub(target as i64);
                crate::util::write_to_addr(target, value as i32);
            }
            5 => {
                // R_X86_64_COPY: Copy symbol at runtime (no-op in kernel loader)
                // This is used by dynamic linkers for copy relocations
                log::debug!("[ELF] R_X86_64_COPY at {:#x} (no-op)", target);
            }
            6 => {
                // R_X86_64_GLOB_DAT: GOT entry for global data
                // Used for accessing global variables through the GOT
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u64);
            }
            7 => {
                // R_X86_64_JUMP_SLOT: PLT entry for function calls
                // Used for lazy binding in dynamic linking
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u64);
            }
            8 => {
                // R_X86_64_RELATIVE: Base address + addend
                let value = base.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u64);
            }
            9 => {
                // R_X86_64_GOTPCREL: GOT-relative PC32
                // S + A - P where S = symbol value (GOT entry address)
                // Note: In our simple loader, we treat GOT as pointing directly to symbol
                let value = (sym_value as i64)
                    .wrapping_add(rela.r_addend)
                    .wrapping_sub(target as i64);
                crate::util::write_to_addr(target, value as i32);
            }
            10 => {
                // R_X86_64_32: 32-bit absolute (zero-extended)
                let value = sym_value.wrapping_add(rela.r_addend as usize);
                crate::util::write_to_addr(target, value as u32);
            }
            11 => {
                // R_X86_64_32S: 32-bit absolute (sign-extended)
                let value = (sym_value as i64).wrapping_add(rela.r_addend);
                // 32ビット符号付き範囲のチェック
                if value > i32::MAX as i64 || value < i32::MIN as i64 {
                    return Err(LoadError::RelocationFailed(alloc::format!(
                        "R_X86_64_32S overflow at offset {:#x}: value {:#x} out of i32 range",
                        rela.r_offset,
                        value
                    )));
                }
                crate::util::write_to_addr(target, value as i32);
            }
            unknown => {
                // 未対応のリロケーションタイプはログ出力して継続
                log::warn!(
                    "[ELF] Unsupported relocation type {} at offset {:#x}",
                    unknown,
                    rela.r_offset
                );
            }
        }

        Ok(())
    }
}
