use super::{Elf64SectionHeader, ElfLoader, MAX_SECTIONS};

/// Section lookup fails independently of whether the requested name is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionError {
    InvalidTable,
    UnsupportedNumbering,
    TooManySections(usize),
    InvalidStringTable,
    InvalidName(usize),
    InvalidData(usize),
    NoFileData(usize),
    DuplicateName,
}

impl core::fmt::Display for SectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTable => {
                f.write_str("section table is outside ELF bounds or has invalid stride")
            }
            Self::UnsupportedNumbering => f.write_str("extended section numbering is unsupported"),
            Self::TooManySections(count) => {
                write!(f, "section count {count} exceeds loader capacity")
            }
            Self::InvalidStringTable => f.write_str("invalid section name string table"),
            Self::InvalidName(index) => write!(f, "invalid name for section {index}"),
            Self::InvalidData(index) => write!(f, "section {index} is outside ELF bounds"),
            Self::NoFileData(index) => write!(f, "section {index} has no file data"),
            Self::DuplicateName => f.write_str("multiple sections have the requested name"),
        }
    }
}

impl<'a> ElfLoader<'a> {
    /// Metadata sections must have a unique name and file backed contents. No
    /// allocation or mapping occurs here; malformed tables never mean absence.
    pub(in crate::loader) fn section_data(
        &self,
        name: &[u8],
    ) -> Result<Option<&'a [u8]>, SectionError> {
        let count = usize::from(self.header.e_shnum);
        let names_index = usize::from(self.header.e_shstrndx);
        let offset =
            usize::try_from(self.header.e_shoff).map_err(|_| SectionError::InvalidTable)?;
        if count == 0 {
            return if offset == 0 && names_index == 0 {
                Ok(None)
            } else {
                Err(SectionError::UnsupportedNumbering)
            };
        }
        if count > MAX_SECTIONS {
            return Err(SectionError::TooManySections(count));
        }
        if names_index == 0xffff {
            return Err(SectionError::UnsupportedNumbering);
        }
        let stride = usize::from(self.header.e_shentsize);
        if offset == 0 || stride < core::mem::size_of::<Elf64SectionHeader>() {
            return Err(SectionError::InvalidTable);
        }
        let end = count
            .checked_mul(stride)
            .and_then(|size| offset.checked_add(size))
            .ok_or(SectionError::InvalidTable)?;
        let table = self
            .data
            .get(offset..end)
            .ok_or(SectionError::InvalidTable)?;
        if names_index == 0 {
            return Ok(None);
        }
        if names_index >= count {
            return Err(SectionError::InvalidStringTable);
        }
        let names_header =
            crate::util::read_struct::<Elf64SectionHeader>(table, names_index * stride)
                .ok_or(SectionError::InvalidTable)?;
        if names_header.sh_type != 3 {
            return Err(SectionError::InvalidStringTable);
        }
        let names = self.section_bytes(&names_header, names_index)?;
        if names.first() != Some(&0) || names.last() != Some(&0) {
            return Err(SectionError::InvalidStringTable);
        }

        let mut found = None;
        for (index, slot) in table.chunks_exact(stride).enumerate() {
            let header = crate::util::read_struct::<Elf64SectionHeader>(slot, 0)
                .ok_or(SectionError::InvalidTable)?;
            if header.sh_name == 0 {
                continue;
            }
            let suffix = names
                .get(header.sh_name as usize..)
                .ok_or(SectionError::InvalidName(index))?;
            let end = suffix
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(SectionError::InvalidName(index))?;
            if &suffix[..end] != name {
                continue;
            }
            if found.is_some() {
                return Err(SectionError::DuplicateName);
            }
            if header.sh_type == 0 || header.sh_type == 8 {
                return Err(SectionError::NoFileData(index));
            }
            found = Some(self.section_bytes(&header, index)?);
        }
        Ok(found)
    }

    fn section_bytes(
        &self,
        header: &Elf64SectionHeader,
        index: usize,
    ) -> Result<&'a [u8], SectionError> {
        let start =
            usize::try_from(header.sh_offset).map_err(|_| SectionError::InvalidData(index))?;
        let size = usize::try_from(header.sh_size).map_err(|_| SectionError::InvalidData(index))?;
        let end = start
            .checked_add(size)
            .ok_or(SectionError::InvalidData(index))?;
        self.data
            .get(start..end)
            .ok_or(SectionError::InvalidData(index))
    }
}
