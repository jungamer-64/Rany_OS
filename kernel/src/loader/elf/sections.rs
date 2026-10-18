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
