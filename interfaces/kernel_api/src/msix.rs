extern crate alloc;

/// Safe MSI-X vector metadata returned by kernel-managed configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixVectorInfo {
    pub vector: u32,
    pub table_index: u16,
}

impl MsixVectorInfo {
    pub const fn new(vector: u32, table_index: u16) -> Self {
        Self {
            vector,
            table_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MsixVectorInfo;

    #[test]
    fn vector_info_constructor_preserves_fields() {
        let info = MsixVectorInfo::new(0x66, 3);
        assert_eq!(info.vector, 0x66);
        assert_eq!(info.table_index, 3);
    }
}
