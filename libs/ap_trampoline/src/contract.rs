// ============================================================================
// libs/ap_trampoline/src/contract.rs
// ============================================================================
use core::mem::size_of;

pub(crate) const GDT_ENTRY_COUNT: usize = 4;
pub(crate) const GDT_SIZE: usize = GDT_ENTRY_COUNT * size_of::<u64>();
pub(crate) const GDT32_CODE_SELECTOR: u16 = 0x08;
pub(crate) const GDT32_DATA_SELECTOR: u16 = 0x10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdt_size_matches_entry_count() {
        assert_eq!(GDT_SIZE, 4 * size_of::<u64>());
    }

    #[test]
    fn gdt_selectors_match_contract() {
        assert_eq!(GDT32_CODE_SELECTOR, 0x08);
        assert_eq!(GDT32_DATA_SELECTOR, 0x10);
    }
}
