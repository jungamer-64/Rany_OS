//! Checked UAR page geometry, independent of any hardware allocation grant.

#![forbid(unsafe_code)]

use crate::regs::uar;
use hal::mmio::MmioAccessError;

pub(super) fn checked_uar_offset(length: usize, number: u32) -> Result<usize, MmioAccessError> {
    let number = usize::try_from(number).map_err(|_| MmioAccessError::OffsetOverflow)?;
    let offset = number
        .checked_mul(uar::PAGE_SIZE)
        .ok_or(MmioAccessError::OffsetOverflow)?;
    let end = offset
        .checked_add(uar::PAGE_SIZE)
        .ok_or(MmioAccessError::OffsetOverflow)?;
    if end > length {
        return Err(MmioAccessError::OutOfBounds);
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uar_requires_a_complete_page_inside_the_mapping() {
        assert_eq!(checked_uar_offset(uar::PAGE_SIZE, 0), Ok(0));
        assert_eq!(
            checked_uar_offset(uar::PAGE_SIZE, 1),
            Err(MmioAccessError::OutOfBounds)
        );
        assert_eq!(
            checked_uar_offset(uar::PAGE_SIZE * 2 - 1, 1),
            Err(MmioAccessError::OutOfBounds)
        );
        assert_eq!(
            checked_uar_offset(uar::PAGE_SIZE * 2, 1),
            Ok(uar::PAGE_SIZE)
        );
        assert_eq!(checked_uar_offset(0, 0), Err(MmioAccessError::OutOfBounds));
        assert!(checked_uar_offset(uar::PAGE_SIZE, u32::MAX).is_err());
    }
}
