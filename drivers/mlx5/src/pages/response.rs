//! Integer-only MANAGE_PAGES return decoding. Geometry is not DMA completion.
//!
//! Wire contract: [adapter PRM, MANAGE_PAGES output tables 136–139](https://network.nvidia.com/sites/default/files/doc-2020/ethernet-adapters-programming-manual.pdf).

#![forbid(unsafe_code)]

pub(crate) const PAGE_BYTES: usize = crate::defs::MLX5_PAGE_SIZE;
pub(crate) const MAILBOX_BYTES: usize = crate::defs::MLX5_CMD_MBOX_SIZE;
pub(crate) const MAX_RETURNED_PAGES: usize = (MAILBOX_BYTES - 16) / 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReturnError {
    Truncated,
    FirmwareStatus(u8),
    ExcessCount,
    UnalignedAddress,
    DuplicateAddress,
    ForeignPage,
}

/// A bounded snapshot; no allocation or ownership transition occurs in parsing.
#[derive(Debug)]
pub(crate) struct ReturnedPages {
    addresses: [u64; MAX_RETURNED_PAGES],
    count: usize,
}

impl ReturnedPages {
    /// PRM MANAGE_PAGES output: count at byte 8, PAS at byte 16.
    /// The caller supplies the actual capacity requested from firmware, not a
    /// second interpretation of the untrusted returned count.
    ///
    /// # Errors
    /// Rejects truncated records, failed commands, excessive counts, unaligned
    /// addresses and duplicate PAS entries before any owner can be released.
    pub(crate) fn parse(bytes: &[u8], requested: usize) -> Result<Self, ReturnError> {
        let header = bytes.get(..16).ok_or(ReturnError::Truncated)?;
        if header[0] != 0 {
            return Err(ReturnError::FirmwareStatus(header[0]));
        }
        let count = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
        if count > requested || count > MAX_RETURNED_PAGES {
            return Err(ReturnError::ExcessCount);
        }
        let mut result = Self {
            addresses: [0; MAX_RETURNED_PAGES],
            count,
        };
        for index in 0..count {
            let start = 16 + index * 8;
            let raw = bytes.get(start..start + 8).ok_or(ReturnError::Truncated)?;
            let address = u64::from_be_bytes(raw.try_into().map_err(|_| ReturnError::Truncated)?);
            if address == 0 || !address.is_multiple_of(PAGE_BYTES as u64) {
                return Err(ReturnError::UnalignedAddress);
            }
            if result.addresses[..index].contains(&address) {
                return Err(ReturnError::DuplicateAddress);
            }
            result.addresses[index] = address;
        }
        Ok(result)
    }

    pub(crate) fn addresses(&self) -> &[u64] {
        &self.addresses[..self.count]
    }

    /// Validate the whole response against the owner's current function and
    /// submission state before committing the first returned page.
    ///
    /// # Errors
    /// Rejects a foreign, already-returned or wrong-function address atomically.
    pub(crate) fn validate_membership(
        &self,
        mut contains: impl FnMut(u64) -> bool,
    ) -> Result<(), ReturnError> {
        if self.addresses().iter().copied().all(&mut contains) {
            Ok(())
        } else {
            Err(ReturnError::ForeignPage)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(addresses: &[u64]) -> [u8; MAILBOX_BYTES] {
        let mut bytes = [0; MAILBOX_BYTES];
        bytes[8..12].copy_from_slice(&(addresses.len() as u32).to_be_bytes());
        for (index, address) in addresses.iter().enumerate() {
            bytes[16 + index * 8..24 + index * 8].copy_from_slice(&address.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn count_comes_from_the_response_not_the_request() -> Result<(), ReturnError> {
        let bytes = response(&[0x1000, 0x9000]);
        let returned = ReturnedPages::parse(&bytes, 4)?;
        assert_eq!(returned.addresses(), &[0x1000, 0x9000]);
        assert_eq!(ReturnedPages::parse(&response(&[]), 4)?.addresses(), &[]);
        Ok(())
    }

    #[test]
    fn capacity_and_truncation_are_checked_before_iteration() {
        assert!(matches!(
            ReturnedPages::parse(&[0; 15], 1),
            Err(ReturnError::Truncated)
        ));
        let bytes = response(&[0x1000, 0x2000]);
        assert!(matches!(
            ReturnedPages::parse(&bytes, 1),
            Err(ReturnError::ExcessCount)
        ));
        assert!(matches!(
            ReturnedPages::parse(&bytes[..23], 2),
            Err(ReturnError::Truncated)
        ));
        let mut oversized = [0; 16];
        oversized[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            ReturnedPages::parse(&oversized, usize::MAX),
            Err(ReturnError::ExcessCount)
        ));
    }

    #[test]
    fn invalid_addresses_and_duplicate_returns_are_rejected() {
        for addresses in [&[0][..], &[0x1001][..]] {
            assert!(matches!(
                ReturnedPages::parse(&response(addresses), 1),
                Err(ReturnError::UnalignedAddress)
            ));
        }
        assert!(matches!(
            ReturnedPages::parse(&response(&[0x1000, 0x1000]), 2),
            Err(ReturnError::DuplicateAddress)
        ));
        let mut bytes = response(&[0x1000]);
        bytes[0] = 7;
        assert!(matches!(
            ReturnedPages::parse(&bytes, 1),
            Err(ReturnError::FirmwareStatus(7))
        ));
    }

    #[test]
    fn membership_validation_never_releases_a_valid_prefix() -> Result<(), ReturnError> {
        let returned = ReturnedPages::parse(&response(&[0x1000, 0x9000]), 2)?;
        assert_eq!(
            returned.validate_membership(|address| address == 0x1000),
            Err(ReturnError::ForeignPage)
        );
        assert_eq!(
            returned.validate_membership(|address| [0x1000, 0x9000].contains(&address)),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn full_mailbox_boundary_is_accepted() -> Result<(), ReturnError> {
        let addresses =
            core::array::from_fn::<_, MAX_RETURNED_PAGES, _>(|index| (index as u64 + 1) * 4096);
        assert_eq!(
            ReturnedPages::parse(&response(&addresses), MAX_RETURNED_PAGES)?.addresses(),
            addresses
        );
        Ok(())
    }
}
