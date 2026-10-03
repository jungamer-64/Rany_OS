//! Borrowed, validated ACPI system-locality distances. Domain identifiers index
//! the firmware matrix directly; kernel node numbering is a separate boundary.

use crate::{AcpiError, AcpiErrorKind};

#[derive(Debug, Clone, Copy)]
pub struct NumaDistances<'a> {
    count: usize,
    entries: &'a [u8],
}

impl<'a> NumaDistances<'a> {
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, AcpiError> {
        let invalid = || {
            AcpiError::table(
                AcpiErrorKind::InvalidLength,
                *b"SLIT",
                "invalid locality matrix extent",
            )
        };
        let header: [u8; 8] = body
            .get(..8)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?;
        let count = usize::try_from(u64::from_le_bytes(header)).map_err(|_| invalid())?;
        let size = count
            .checked_mul(count)
            .filter(|_| count != 0)
            .ok_or_else(invalid)?;
        let entries = body
            .get(8..)
            .filter(|entries| entries.len() == size)
            .ok_or_else(invalid)?;
        if entries.iter().any(|distance| *distance < 10)
            || (0..count).any(|i| entries[i * count + i] != 10)
        {
            return Err(AcpiError::table(
                AcpiErrorKind::InvalidEncoding,
                *b"SLIT",
                "local distances must be 10 and values below 10 are reserved",
            ));
        }
        Ok(Self { count, entries })
    }

    /// 255 represents an unreachable locality. An absent domain is distinct
    /// from an unreachable pair and indicates inconsistent SRAT/SLIT input.
    pub fn distance(self, from_domain: u32, to_domain: u32) -> Option<u8> {
        let from = usize::try_from(from_domain).ok()?;
        let to = usize::try_from(to_domain).ok()?;
        if from >= self.count || to >= self.count {
            return None;
        }
        Some(self.entries[from * self.count + to])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_domain_coordinates_and_unreachable_distances() {
        let body = [3, 0, 0, 0, 0, 0, 0, 0, 10, 21, 255, 18, 10, 24, 255, 25, 10];
        let map = NumaDistances::parse(&body).unwrap();
        assert_eq!(map.distance(1, 0), Some(18));
        assert_eq!(map.distance(0, 2), Some(255));
        assert_eq!(map.distance(3, 0), None);
    }
    #[test]
    fn malformed_matrix_is_rejected_without_indexing_it() {
        for body in [
            &[0u8; 8][..],
            &[255u8; 8][..],
            &[2, 0, 0, 0, 0, 0, 0, 0, 10][..],
        ] {
            assert_eq!(
                NumaDistances::parse(body).unwrap_err().kind,
                AcpiErrorKind::InvalidLength
            );
        }
        for body in [
            [2, 0, 0, 0, 0, 0, 0, 0, 10, 9, 20, 10],
            [2, 0, 0, 0, 0, 0, 0, 0, 11, 20, 20, 10],
        ] {
            assert_eq!(
                NumaDistances::parse(&body).unwrap_err().kind,
                AcpiErrorKind::InvalidEncoding
            );
        }
    }
}
